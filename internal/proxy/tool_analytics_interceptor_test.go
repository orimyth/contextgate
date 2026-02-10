package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/store"
)

// mockToolStore implements only the tool-related Store methods.
type mockToolStore struct {
	store.Store // embed to satisfy interface (panics on unimplemented)
	registered  []store.ToolRecord
	usageCounts map[string]int
}

func newMockToolStore() *mockToolStore {
	return &mockToolStore{usageCounts: make(map[string]int)}
}

func (m *mockToolStore) RegisterTools(_ context.Context, sessionID string, tools []store.ToolRecord) error {
	for _, t := range tools {
		t.SessionID = sessionID
		m.registered = append(m.registered, t)
	}
	return nil
}

func (m *mockToolStore) GetToolAnalytics(_ context.Context, _ string) (*store.ToolAnalyticsSummary, error) {
	return &store.ToolAnalyticsSummary{}, nil
}

func (m *mockToolStore) GetToolUsageCounts(_ context.Context, _ int) (map[string]int, error) {
	return m.usageCounts, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func makeToolsListRequest(id string) *InterceptedMessage {
	raw := []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list"}`)
	parsed, _ := ParseMessage(raw)
	return &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: DirHostToServer,
		RawBytes:  raw,
		Parsed:    parsed,
	}
}

func makeToolsListResponse(id string, tools string) *InterceptedMessage {
	raw := []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":` + tools + `}}`)
	parsed, _ := ParseMessage(raw)
	return &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: DirServerToHost,
		RawBytes:  raw,
		Parsed:    parsed,
	}
}

func TestToolAnalytics_TracksRequest(t *testing.T) {
	ms := newMockToolStore()
	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{})

	msg := makeToolsListRequest("1")
	result, err := ta.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected pass through")
	}

	ta.mu.Lock()
	_, exists := ta.pendingIDs["1"]
	ta.mu.Unlock()
	if !exists {
		t.Fatal("expected pending ID to be tracked")
	}
}

func TestToolAnalytics_CorrelatesResponse(t *testing.T) {
	ms := newMockToolStore()
	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{})
	ctx := context.Background()

	// Send request
	ta.Intercept(ctx, makeToolsListRequest("1"))

	// Send correlated response
	tools := `[{"name":"read_file","description":"Read a file"},{"name":"write_file","description":"Write a file"}]`
	resp := makeToolsListResponse("1", tools)
	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected pass through")
	}

	// Verify tools were registered
	if len(ms.registered) != 2 {
		t.Fatalf("expected 2 registered tools, got %d", len(ms.registered))
	}
	if ms.registered[0].ToolName != "read_file" {
		t.Errorf("first tool = %q, want read_file", ms.registered[0].ToolName)
	}
	if ms.registered[1].ToolName != "write_file" {
		t.Errorf("second tool = %q, want write_file", ms.registered[1].ToolName)
	}

	// Pending ID should be cleaned up
	ta.mu.Lock()
	_, exists := ta.pendingIDs["1"]
	ta.mu.Unlock()
	if exists {
		t.Fatal("expected pending ID to be removed after correlation")
	}
}

func TestToolAnalytics_NoPruning_PassThrough(t *testing.T) {
	ms := newMockToolStore()
	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	tools := `[{"name":"read_file","description":"Read"},{"name":"write_file","description":"Write"}]`
	resp := makeToolsListResponse("1", tools)
	original := string(resp.RawBytes)

	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With no pruning config, bytes should be unchanged
	if string(result) != original {
		t.Fatalf("expected unchanged bytes, got:\n%s", string(result))
	}
}

func TestToolAnalytics_PruneUnused(t *testing.T) {
	ms := newMockToolStore()
	// read_file has been used, write_file and delete_file have not
	ms.usageCounts = map[string]int{"read_file": 5}

	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{
		UnusedSessions: 3,
	})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	tools := `[{"name":"read_file","description":"Read"},{"name":"write_file","description":"Write"},{"name":"delete_file","description":"Delete"}]`
	resp := makeToolsListResponse("1", tools)

	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "read_file") {
		t.Fatal("expected read_file to be kept")
	}
	if strings.Contains(resultStr, "write_file") {
		t.Fatal("expected write_file to be pruned")
	}
	if strings.Contains(resultStr, "delete_file") {
		t.Fatal("expected delete_file to be pruned")
	}

	// Verify metadata
	pruned, ok := resp.Metadata[MetaKeyToolsPruned].(int)
	if !ok || pruned != 2 {
		t.Fatalf("expected 2 pruned tools, got %v", resp.Metadata[MetaKeyToolsPruned])
	}
}

func TestToolAnalytics_AlwaysKeep(t *testing.T) {
	ms := newMockToolStore()
	ms.usageCounts = map[string]int{"read_file": 5}

	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{
		UnusedSessions: 3,
		AlwaysKeep:     []string{"delete_file"},
	})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	tools := `[{"name":"read_file","description":"Read"},{"name":"write_file","description":"Write"},{"name":"delete_file","description":"Delete"}]`
	resp := makeToolsListResponse("1", tools)

	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "read_file") {
		t.Fatal("expected read_file to be kept (used)")
	}
	if strings.Contains(resultStr, "write_file") {
		t.Fatal("expected write_file to be pruned")
	}
	if !strings.Contains(resultStr, "delete_file") {
		t.Fatal("expected delete_file to be kept (always-keep)")
	}
}

func TestToolAnalytics_KeepTopK(t *testing.T) {
	ms := newMockToolStore()
	ms.usageCounts = map[string]int{"a": 10, "b": 5, "c": 3, "d": 1}

	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{
		KeepTopK: 2,
	})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	tools := `[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"}]`
	resp := makeToolsListResponse("1", tools)

	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the result to check which tools remain
	var parsed JSONRPCMessage
	json.Unmarshal(result, &parsed)
	var res toolsListResult
	json.Unmarshal(parsed.Result, &res)

	if len(res.Tools) != 2 {
		t.Fatalf("expected 2 tools after top-K pruning, got %d", len(res.Tools))
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, `"a"`) {
		t.Fatal("expected tool 'a' to be kept (highest usage)")
	}
	if !strings.Contains(resultStr, `"b"`) {
		t.Fatal("expected tool 'b' to be kept (second highest)")
	}
}

func TestToolAnalytics_NonToolsResponse_Ignored(t *testing.T) {
	ms := newMockToolStore()
	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{})
	ctx := context.Background()

	// A regular response (not tools/list)
	raw := []byte(`{"jsonrpc":"2.0","id":99,"result":{"content":"hello"}}`)
	parsed, _ := ParseMessage(raw)
	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: DirServerToHost,
		RawBytes:  raw,
		Parsed:    parsed,
	}

	result, err := ta.Intercept(ctx, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(raw) {
		t.Fatal("expected unchanged bytes for non-tools response")
	}
	if len(ms.registered) != 0 {
		t.Fatal("expected no tools registered for non-tools response")
	}
}

func TestToolAnalytics_UnparseableResult_PassThrough(t *testing.T) {
	ms := newMockToolStore()
	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{UnusedSessions: 3})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	// Response with invalid result structure
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":"not-an-object"}`)
	parsed, _ := ParseMessage(raw)
	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: DirServerToHost,
		RawBytes:  raw,
		Parsed:    parsed,
	}

	result, err := ta.Intercept(ctx, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(raw) {
		t.Fatal("expected unchanged bytes for unparseable result")
	}
}

func TestToolAnalytics_PreservesInputSchema(t *testing.T) {
	ms := newMockToolStore()
	ms.usageCounts = map[string]int{"read_file": 1}

	ta := NewToolAnalyticsInterceptor(ms, testLogger(), PruneConfig{
		UnusedSessions: 3,
	})
	ctx := context.Background()

	ta.Intercept(ctx, makeToolsListRequest("1"))

	// Tools with inputSchema that must be preserved
	tools := `[{"name":"read_file","description":"Read","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}},{"name":"unused","description":"Unused"}]`
	resp := makeToolsListResponse("1", tools)

	result, err := ta.Intercept(ctx, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "inputSchema") {
		t.Fatal("expected inputSchema to be preserved in kept tool")
	}
	if !strings.Contains(resultStr, `"path"`) {
		t.Fatal("expected inputSchema properties to be preserved")
	}
}
