package store

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s, err := NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLogAndQuery(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entry := &LogEntry{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: "host_to_server",
		Kind:      "request",
		Method:    "tools/call",
		MsgID:     "1",
		Payload:   `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
		SizeBytes: 46,
	}

	if err := s.LogMessage(ctx, entry); err != nil {
		t.Fatalf("LogMessage failed: %v", err)
	}

	// Wait for flush
	time.Sleep(700 * time.Millisecond)

	entries, err := s.Query(ctx, QueryFilter{SessionID: "test-session"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Method != "tools/call" {
		t.Errorf("method = %q, want %q", entries[0].Method, "tools/call")
	}
}

func TestBatchWrite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		s.LogMessage(ctx, &LogEntry{
			Timestamp: time.Now(),
			SessionID: "batch-test",
			Direction: "host_to_server",
			Kind:      "request",
			Method:    "tools/list",
			Payload:   `{}`,
			SizeBytes: 2,
		})
	}

	time.Sleep(700 * time.Millisecond)

	entries, err := s.Query(ctx, QueryFilter{SessionID: "batch-test", Limit: 100})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(entries) != 50 {
		t.Errorf("got %d entries, want 50", len(entries))
	}
}

func TestStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := []*LogEntry{
		{Timestamp: time.Now(), SessionID: "s1", Direction: "host_to_server", Kind: "request", Method: "tools/call", Payload: `{}`, SizeBytes: 10},
		{Timestamp: time.Now(), SessionID: "s1", Direction: "server_to_host", Kind: "response", Payload: `{}`, SizeBytes: 20},
		{Timestamp: time.Now(), SessionID: "s1", Direction: "server_to_host", Kind: "error", Payload: `{}`, SizeBytes: 15, Blocked: true},
	}

	for _, e := range entries {
		s.LogMessage(ctx, e)
	}

	time.Sleep(700 * time.Millisecond)

	stats, err := s.Stats(ctx, "s1")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	if stats.TotalMessages != 3 {
		t.Errorf("total = %d, want 3", stats.TotalMessages)
	}
	if stats.RequestCount != 1 {
		t.Errorf("requests = %d, want 1", stats.RequestCount)
	}
	if stats.ResponseCount != 1 {
		t.Errorf("responses = %d, want 1", stats.ResponseCount)
	}
	if stats.ErrorCount != 1 {
		t.Errorf("errors = %d, want 1", stats.ErrorCount)
	}
	if stats.BlockedCount != 1 {
		t.Errorf("blocked = %d, want 1", stats.BlockedCount)
	}
}

func TestGetMessage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.LogMessage(ctx, &LogEntry{
		Timestamp: time.Now(),
		SessionID: "s1",
		Direction: "host_to_server",
		Kind:      "request",
		Method:    "initialize",
		MsgID:     "1",
		Payload:   `{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		SizeBytes: 45,
	})

	time.Sleep(700 * time.Millisecond)

	entry, err := s.GetMessage(ctx, 1)
	if err != nil {
		t.Fatalf("GetMessage failed: %v", err)
	}
	if entry.Method != "initialize" {
		t.Errorf("method = %q, want %q", entry.Method, "initialize")
	}
}

func TestSession(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	session := &Session{
		ID:        "test-session",
		StartedAt: time.Now(),
		Command:   "npx",
		Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
	}

	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if err := s.EndSession(ctx, "test-session"); err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}
}

func TestRegisterTools(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tools := []ToolRecord{
		{ToolName: "read_file", Description: "Read a file"},
		{ToolName: "write_file", Description: "Write a file"},
		{ToolName: "list_directory", Description: "List directory contents"},
	}

	if err := s.RegisterTools(ctx, "s1", tools); err != nil {
		t.Fatalf("RegisterTools failed: %v", err)
	}

	// Upsert should be idempotent
	if err := s.RegisterTools(ctx, "s1", tools[:1]); err != nil {
		t.Fatalf("RegisterTools (upsert) failed: %v", err)
	}

	analytics, err := s.GetToolAnalytics(ctx, "s1")
	if err != nil {
		t.Fatalf("GetToolAnalytics failed: %v", err)
	}
	if analytics.TotalAvailable != 3 {
		t.Errorf("total available = %d, want 3", analytics.TotalAvailable)
	}
	if analytics.TotalUsed != 0 {
		t.Errorf("total used = %d, want 0", analytics.TotalUsed)
	}
}

func TestToolAnalyticsWithUsage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Create session
	s.CreateSession(ctx, &Session{
		ID: "s1", StartedAt: time.Now(), Command: "test",
	})

	// Register tools
	s.RegisterTools(ctx, "s1", []ToolRecord{
		{ToolName: "read_file", Description: "Read a file"},
		{ToolName: "write_file", Description: "Write a file"},
		{ToolName: "delete_file", Description: "Delete a file"},
	})

	// Log some tool calls
	for _, name := range []string{"read_file", "read_file", "write_file"} {
		s.LogMessage(ctx, &LogEntry{
			Timestamp: time.Now(),
			SessionID: "s1",
			Direction: "host_to_server",
			Kind:      "request",
			Method:    "tools/call",
			ToolName:  name,
			Payload:   `{}`,
			SizeBytes: 2,
		})
	}

	time.Sleep(700 * time.Millisecond)

	analytics, err := s.GetToolAnalytics(ctx, "s1")
	if err != nil {
		t.Fatalf("GetToolAnalytics failed: %v", err)
	}
	if analytics.TotalAvailable != 3 {
		t.Errorf("total available = %d, want 3", analytics.TotalAvailable)
	}
	if analytics.TotalUsed != 2 {
		t.Errorf("total used = %d, want 2", analytics.TotalUsed)
	}

	// Check ordering: read_file (2 calls) should be first
	if len(analytics.Tools) < 3 {
		t.Fatalf("expected 3 tools, got %d", len(analytics.Tools))
	}
	if analytics.Tools[0].ToolName != "read_file" {
		t.Errorf("first tool = %q, want read_file", analytics.Tools[0].ToolName)
	}
	if analytics.Tools[0].CallCount != 2 {
		t.Errorf("read_file calls = %d, want 2", analytics.Tools[0].CallCount)
	}
}

func TestGetToolUsageCounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateSession(ctx, &Session{
		ID: "s1", StartedAt: time.Now(), Command: "test",
	})

	for _, name := range []string{"read_file", "read_file", "write_file"} {
		s.LogMessage(ctx, &LogEntry{
			Timestamp: time.Now(),
			SessionID: "s1",
			Direction: "host_to_server",
			Kind:      "request",
			Method:    "tools/call",
			ToolName:  name,
			Payload:   `{}`,
			SizeBytes: 2,
		})
	}

	time.Sleep(700 * time.Millisecond)

	counts, err := s.GetToolUsageCounts(ctx, 0) // all sessions
	if err != nil {
		t.Fatalf("GetToolUsageCounts failed: %v", err)
	}
	if counts["read_file"] != 2 {
		t.Errorf("read_file count = %d, want 2", counts["read_file"])
	}
	if counts["write_file"] != 1 {
		t.Errorf("write_file count = %d, want 1", counts["write_file"])
	}

	// With session scoping
	counts, err = s.GetToolUsageCounts(ctx, 1)
	if err != nil {
		t.Fatalf("GetToolUsageCounts (scoped) failed: %v", err)
	}
	if counts["read_file"] != 2 {
		t.Errorf("scoped read_file count = %d, want 2", counts["read_file"])
	}
}
