package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/policy"
)

// buildTestChain creates a full interceptor chain with all four interceptors.
func buildTestChain(rules []policy.Rule, scrubEnabled bool, approvalTimeout time.Duration) (*InterceptorChain, *ApprovalManager) {
	cfg := &policy.Config{
		Version: "1",
		Rules:   rules,
	}
	cfg.Compile() // pre-compile regex patterns
	engine := policy.NewEngine(cfg)

	policyInt := NewPolicyInterceptor(engine)
	scrubber := NewScrubberInterceptor(scrubEnabled, nil)
	mgr := NewApprovalManager(approvalTimeout)
	approvalInt := NewApprovalInterceptor(mgr)

	// Use a no-op logging interceptor (no store/eventbus needed)
	chain := NewInterceptorChain(policyInt, scrubber, approvalInt, &noopInterceptor{})
	return chain, mgr
}

// buildFullChain creates a 5-interceptor chain including ToolAnalyticsInterceptor.
func buildFullChain(rules []policy.Rule, scrubEnabled bool, approvalTimeout time.Duration, pruneCfg PruneConfig) (*InterceptorChain, *ApprovalManager, *mockToolStore) {
	cfg := &policy.Config{
		Version: "1",
		Rules:   rules,
	}
	cfg.Compile()
	engine := policy.NewEngine(cfg)

	policyInt := NewPolicyInterceptor(engine)
	scrubber := NewScrubberInterceptor(scrubEnabled, nil)
	mgr := NewApprovalManager(approvalTimeout)
	approvalInt := NewApprovalInterceptor(mgr)

	ms := newMockToolStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	toolAnalytics := NewToolAnalyticsInterceptor(ms, logger, pruneCfg)

	chain := NewInterceptorChain(policyInt, scrubber, approvalInt, toolAnalytics, &noopInterceptor{})
	return chain, mgr, ms
}

// noopInterceptor passes through unchanged — stands in for LoggingInterceptor.
type noopInterceptor struct{}

func (n *noopInterceptor) Intercept(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
	return msg.RawBytes, nil
}

func makeChainMsg(direction Direction, method string, payload string) *InterceptedMessage {
	raw := []byte(payload)
	parsed, _ := ParseMessage(raw)
	return &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "integration-test",
		Direction: direction,
		RawBytes:  raw,
		Parsed:    parsed,
	}
}

func TestChain_DenyBlocks(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "block-shell",
			Action:  policy.ActionDeny,
			Methods: []string{"tools/call"},
			Tools:   []string{"execute_command"},
		},
	}
	chain, _ := buildTestChain(rules, false, 10*time.Second)

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result for denied message")
	}
}

func TestChain_ApprovalApproved(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "approve-delete",
			Action:  policy.ActionRequireApproval,
			Methods: []string{"tools/call"},
			Tools:   []string{"delete_file"},
		},
	}
	chain, mgr := buildTestChain(rules, false, 10*time.Second)

	// Auto-approve when request arrives
	mgr.OnRequest = func(req *ApprovalRequest) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			mgr.Resolve(req.ID, true)
		}()
	}

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for approved message")
	}
}

func TestChain_ApprovalDenied(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "approve-delete",
			Action:  policy.ActionRequireApproval,
			Methods: []string{"tools/call"},
			Tools:   []string{"delete_file"},
		},
	}
	chain, mgr := buildTestChain(rules, false, 10*time.Second)

	// Auto-deny when request arrives
	mgr.OnRequest = func(req *ApprovalRequest) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			mgr.Resolve(req.ID, false)
		}()
	}

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_file"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for denied approval")
	}
	if !strings.Contains(err.Error(), "denied by human review") {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result for denied message")
	}
}

func TestChain_ApprovalTimeout(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "approve-delete",
			Action:  policy.ActionRequireApproval,
			Methods: []string{"tools/call"},
			Tools:   []string{"delete_file"},
		},
	}
	chain, _ := buildTestChain(rules, false, 50*time.Millisecond)

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_file"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for timed out approval")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result for timed out message")
	}
}

func TestChain_AuditFlag(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "audit-tools",
			Action:  policy.ActionAudit,
			Methods: []string{"tools/call"},
		},
	}
	chain, _ := buildTestChain(rules, false, 10*time.Second)

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for audited message")
	}

	// Check metadata was set
	audit, ok := msg.Metadata[MetaKeyAudit].(bool)
	if !ok || !audit {
		t.Fatal("expected audit flag to be set")
	}
}

func TestChain_ScrubPII(t *testing.T) {
	rules := []policy.Rule{}
	chain, _ := buildTestChain(rules, true, 10*time.Second)

	// Server→host response containing a secret
	msg := makeChainMsg(DirServerToHost, "",
		`{"jsonrpc":"2.0","id":6,"result":{"content":"Your key is sk-abcdefghij1234567890abcd"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if strings.Contains(resultStr, "sk-abcdefghij1234567890abcd") {
		t.Fatal("PII was not scrubbed from result")
	}
	if !strings.Contains(resultStr, "[REDACTED:api_key]") {
		t.Fatalf("expected redaction marker, got: %s", resultStr)
	}

	// Verify scrub count metadata
	count, ok := msg.Metadata[MetaKeyScrubCount].(int)
	if !ok || count < 1 {
		t.Fatalf("expected scrub count >= 1, got %v", msg.Metadata[MetaKeyScrubCount])
	}
}

func TestChain_ScrubPII_HostToServer_NoScrub(t *testing.T) {
	rules := []policy.Rule{}
	chain, _ := buildTestChain(rules, true, 10*time.Second)

	// Host→server direction — should NOT be scrubbed
	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"secret":"sk-abcdefghij1234567890abcd"}}`)

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(string(result), "sk-abcdefghij1234567890abcd") {
		t.Fatal("host→server message should not be scrubbed")
	}
}

func TestChain_NoRules_PassThrough(t *testing.T) {
	chain, _ := buildTestChain(nil, false, 10*time.Second)

	msg := makeChainMsg(DirHostToServer, "tools/list",
		`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`)

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for pass-through message")
	}
}

func TestChain_DenyTakesPriority(t *testing.T) {
	rules := []policy.Rule{
		{
			Name:    "audit-all",
			Action:  policy.ActionAudit,
			Methods: []string{"tools/call"},
		},
		{
			Name:    "deny-shell",
			Action:  policy.ActionDeny,
			Methods: []string{"tools/call"},
			Tools:   []string{"execute_command"},
		},
	}
	chain, _ := buildTestChain(rules, false, 10*time.Second)

	msg := makeChainMsg(DirHostToServer, "tools/call",
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"execute_command"}}`)

	_, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Fatal("expected deny error even with audit rule present")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Full 5-interceptor chain tests (Phase 3) ---

func TestFullChain_ToolsListRegistersTools(t *testing.T) {
	chain, _, ms := buildFullChain(nil, false, 10*time.Second, PruneConfig{})
	ctx := context.Background()

	// Send tools/list request through the chain
	reqMsg := makeChainMsg(DirHostToServer, "tools/list",
		`{"jsonrpc":"2.0","id":10,"method":"tools/list"}`)
	result, err := chain.Process(ctx, reqMsg)
	if err != nil {
		t.Fatalf("unexpected error on request: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for tools/list request")
	}

	// Send correlated tools/list response
	respMsg := makeChainMsg(DirServerToHost, "",
		`{"jsonrpc":"2.0","id":10,"result":{"tools":[{"name":"read_file","description":"Read a file"},{"name":"write_file","description":"Write a file"}]}}`)
	result, err = chain.Process(ctx, respMsg)
	if err != nil {
		t.Fatalf("unexpected error on response: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for tools/list response")
	}

	// Verify tools were registered in the mock store
	if len(ms.registered) != 2 {
		t.Fatalf("expected 2 registered tools, got %d", len(ms.registered))
	}
	if ms.registered[0].ToolName != "read_file" {
		t.Errorf("first tool = %q, want read_file", ms.registered[0].ToolName)
	}
}

func TestFullChain_ToolsListPruning(t *testing.T) {
	ms := newMockToolStore()
	ms.usageCounts = map[string]int{"read_file": 5}

	cfg := &policy.Config{Version: "1"}
	cfg.Compile()
	engine := policy.NewEngine(cfg)

	policyInt := NewPolicyInterceptor(engine)
	scrubber := NewScrubberInterceptor(false, nil)
	mgr := NewApprovalManager(10 * time.Second)
	approvalInt := NewApprovalInterceptor(mgr)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	toolAnalytics := NewToolAnalyticsInterceptor(ms, logger, PruneConfig{UnusedSessions: 3})

	chain := NewInterceptorChain(policyInt, scrubber, approvalInt, toolAnalytics, &noopInterceptor{})
	ctx := context.Background()

	// Send tools/list request
	reqMsg := makeChainMsg(DirHostToServer, "tools/list",
		`{"jsonrpc":"2.0","id":11,"method":"tools/list"}`)
	chain.Process(ctx, reqMsg)

	// Send response with 3 tools (only read_file has usage)
	respMsg := makeChainMsg(DirServerToHost, "",
		`{"jsonrpc":"2.0","id":11,"result":{"tools":[{"name":"read_file","description":"Read"},{"name":"write_file","description":"Write"},{"name":"delete_file","description":"Delete"}]}}`)
	result, err := chain.Process(ctx, respMsg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "read_file") {
		t.Fatal("expected read_file to survive pruning")
	}
	if strings.Contains(resultStr, "write_file") {
		t.Fatal("expected write_file to be pruned")
	}
	if strings.Contains(resultStr, "delete_file") {
		t.Fatal("expected delete_file to be pruned")
	}

	// Verify the response is still valid JSON-RPC
	var parsed JSONRPCMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("pruned response is not valid JSON: %v", err)
	}
	if string(parsed.ID) != "11" {
		t.Errorf("response ID = %s, want 11", string(parsed.ID))
	}
}

func TestFullChain_NonToolsPassThrough(t *testing.T) {
	chain, _, _ := buildFullChain(nil, false, 10*time.Second, PruneConfig{})
	ctx := context.Background()

	msg := makeChainMsg(DirHostToServer, "resources/list",
		`{"jsonrpc":"2.0","id":12,"method":"resources/list"}`)

	result, err := chain.Process(ctx, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for non-tools message")
	}
	if string(result) != string(msg.RawBytes) {
		t.Fatal("expected unchanged bytes for non-tools message")
	}
}
