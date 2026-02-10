package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/policy"
)

func newTestPolicyInterceptor(rules ...policy.Rule) *PolicyInterceptor {
	cfg := &policy.Config{Rules: rules}
	cfg.Compile()
	return NewPolicyInterceptor(policy.NewEngine(cfg))
}

func TestPolicyInterceptor_Deny(t *testing.T) {
	pi := newTestPolicyInterceptor(policy.Rule{
		Name:    "block-shell",
		Action:  policy.ActionDeny,
		Methods: []string{"tools/call"},
		Tools:   []string{"run_shell"},
	})

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_shell"}}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"run_shell"}`),
		},
	}

	result, err := pi.Intercept(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for deny")
	}
	if result != nil {
		t.Fatal("expected nil bytes for deny")
	}
}

func TestPolicyInterceptor_RequireApproval(t *testing.T) {
	pi := newTestPolicyInterceptor(policy.Rule{
		Name:    "approve-delete",
		Action:  policy.ActionRequireApproval,
		Methods: []string{"tools/call"},
		Tools:   []string{"delete_file"},
	})

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"delete_file"}`),
		},
	}

	result, err := pi.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes to be returned for require_approval")
	}
	if msg.Metadata[MetaKeyPolicyAction] != string(policy.ActionRequireApproval) {
		t.Fatalf("expected require_approval in metadata, got %v", msg.Metadata[MetaKeyPolicyAction])
	}
}

func TestPolicyInterceptor_Audit(t *testing.T) {
	pi := newTestPolicyInterceptor(policy.Rule{
		Name:    "audit-all",
		Action:  policy.ActionAudit,
		Methods: []string{"tools/call"},
	})

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"read_file"}`),
		},
	}

	result, err := pi.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes to be returned for audit")
	}
	if msg.Metadata[MetaKeyAudit] != true {
		t.Fatal("expected audit=true in metadata")
	}
}

func TestPolicyInterceptor_NoMatch(t *testing.T) {
	pi := newTestPolicyInterceptor(policy.Rule{
		Name:    "block-shell",
		Action:  policy.ActionDeny,
		Methods: []string{"tools/call"},
		Tools:   []string{"run_shell"},
	})

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"read_file"}`),
		},
	}

	result, err := pi.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes to pass through")
	}
	if msg.Metadata != nil {
		t.Fatal("expected nil metadata when no rules match")
	}
}

func TestPolicyInterceptor_UnparseableMessage(t *testing.T) {
	pi := newTestPolicyInterceptor(policy.Rule{
		Name:    "block-all",
		Action:  policy.ActionDeny,
		Methods: []string{"tools/call"},
	})

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`not valid json`),
		ParseErr:  fmt.Errorf("parse error"),
	}

	result, err := pi.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected unparseable messages to pass through")
	}
}
