package proxy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/policy"
)

func makeApprovalMsg() *InterceptedMessage {
	return &InterceptedMessage{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/call",
			Params:  json.RawMessage(`{"name":"delete_file"}`),
		},
		Metadata: map[string]any{
			MetaKeyPolicyAction: string(policy.ActionRequireApproval),
			MetaKeyPolicyRule:   "approve-delete",
		},
	}
}

func TestApproval_NoMetadata_PassThrough(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)
	ai := NewApprovalInterceptor(mgr)

	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: DirHostToServer,
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
		Parsed: JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  "tools/list",
		},
	}

	result, err := ai.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected pass through")
	}
}

func TestApproval_Approved(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)
	ai := NewApprovalInterceptor(mgr)

	msg := makeApprovalMsg()

	// Resolve in background after submission
	mgr.OnRequest = func(req *ApprovalRequest) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			mgr.Resolve(req.ID, true)
		}()
	}

	result, err := ai.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bytes for approved request")
	}
}

func TestApproval_Denied(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)
	ai := NewApprovalInterceptor(mgr)

	msg := makeApprovalMsg()

	mgr.OnRequest = func(req *ApprovalRequest) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			mgr.Resolve(req.ID, false)
		}()
	}

	result, err := ai.Intercept(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for denied request")
	}
	if result != nil {
		t.Fatal("expected nil bytes for denied request")
	}
}

func TestApproval_Timeout(t *testing.T) {
	mgr := NewApprovalManager(50 * time.Millisecond) // short timeout
	ai := NewApprovalInterceptor(mgr)

	msg := makeApprovalMsg()

	result, err := ai.Intercept(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error for timed out request")
	}
	if result != nil {
		t.Fatal("expected nil bytes for timed out request")
	}
}

func TestApproval_ContextCancelled(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)
	ai := NewApprovalInterceptor(mgr)

	msg := makeApprovalMsg()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	result, err := ai.Intercept(ctx, msg)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if result != nil {
		t.Fatal("expected nil bytes for cancelled context")
	}
}

func TestApprovalManager_ResolveNonExistent(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)
	err := mgr.Resolve("does-not-exist", true)
	if err == nil {
		t.Fatal("expected error for non-existent ID")
	}
}

func TestApprovalManager_Pending(t *testing.T) {
	mgr := NewApprovalManager(10 * time.Second)

	req := &ApprovalRequest{
		Timestamp: time.Now(),
		SessionID: "test",
		Method:    "tools/call",
		ToolName:  "delete_file",
		RuleName:  "approve-delete",
		Payload:   `{}`,
	}

	mgr.Submit(req)

	pending := mgr.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	mgr.Resolve(req.ID, true)

	pending = mgr.Pending()
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after resolve, got %d", len(pending))
	}
}
