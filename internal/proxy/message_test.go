package proxy

import (
	"encoding/json"
	"testing"
)

func TestParseMessage_Request(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method = %q, want %q", msg.Method, "tools/call")
	}
	if msg.Kind() != KindRequest {
		t.Errorf("kind = %q, want %q", msg.Kind(), KindRequest)
	}
	if msg.ID == nil {
		t.Error("id should not be nil for a request")
	}
}

func TestParseMessage_Notification(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "notifications/initialized" {
		t.Errorf("method = %q, want %q", msg.Method, "notifications/initialized")
	}
	if msg.Kind() != KindNotification {
		t.Errorf("kind = %q, want %q", msg.Kind(), KindNotification)
	}
}

func TestParseMessage_Response(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Kind() != KindResponse {
		t.Errorf("kind = %q, want %q", msg.Kind(), KindResponse)
	}
}

func TestParseMessage_Error(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid request"}}`)
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Kind() != KindError {
		t.Errorf("kind = %q, want %q", msg.Kind(), KindError)
	}
	if msg.Error.Code != -32600 {
		t.Errorf("error code = %d, want %d", msg.Error.Code, -32600)
	}
}

func TestMakeErrorResponse(t *testing.T) {
	id := json.RawMessage(`42`)
	resp := MakeErrorResponse(id, -32600, "blocked by policy")

	var msg JSONRPCMessage
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if msg.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", msg.JSONRPC, "2.0")
	}
	if msg.Error == nil {
		t.Fatal("error should not be nil")
	}
	if msg.Error.Code != -32600 {
		t.Errorf("error code = %d, want %d", msg.Error.Code, -32600)
	}
	if msg.Error.Message != "blocked by policy" {
		t.Errorf("error message = %q, want %q", msg.Error.Message, "blocked by policy")
	}
}
