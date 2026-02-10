package proxy

import (
	"encoding/json"
	"time"
)

// Direction indicates which way a message flows through the proxy.
type Direction string

const (
	DirHostToServer Direction = "host_to_server"
	DirServerToHost Direction = "server_to_host"
)

// MessageKind classifies a JSON-RPC message.
type MessageKind string

const (
	KindRequest      MessageKind = "request"
	KindResponse     MessageKind = "response"
	KindNotification MessageKind = "notification"
	KindError        MessageKind = "error"
)

// JSONRPCMessage is a minimal parse of a JSON-RPC 2.0 message.
// Fields are kept as json.RawMessage to avoid full deserialization —
// the proxy should not need to understand every MCP method's schema.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Kind determines what type of JSON-RPC message this is.
func (m *JSONRPCMessage) Kind() MessageKind {
	if m.Method != "" && m.ID != nil {
		return KindRequest
	}
	if m.Method != "" && m.ID == nil {
		return KindNotification
	}
	if m.Error != nil {
		return KindError
	}
	return KindResponse
}

// InterceptedMessage wraps a raw JSON-RPC line with parsed metadata.
type InterceptedMessage struct {
	Timestamp time.Time
	SessionID string
	Direction Direction
	RawBytes  []byte         // original newline-delimited JSON
	Parsed    JSONRPCMessage // minimal parse (may be zero-value if parse failed)
	ParseErr  error          // non-nil if JSON parsing failed
	Metadata  map[string]any // inter-interceptor communication (policy annotations, scrub counts, etc.)
}

// ParseMessage does a minimal parse of raw JSON-RPC bytes.
func ParseMessage(raw []byte) (JSONRPCMessage, error) {
	var msg JSONRPCMessage
	err := json.Unmarshal(raw, &msg)
	return msg, err
}

// MakeErrorResponse creates a JSON-RPC error response for a given request ID.
func MakeErrorResponse(id json.RawMessage, code int, message string) []byte {
	resp := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	data, _ := json.Marshal(resp)
	return data
}
