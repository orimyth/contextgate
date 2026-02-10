package proxy

import (
	"context"
	"encoding/json"

	"github.com/contextgate/contextgate/internal/eventbus"
	"github.com/contextgate/contextgate/internal/store"
)

func extractToolNameFromParams(params json.RawMessage) string {
	if params == nil {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}

// LoggingInterceptor logs all messages to the store and publishes
// them to the event bus for the live dashboard. It never blocks
// or modifies messages.
type LoggingInterceptor struct {
	store    store.Store
	eventBus *eventbus.EventBus
}

func NewLoggingInterceptor(s store.Store, eb *eventbus.EventBus) *LoggingInterceptor {
	return &LoggingInterceptor{store: s, eventBus: eb}
}

func (l *LoggingInterceptor) Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error) {
	entry := &store.LogEntry{
		Timestamp: msg.Timestamp,
		SessionID: msg.SessionID,
		Direction: string(msg.Direction),
		Kind:      string(msg.Parsed.Kind()),
		Method:    msg.Parsed.Method,
		MsgID:     string(msg.Parsed.ID),
		Payload:   string(msg.RawBytes),
		SizeBytes: len(msg.RawBytes),
	}

	// Read metadata annotations from earlier interceptors
	if msg.Metadata != nil {
		if audit, ok := msg.Metadata[MetaKeyAudit].(bool); ok && audit {
			entry.Audit = true
		}
		if scrubCount, ok := msg.Metadata[MetaKeyScrubCount].(int); ok {
			entry.ScrubCount = scrubCount
		}
		if rules, ok := msg.Metadata[MetaKeyMatchedRules].([]string); ok {
			entry.MatchedRules = rules
		}
		if action, ok := msg.Metadata[MetaKeyPolicyAction].(string); ok {
			entry.PolicyAction = action
		}
	}

	// Extract tool name for tools/call
	if msg.Parsed.Method == "tools/call" {
		entry.ToolName = extractToolNameFromParams(msg.Parsed.Params)
	}

	// Async — does not block
	l.store.LogMessage(ctx, entry)

	// Publish for SSE — also non-blocking
	l.eventBus.Publish(entry)

	return msg.RawBytes, nil
}
