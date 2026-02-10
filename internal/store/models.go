package store

import "time"

// LogEntry represents a logged MCP message.
type LogEntry struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	SessionID    string    `json:"session_id"`
	Direction    string    `json:"direction"`
	Kind         string    `json:"kind"`
	Method       string    `json:"method"`
	MsgID        string    `json:"msg_id"`
	Payload      string    `json:"payload"`
	SizeBytes    int       `json:"size_bytes"`
	Blocked      bool      `json:"blocked"`
	Audit        bool      `json:"audit"`
	ScrubCount   int       `json:"scrub_count"`
	MatchedRules []string  `json:"matched_rules,omitempty"`
	ToolName     string    `json:"tool_name,omitempty"`
	PolicyAction string    `json:"policy_action,omitempty"`
}

// Session represents an MCP proxy session.
type Session struct {
	ID        string     `json:"id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Command   string     `json:"command"`
	Args      []string   `json:"args"`
}

// QueryFilter specifies filters for querying messages.
type QueryFilter struct {
	SessionID string
	Direction string
	Method    string
	Kind      string
	Since     *time.Time
	Limit     int
	Offset    int
}

// Stats holds aggregate statistics.
type Stats struct {
	TotalMessages     int            `json:"total_messages"`
	RequestCount      int            `json:"request_count"`
	ResponseCount     int            `json:"response_count"`
	NotificationCount int            `json:"notification_count"`
	ErrorCount        int            `json:"error_count"`
	BlockedCount      int            `json:"blocked_count"`
	MethodCounts      map[string]int `json:"method_counts"`
	TotalBytes        int64          `json:"total_bytes"`
	ScrubCount        int            `json:"scrub_count"`
	AuditCount        int            `json:"audit_count"`
	ApprovalPending   int            `json:"approval_pending"`
}

// ApprovalRecord represents an approval decision for audit trail.
type ApprovalRecord struct {
	ID        string     `json:"id"`
	Timestamp time.Time  `json:"timestamp"`
	SessionID string     `json:"session_id"`
	Direction string     `json:"direction"`
	Method    string     `json:"method"`
	ToolName  string     `json:"tool_name"`
	RuleName  string     `json:"rule_name"`
	Payload   string     `json:"payload"`
	Decision  string     `json:"decision"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
}

// ApprovalEvent is published when a new approval is requested or resolved.
type ApprovalEvent struct {
	Type    string          `json:"type"` // "requested" or "resolved"
	Request *ApprovalRecord `json:"request"`
}

// ToolRecord represents a tool exposed by an MCP server.
type ToolRecord struct {
	SessionID   string `json:"session_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
}

// ToolAnalytics represents computed analytics for a single tool.
type ToolAnalytics struct {
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	CallCount   int    `json:"call_count"`
	SessionsSeen int   `json:"sessions_seen"`
	LastUsed    string `json:"last_used,omitempty"`
	IsPruned    bool   `json:"is_pruned"`
}

// ToolAnalyticsSummary is the full analytics response.
type ToolAnalyticsSummary struct {
	TotalAvailable int             `json:"total_available"`
	TotalUsed      int             `json:"total_used"`
	TotalPruned    int             `json:"total_pruned"`
	Tools          []ToolAnalytics `json:"tools"`
}
