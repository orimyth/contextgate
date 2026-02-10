package store

import "context"

// Store is the persistence interface for MCP message logging.
type Store interface {
	// LogMessage persists a message asynchronously (buffered).
	LogMessage(ctx context.Context, entry *LogEntry) error

	// Query retrieves messages matching the filter, ordered by timestamp desc.
	Query(ctx context.Context, filter QueryFilter) ([]LogEntry, error)

	// GetMessage retrieves a single message by ID.
	GetMessage(ctx context.Context, id int64) (*LogEntry, error)

	// Stats returns aggregate statistics, optionally filtered by session.
	Stats(ctx context.Context, sessionID string) (*Stats, error)

	// CreateSession records a new proxy session.
	CreateSession(ctx context.Context, session *Session) error

	// EndSession marks a session as ended.
	EndSession(ctx context.Context, sessionID string) error

	// LogApproval records an approval decision.
	LogApproval(ctx context.Context, record *ApprovalRecord) error

	// GetApprovals retrieves approval records, optionally filtered by session.
	GetApprovals(ctx context.Context, sessionID string) ([]ApprovalRecord, error)

	// RegisterTools records tools from a tools/list response for a session.
	RegisterTools(ctx context.Context, sessionID string, tools []ToolRecord) error

	// GetToolAnalytics computes tool analytics across sessions.
	GetToolAnalytics(ctx context.Context, sessionID string) (*ToolAnalyticsSummary, error)

	// GetToolUsageCounts returns per-tool call counts within recent sessions.
	GetToolUsageCounts(ctx context.Context, lastNSessions int) (map[string]int, error)

	// Close flushes pending writes and closes the store.
	Close() error
}
