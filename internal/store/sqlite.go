package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

const (
	bufferSize    = 1024
	batchSize     = 100
	flushInterval = 500 * time.Millisecond
)

// SQLiteStore implements Store with buffered writes to SQLite.
type SQLiteStore struct {
	db      *sql.DB
	logger  *slog.Logger
	writeCh chan *LogEntry
	wg      sync.WaitGroup
}

// NewSQLiteStore opens (or creates) a SQLite database and starts the
// background write consumer.
func NewSQLiteStore(dbPath string, logger *slog.Logger) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(2) // one for writer, one for readers
	db.SetMaxIdleConns(2)

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Idempotent migrations for Phase 2 columns (existing databases)
	for _, m := range []string{
		"ALTER TABLE messages ADD COLUMN audit INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE messages ADD COLUMN scrub_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE messages ADD COLUMN matched_rules TEXT",
		"ALTER TABLE messages ADD COLUMN tool_name TEXT",
		"ALTER TABLE messages ADD COLUMN policy_action TEXT",
	} {
		db.Exec(m) // ignore "duplicate column" errors
	}

	// Phase 3 migrations (tool_registry table for existing databases)
	for _, m := range []string{
		`CREATE TABLE IF NOT EXISTS tool_registry (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			UNIQUE(session_id, tool_name)
		)`,
		"CREATE INDEX IF NOT EXISTS idx_tool_registry_session ON tool_registry(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_tool_registry_tool ON tool_registry(tool_name)",
	} {
		db.Exec(m)
	}

	s := &SQLiteStore{
		db:      db,
		logger:  logger,
		writeCh: make(chan *LogEntry, bufferSize),
	}

	s.wg.Add(1)
	go s.consumeWrites()

	return s, nil
}

// LogMessage enqueues a message for async persistence.
func (s *SQLiteStore) LogMessage(_ context.Context, entry *LogEntry) error {
	select {
	case s.writeCh <- entry:
		return nil
	default:
		s.logger.Warn("write buffer full, dropping message", "method", entry.Method)
		return nil
	}
}

func (s *SQLiteStore) consumeWrites() {
	defer s.wg.Done()

	batch := make([]*LogEntry, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-s.writeCh:
			if !ok {
				if len(batch) > 0 {
					s.flushBatch(batch)
				}
				return
			}
			batch = append(batch, entry)
			if len(batch) >= batchSize {
				s.flushBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *SQLiteStore) flushBatch(batch []*LogEntry) {
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("begin tx", "error", err)
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO messages (timestamp, session_id, direction, kind, method, msg_id, payload, size_bytes, blocked, audit, scrub_count, matched_rules, tool_name, policy_action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		s.logger.Error("prepare insert", "error", err)
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		blocked := 0
		if e.Blocked {
			blocked = 1
		}
		audit := 0
		if e.Audit {
			audit = 1
		}
		var matchedRules *string
		if len(e.MatchedRules) > 0 {
			j, _ := json.Marshal(e.MatchedRules)
			s := string(j)
			matchedRules = &s
		}
		_, err := stmt.Exec(
			e.Timestamp.Format(time.RFC3339Nano),
			e.SessionID,
			e.Direction,
			e.Kind,
			e.Method,
			e.MsgID,
			e.Payload,
			e.SizeBytes,
			blocked,
			audit,
			e.ScrubCount,
			matchedRules,
			nilIfEmpty(e.ToolName),
			nilIfEmpty(e.PolicyAction),
		)
		if err != nil {
			s.logger.Error("insert message", "error", err, "method", e.Method)
		}
	}

	if err := tx.Commit(); err != nil {
		s.logger.Error("commit batch", "error", err)
	}
}

// Query retrieves messages matching the filter.
func (s *SQLiteStore) Query(_ context.Context, f QueryFilter) ([]LogEntry, error) {
	var conditions []string
	var args []any

	if f.SessionID != "" {
		conditions = append(conditions, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.Direction != "" {
		conditions = append(conditions, "direction = ?")
		args = append(args, f.Direction)
	}
	if f.Method != "" {
		conditions = append(conditions, "method = ?")
		args = append(args, f.Method)
	}
	if f.Kind != "" {
		conditions = append(conditions, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.Since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, f.Since.Format(time.RFC3339Nano))
	}

	query := "SELECT id, timestamp, session_id, direction, kind, method, msg_id, payload, size_bytes, blocked, audit, scrub_count, matched_rules, tool_name, policy_action FROM messages"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	query += fmt.Sprintf(" LIMIT %d", limit)
	if f.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query messages: %w", err)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		e, err := scanLogEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetMessage retrieves a single message by ID.
func (s *SQLiteStore) GetMessage(_ context.Context, id int64) (*LogEntry, error) {
	row := s.db.QueryRow(
		"SELECT id, timestamp, session_id, direction, kind, method, msg_id, payload, size_bytes, blocked, audit, scrub_count, matched_rules, tool_name, policy_action FROM messages WHERE id = ?",
		id,
	)
	e, err := scanLogEntryRow(row)
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}
	return &e, nil
}

// Stats returns aggregate statistics.
func (s *SQLiteStore) Stats(_ context.Context, sessionID string) (*Stats, error) {
	st := &Stats{
		MethodCounts: make(map[string]int),
	}

	whereClause := ""
	var args []any
	if sessionID != "" {
		whereClause = " WHERE session_id = ?"
		args = append(args, sessionID)
	}

	// Totals
	err := s.db.QueryRow(
		"SELECT COUNT(*), COALESCE(SUM(size_bytes), 0), COALESCE(SUM(blocked), 0), COALESCE(SUM(scrub_count), 0), COALESCE(SUM(audit), 0) FROM messages"+whereClause,
		args...,
	).Scan(&st.TotalMessages, &st.TotalBytes, &st.BlockedCount, &st.ScrubCount, &st.AuditCount)
	if err != nil {
		return nil, fmt.Errorf("stats totals: %w", err)
	}

	// Kind counts
	rows, err := s.db.Query("SELECT kind, COUNT(*) FROM messages"+whereClause+" GROUP BY kind", args...)
	if err != nil {
		return nil, fmt.Errorf("stats kinds: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			continue
		}
		switch kind {
		case "request":
			st.RequestCount = count
		case "response":
			st.ResponseCount = count
		case "notification":
			st.NotificationCount = count
		case "error":
			st.ErrorCount = count
		}
	}

	// Method counts
	methodQuery := "SELECT method, COUNT(*) FROM messages WHERE method IS NOT NULL AND method != ''"
	if sessionID != "" {
		methodQuery += " AND session_id = ?"
	}
	methodQuery += " GROUP BY method ORDER BY COUNT(*) DESC LIMIT 20"
	rows2, err := s.db.Query(methodQuery, args...)
	if err != nil {
		return st, nil // return partial stats
	}
	defer rows2.Close()
	for rows2.Next() {
		var method string
		var count int
		if err := rows2.Scan(&method, &count); err != nil {
			continue
		}
		st.MethodCounts[method] = count
	}

	return st, nil
}

// CreateSession records a new proxy session.
func (s *SQLiteStore) CreateSession(_ context.Context, session *Session) error {
	argsJSON, _ := json.Marshal(session.Args)
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, started_at, command, args) VALUES (?, ?, ?, ?)",
		session.ID,
		session.StartedAt.Format(time.RFC3339Nano),
		session.Command,
		string(argsJSON),
	)
	return err
}

// EndSession marks a session as ended.
func (s *SQLiteStore) EndSession(_ context.Context, sessionID string) error {
	_, err := s.db.Exec(
		"UPDATE sessions SET ended_at = ? WHERE id = ?",
		time.Now().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

// LogApproval records an approval decision.
func (s *SQLiteStore) LogApproval(_ context.Context, record *ApprovalRecord) error {
	var decidedAt *string
	if record.DecidedAt != nil {
		s := record.DecidedAt.Format(time.RFC3339Nano)
		decidedAt = &s
	}
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO approvals (id, timestamp, session_id, direction, method, tool_name, rule_name, payload, decision, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		record.ID,
		record.Timestamp.Format(time.RFC3339Nano),
		record.SessionID,
		record.Direction,
		record.Method,
		record.ToolName,
		record.RuleName,
		record.Payload,
		record.Decision,
		decidedAt,
	)
	return err
}

// GetApprovals retrieves approval records.
func (s *SQLiteStore) GetApprovals(_ context.Context, sessionID string) ([]ApprovalRecord, error) {
	query := "SELECT id, timestamp, session_id, direction, method, tool_name, rule_name, payload, decision, decided_at FROM approvals"
	var args []any
	if sessionID != "" {
		query += " WHERE session_id = ?"
		args = append(args, sessionID)
	}
	query += " ORDER BY timestamp DESC LIMIT 100"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query approvals: %w", err)
	}
	defer rows.Close()

	var records []ApprovalRecord
	for rows.Next() {
		var r ApprovalRecord
		var ts string
		var method, toolName sql.NullString
		var decidedAt sql.NullString
		if err := rows.Scan(&r.ID, &ts, &r.SessionID, &r.Direction, &method, &toolName, &r.RuleName, &r.Payload, &r.Decision, &decidedAt); err != nil {
			return nil, fmt.Errorf("scan approval: %w", err)
		}
		r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		r.Method = method.String
		r.ToolName = toolName.String
		if decidedAt.Valid {
			t, _ := time.Parse(time.RFC3339Nano, decidedAt.String)
			r.DecidedAt = &t
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// RegisterTools records tools from a tools/list response for a session.
func (s *SQLiteStore) RegisterTools(_ context.Context, sessionID string, tools []ToolRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO tool_registry (session_id, tool_name, description, first_seen)
		 VALUES (?, ?, ?, ?)`,
	)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339Nano)
	for _, t := range tools {
		if _, err := stmt.Exec(sessionID, t.ToolName, t.Description, now); err != nil {
			s.logger.Error("insert tool", "error", err, "tool", t.ToolName)
		}
	}

	return tx.Commit()
}

// GetToolAnalytics computes tool analytics across sessions.
func (s *SQLiteStore) GetToolAnalytics(_ context.Context, sessionID string) (*ToolAnalyticsSummary, error) {
	var whereClause string
	var args []any
	if sessionID != "" {
		whereClause = " WHERE session_id = ?"
		args = append(args, sessionID)
	}

	query := `
		SELECT
			tr.tool_name,
			tr.description,
			COALESCE(u.call_count, 0) AS call_count,
			COALESCE(u.sessions_used, 0) AS sessions_used,
			COALESCE(u.last_used, '') AS last_used
		FROM (
			SELECT DISTINCT tool_name, description
			FROM tool_registry` + whereClause + `
		) tr
		LEFT JOIN (
			SELECT
				tool_name,
				COUNT(*) AS call_count,
				COUNT(DISTINCT session_id) AS sessions_used,
				MAX(timestamp) AS last_used
			FROM messages
			WHERE tool_name IS NOT NULL AND tool_name != ''
			GROUP BY tool_name
		) u ON tr.tool_name = u.tool_name
		ORDER BY call_count DESC, tr.tool_name ASC
	`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query tool analytics: %w", err)
	}
	defer rows.Close()

	summary := &ToolAnalyticsSummary{}
	for rows.Next() {
		var ta ToolAnalytics
		if err := rows.Scan(&ta.ToolName, &ta.Description, &ta.CallCount, &ta.SessionsSeen, &ta.LastUsed); err != nil {
			return nil, fmt.Errorf("scan tool analytics: %w", err)
		}
		summary.Tools = append(summary.Tools, ta)
		summary.TotalAvailable++
		if ta.CallCount > 0 {
			summary.TotalUsed++
		}
	}

	return summary, rows.Err()
}

// GetToolUsageCounts returns per-tool call counts, optionally scoped to recent sessions.
func (s *SQLiteStore) GetToolUsageCounts(_ context.Context, lastNSessions int) (map[string]int, error) {
	var sessionClause string
	var args []any
	if lastNSessions > 0 {
		sessionClause = ` AND session_id IN (
			SELECT id FROM sessions ORDER BY started_at DESC LIMIT ?
		)`
		args = append(args, lastNSessions)
	}

	query := fmt.Sprintf(`
		SELECT tool_name, COUNT(*) AS cnt
		FROM messages
		WHERE tool_name IS NOT NULL AND tool_name != ''%s
		GROUP BY tool_name
	`, sessionClause)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query tool usage: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			continue
		}
		counts[name] = count
	}
	return counts, rows.Err()
}

// Close flushes pending writes and closes the database.
func (s *SQLiteStore) Close() error {
	close(s.writeCh)
	s.wg.Wait()
	return s.db.Close()
}

// scanner is an interface satisfied by both *sql.Rows and *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

func scanLogEntryFromScanner(sc scanner) (LogEntry, error) {
	var e LogEntry
	var ts string
	var method, msgID, matchedRulesJSON, toolName, policyAction sql.NullString
	var blocked, audit, scrubCount int

	err := sc.Scan(&e.ID, &ts, &e.SessionID, &e.Direction, &e.Kind,
		&method, &msgID, &e.Payload, &e.SizeBytes, &blocked,
		&audit, &scrubCount, &matchedRulesJSON, &toolName, &policyAction)
	if err != nil {
		return e, err
	}

	e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	e.Method = method.String
	e.MsgID = msgID.String
	e.Blocked = blocked != 0
	e.Audit = audit != 0
	e.ScrubCount = scrubCount
	e.ToolName = toolName.String
	e.PolicyAction = policyAction.String
	if matchedRulesJSON.Valid {
		json.Unmarshal([]byte(matchedRulesJSON.String), &e.MatchedRules)
	}
	return e, nil
}

// scanLogEntry scans a LogEntry from a *sql.Rows.
func scanLogEntry(rows *sql.Rows) (LogEntry, error) {
	return scanLogEntryFromScanner(rows)
}

// scanLogEntryRow scans a LogEntry from a *sql.Row.
func scanLogEntryRow(row *sql.Row) (LogEntry, error) {
	return scanLogEntryFromScanner(row)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
