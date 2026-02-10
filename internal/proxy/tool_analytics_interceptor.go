package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/contextgate/contextgate/internal/store"
)

// MetaKeyToolsPruned is set when tools are pruned from a tools/list response.
const MetaKeyToolsPruned = "tools_pruned"

// PruneConfig controls tool pruning behavior.
type PruneConfig struct {
	UnusedSessions int      // prune tools with 0 calls in last N sessions (0=disabled)
	KeepTopK       int      // keep only top K most-used tools (0=disabled)
	AlwaysKeep     []string // tool names that should never be pruned
}

func (c PruneConfig) enabled() bool {
	return c.UnusedSessions > 0 || c.KeepTopK > 0
}

// pendingRequest tracks a tools/list request waiting for its response.
type pendingRequest struct {
	sessionID string
	timestamp time.Time
}

// ToolAnalyticsInterceptor tracks tool availability and usage,
// and optionally prunes rarely-used tools from tools/list responses.
type ToolAnalyticsInterceptor struct {
	store       store.Store
	logger      *slog.Logger
	pruneConfig PruneConfig

	mu         sync.Mutex
	pendingIDs map[string]*pendingRequest
}

// NewToolAnalyticsInterceptor creates a tool analytics interceptor.
func NewToolAnalyticsInterceptor(s store.Store, logger *slog.Logger, cfg PruneConfig) *ToolAnalyticsInterceptor {
	ta := &ToolAnalyticsInterceptor{
		store:       s,
		logger:      logger,
		pruneConfig: cfg,
		pendingIDs:  make(map[string]*pendingRequest),
	}
	go ta.cleanupLoop()
	return ta
}

func (ta *ToolAnalyticsInterceptor) Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error) {
	if msg.ParseErr != nil {
		return msg.RawBytes, nil
	}

	// Track outgoing tools/list requests
	if msg.Direction == DirHostToServer && msg.Parsed.Method == "tools/list" {
		if msg.Parsed.ID != nil {
			idStr := string(msg.Parsed.ID)
			ta.mu.Lock()
			ta.pendingIDs[idStr] = &pendingRequest{
				sessionID: msg.SessionID,
				timestamp: msg.Timestamp,
			}
			ta.mu.Unlock()
		}
		return msg.RawBytes, nil
	}

	// Check if this is a tools/list response
	if msg.Direction == DirServerToHost && msg.Parsed.Kind() == KindResponse && msg.Parsed.ID != nil {
		idStr := string(msg.Parsed.ID)
		ta.mu.Lock()
		pending, found := ta.pendingIDs[idStr]
		if found {
			delete(ta.pendingIDs, idStr)
		}
		ta.mu.Unlock()

		if found {
			return ta.handleToolsListResponse(ctx, msg, pending)
		}
	}

	return msg.RawBytes, nil
}

// toolsListResult represents the result field of a tools/list response.
type toolsListResult struct {
	Tools []json.RawMessage `json:"tools"`
}

// toolNameOnly extracts just the name from a raw tool JSON object.
type toolNameOnly struct {
	Name string `json:"name"`
}

func (ta *ToolAnalyticsInterceptor) handleToolsListResponse(
	ctx context.Context,
	msg *InterceptedMessage,
	pending *pendingRequest,
) ([]byte, error) {
	if msg.Parsed.Result == nil {
		return msg.RawBytes, nil
	}

	// Parse the result to extract tools
	var result toolsListResult
	if err := json.Unmarshal(msg.Parsed.Result, &result); err != nil {
		ta.logger.Debug("failed to parse tools/list result", "error", err)
		return msg.RawBytes, nil
	}

	// Extract tool names and descriptions for registration
	var records []store.ToolRecord
	for _, toolRaw := range result.Tools {
		var t struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(toolRaw, &t); err != nil {
			continue
		}
		records = append(records, store.ToolRecord{
			SessionID:   pending.sessionID,
			ToolName:    t.Name,
			Description: t.Description,
		})
	}

	ta.logger.Info("tools/list response",
		"session", pending.sessionID,
		"tool_count", len(records),
	)

	if len(records) > 0 {
		if err := ta.store.RegisterTools(ctx, pending.sessionID, records); err != nil {
			ta.logger.Error("failed to register tools", "error", err)
		}
	}

	// If pruning is not configured, pass through unchanged
	if !ta.pruneConfig.enabled() {
		return msg.RawBytes, nil
	}

	// Get historical usage counts for pruning decisions
	usageCounts, err := ta.store.GetToolUsageCounts(ctx, ta.pruneConfig.UnusedSessions)
	if err != nil {
		ta.logger.Error("failed to get usage counts for pruning", "error", err)
		return msg.RawBytes, nil
	}

	// Determine which tools to keep
	kept, pruned := ta.applyPruning(result.Tools, usageCounts)
	if len(pruned) == 0 {
		return msg.RawBytes, nil
	}

	if msg.Metadata == nil {
		msg.Metadata = make(map[string]any)
	}
	msg.Metadata[MetaKeyToolsPruned] = len(pruned)

	ta.logger.Info("pruned tools from response",
		"kept", len(kept),
		"pruned", len(pruned),
	)

	return ta.rebuildResponse(msg, kept)
}

func (ta *ToolAnalyticsInterceptor) applyPruning(
	tools []json.RawMessage,
	usageCounts map[string]int,
) (kept, pruned []json.RawMessage) {
	alwaysKeep := make(map[string]bool)
	for _, name := range ta.pruneConfig.AlwaysKeep {
		alwaysKeep[name] = true
	}

	// Parse tool names
	type toolWithUsage struct {
		raw   json.RawMessage
		name  string
		count int
	}
	var toolInfos []toolWithUsage
	for _, raw := range tools {
		var t toolNameOnly
		if err := json.Unmarshal(raw, &t); err != nil {
			// Can't parse — keep it
			kept = append(kept, raw)
			continue
		}
		toolInfos = append(toolInfos, toolWithUsage{
			raw:   raw,
			name:  t.Name,
			count: usageCounts[t.Name],
		})
	}

	keepSet := make(map[string]bool)

	// Strategy 1: Remove tools unused in last N sessions
	if ta.pruneConfig.UnusedSessions > 0 {
		for _, ti := range toolInfos {
			if alwaysKeep[ti.name] || ti.count > 0 {
				keepSet[ti.name] = true
			}
		}
	} else {
		// No unused-sessions filter — keep all by default
		for _, ti := range toolInfos {
			keepSet[ti.name] = true
		}
	}

	// Strategy 2: Keep only top K (applied on top)
	if ta.pruneConfig.KeepTopK > 0 {
		// Count non-always-keep tools in the keep set
		var inSet []toolWithUsage
		for _, ti := range toolInfos {
			if keepSet[ti.name] && !alwaysKeep[ti.name] {
				inSet = append(inSet, ti)
			}
		}

		if len(inSet) > ta.pruneConfig.KeepTopK {
			sort.Slice(inSet, func(i, j int) bool {
				return inSet[i].count > inSet[j].count
			})

			// Rebuild keep set: always-keep + top K
			newKeep := make(map[string]bool)
			for name := range alwaysKeep {
				newKeep[name] = true
			}
			for i := 0; i < ta.pruneConfig.KeepTopK && i < len(inSet); i++ {
				newKeep[inSet[i].name] = true
			}
			keepSet = newKeep
		}
	}

	// Ensure always-keep tools are in the set
	for name := range alwaysKeep {
		keepSet[name] = true
	}

	for _, ti := range toolInfos {
		if keepSet[ti.name] {
			kept = append(kept, ti.raw)
		} else {
			pruned = append(pruned, ti.raw)
		}
	}

	return kept, pruned
}

func (ta *ToolAnalyticsInterceptor) rebuildResponse(
	msg *InterceptedMessage,
	keptTools []json.RawMessage,
) ([]byte, error) {
	// Parse the full result as a generic map to preserve extra fields (cursor, etc.)
	var fullResult map[string]json.RawMessage
	if err := json.Unmarshal(msg.Parsed.Result, &fullResult); err != nil {
		return msg.RawBytes, nil
	}

	toolsJSON, err := json.Marshal(keptTools)
	if err != nil {
		return msg.RawBytes, nil
	}
	fullResult["tools"] = toolsJSON

	newResult, err := json.Marshal(fullResult)
	if err != nil {
		return msg.RawBytes, nil
	}

	resp := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      msg.Parsed.ID,
		Result:  newResult,
	}
	rebuilt, err := json.Marshal(resp)
	if err != nil {
		return msg.RawBytes, nil
	}
	return rebuilt, nil
}

// cleanupLoop removes stale pending IDs every 60 seconds.
func (ta *ToolAnalyticsInterceptor) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ta.mu.Lock()
		cutoff := time.Now().Add(-5 * time.Minute)
		for id, p := range ta.pendingIDs {
			if p.timestamp.Before(cutoff) {
				delete(ta.pendingIDs, id)
			}
		}
		ta.mu.Unlock()
	}
}
