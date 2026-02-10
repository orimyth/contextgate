package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/contextgate/contextgate/internal/store"
)

// handleIndex serves the main dashboard page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	messages, err := s.store.Query(r.Context(), store.QueryFilter{Limit: 100})
	if err != nil {
		s.logger.Error("query messages", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	stats, err := s.store.Stats(r.Context(), "")
	if err != nil {
		s.logger.Error("query stats", "error", err)
		stats = &store.Stats{MethodCounts: make(map[string]int)}
	}
	if s.approvalMgr != nil {
		stats.ApprovalPending = s.approvalMgr.PendingCount()
	}

	data := map[string]any{
		"Messages": messages,
		"Stats":    stats,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		s.logger.Error("render index", "error", err)
	}
}

// handleMessageDetail serves the detail panel for a single message.
func (s *Server) handleMessageDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	entry, err := s.store.GetMessage(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "message_detail.html", entry); err != nil {
		s.logger.Error("render detail", "error", err)
	}
}

// handleSSE streams live message and approval events to the browser.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID := fmt.Sprintf("sse-%d", time.Now().UnixNano())
	ch, unsub := s.eventBus.Subscribe(subID)
	defer unsub()

	approvalCh, approvalUnsub := s.eventBus.SubscribeApprovals(subID + "-approval")
	defer approvalUnsub()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}

			// Render message row HTML fragment
			var buf bytes.Buffer
			if err := s.tmpl.ExecuteTemplate(&buf, "message_row.html", entry); err != nil {
				s.logger.Error("render SSE fragment", "error", err)
				continue
			}

			// Write SSE event — multiline data
			fmt.Fprintf(w, "event: message\n")
			for _, line := range strings.Split(buf.String(), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprintf(w, "\n")
			flusher.Flush()

		case approval, ok := <-approvalCh:
			if !ok {
				return
			}

			// Render approval modal HTML fragment
			var buf bytes.Buffer
			if err := s.tmpl.ExecuteTemplate(&buf, "approval_modal.html", approval.Request); err != nil {
				s.logger.Error("render approval SSE fragment", "error", err)
				continue
			}

			fmt.Fprintf(w, "event: approval\n")
			for _, line := range strings.Split(buf.String(), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprintf(w, "\n")
			flusher.Flush()
		}
	}
}

// handleStatsPartial serves the stats bar as an HTMX partial.
func (s *Server) handleStatsPartial(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context(), "")
	if err != nil {
		s.logger.Error("query stats", "error", err)
		stats = &store.Stats{MethodCounts: make(map[string]int)}
	}

	// Enrich with live data
	if s.approvalMgr != nil {
		stats.ApprovalPending = s.approvalMgr.PendingCount()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "stats.html", stats); err != nil {
		s.logger.Error("render stats", "error", err)
	}
}

// handleAPIMessages returns messages as JSON.
func (s *Server) handleAPIMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.QueryFilter{
		SessionID: q.Get("session_id"),
		Direction: q.Get("direction"),
		Method:    q.Get("method"),
		Kind:      q.Get("kind"),
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		filter.Limit, _ = strconv.Atoi(limitStr)
	}
	if offsetStr := q.Get("offset"); offsetStr != "" {
		filter.Offset, _ = strconv.Atoi(offsetStr)
	}

	messages, err := s.store.Query(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// handleAPIStats returns stats as JSON.
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	stats, err := s.store.Stats(r.Context(), sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleApprove approves a pending approval request.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.approvalMgr == nil {
		http.Error(w, "approval not enabled", http.StatusNotFound)
		return
	}
	if err := s.approvalMgr.Resolve(id, true); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<div class="approval-resolved">Approved</div>`))
}

// handleDeny denies a pending approval request.
func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.approvalMgr == nil {
		http.Error(w, "approval not enabled", http.StatusNotFound)
		return
	}
	if err := s.approvalMgr.Resolve(id, false); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<div class="approval-resolved">Denied</div>`))
}

// handlePendingApprovals returns pending approval requests as JSON.
func (s *Server) handlePendingApprovals(w http.ResponseWriter, r *http.Request) {
	if s.approvalMgr == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
		return
	}
	pending := s.approvalMgr.Pending()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

// handleToolAnalytics returns tool analytics as JSON.
func (s *Server) handleToolAnalytics(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	analytics, err := s.store.GetToolAnalytics(r.Context(), sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analytics)
}

// handleToolAnalyticsPartial serves the tool analytics section as an HTMX partial.
func (s *Server) handleToolAnalyticsPartial(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	analytics, err := s.store.GetToolAnalytics(r.Context(), sessionID)
	if err != nil {
		s.logger.Error("query tool analytics", "error", err)
		analytics = &store.ToolAnalyticsSummary{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "tool_analytics.html", analytics); err != nil {
		s.logger.Error("render tool analytics", "error", err)
	}
}

// prettyJSON formats a JSON string for display.
func prettyJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return s
	}
	return buf.String()
}
