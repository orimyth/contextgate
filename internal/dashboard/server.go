package dashboard

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/contextgate/contextgate/internal/eventbus"
	"github.com/contextgate/contextgate/internal/proxy"
	"github.com/contextgate/contextgate/internal/store"
)

//go:embed static
var staticFS embed.FS

//go:embed templates
var templateFS embed.FS

// Server is the HTMX dashboard HTTP server.
type Server struct {
	store          store.Store
	eventBus       *eventbus.EventBus
	approvalMgr    *proxy.ApprovalManager
	scrubber       *proxy.ScrubberInterceptor
	toolAnalytics  *proxy.ToolAnalyticsInterceptor
	logger         *slog.Logger
	tmpl           *template.Template
	addr           string
}

func NewServer(addr string, s store.Store, eb *eventbus.EventBus, approvalMgr *proxy.ApprovalManager, scrubber *proxy.ScrubberInterceptor, toolAnalytics *proxy.ToolAnalyticsInterceptor, logger *slog.Logger) (*Server, error) {
	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("15:04:05.000")
		},
		"formatTimeFull": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05.000")
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"kindClass": func(k string) string {
			switch k {
			case "request":
				return "kind-request"
			case "response":
				return "kind-response"
			case "notification":
				return "kind-notification"
			case "error":
				return "kind-error"
			default:
				return "kind-unknown"
			}
		},
		"dirArrow": func(d string) string {
			if d == "host_to_server" {
				return "\u2192" // →
			}
			return "\u2190" // ←
		},
		"dirLabel": func(d string) string {
			if d == "host_to_server" {
				return "Host \u2192 Server"
			}
			return "Server \u2192 Host"
		},
		"prettyJSON": prettyJSON,
		"joinStrings": func(strs []string, sep string) string {
			return strings.Join(strs, sep)
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS,
		"templates/*.html",
		"templates/partials/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	return &Server{
		store:         s,
		eventBus:      eb,
		approvalMgr:   approvalMgr,
		scrubber:      scrubber,
		toolAnalytics: toolAnalytics,
		logger:        logger,
		tmpl:          tmpl,
		addr:          addr,
	}, nil
}

// Start starts the HTTP server. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Static assets
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Pages
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /messages/{id}", s.handleMessageDetail)

	// SSE
	mux.HandleFunc("GET /events", s.handleSSE)

	// HTMX partials
	mux.HandleFunc("GET /partials/stats", s.handleStatsPartial)
	mux.HandleFunc("GET /partials/tool-analytics", s.handleToolAnalyticsPartial)

	// JSON API
	mux.HandleFunc("GET /api/messages", s.handleAPIMessages)
	mux.HandleFunc("GET /api/stats", s.handleAPIStats)
	mux.HandleFunc("GET /api/tools/analytics", s.handleToolAnalytics)

	// Approval API
	mux.HandleFunc("POST /api/approve/{id}", s.handleApprove)
	mux.HandleFunc("POST /api/deny/{id}", s.handleDeny)
	mux.HandleFunc("GET /api/approvals/pending", s.handlePendingApprovals)

	server := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutCtx)
	}()

	s.logger.Info("dashboard starting", "url", fmt.Sprintf("http://localhost%s", s.addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
