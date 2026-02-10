package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/contextgate/contextgate/internal/cli"
	"github.com/contextgate/contextgate/internal/dashboard"
	"github.com/contextgate/contextgate/internal/eventbus"
	"github.com/contextgate/contextgate/internal/policy"
	"github.com/contextgate/contextgate/internal/proxy"
	"github.com/contextgate/contextgate/internal/store"
)

var version = "dev"

func main() {
	// Check for subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "setup":
			if err := cli.RunSetup(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		case "wrap":
			if err := cli.RunWrap(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			return
		case "version":
			fmt.Fprintf(os.Stderr, "contextgate %s\n", version)
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	// Proxy mode — parse flags
	proxyFlags := flag.NewFlagSet("proxy", flag.ExitOnError)
	dashAddr := proxyFlags.String("dashboard", ":9000", "dashboard listen address (empty to disable)")
	dbPath := proxyFlags.String("db", defaultDBPath(), "SQLite database path")
	logLevel := proxyFlags.String("log-level", "info", "log level (debug, info, warn, error)")
	noBrowser := proxyFlags.Bool("no-browser", false, "don't auto-open the dashboard in a browser")
	policyPath := proxyFlags.String("policy", "", "path to security policy YAML file")
	scrubPII := proxyFlags.Bool("scrub-pii", false, "enable PII scrubbing in responses")
	approvalTimeout := proxyFlags.Duration("approval-timeout", 60*time.Second, "timeout for approval requests")
	pruneUnused := proxyFlags.Int("prune-unused", 0, "prune tools unused in the last N sessions (0 = disabled)")
	pruneKeepTop := proxyFlags.Int("prune-keep-top", 0, "keep only the top K most-used tools (0 = disabled)")
	pruneKeep := proxyFlags.String("prune-keep", "", "comma-separated tool names that should never be pruned")
	showVersion := proxyFlags.Bool("version", false, "print version and exit")
	proxyFlags.Parse(os.Args[1:])

	if *showVersion {
		fmt.Fprintf(os.Stderr, "contextgate %s\n", version)
		os.Exit(0)
	}

	// Everything after flags is the downstream command
	args := proxyFlags.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}

	cmdArgs := args
	if args[0] == "--" {
		cmdArgs = args[1:]
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no downstream command specified after --")
		os.Exit(2)
	}

	// Logger — all output goes to stderr (stdout is for MCP JSON-RPC)
	level := parseLogLevel(*logLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize store
	sqliteStore, err := store.NewSQLiteStore(*dbPath, logger)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer sqliteStore.Close()

	// Initialize event bus
	eb := eventbus.New(256)

	// Build interceptor chain
	var interceptors []proxy.Interceptor

	// Policy interceptor (optional — only if --policy is set)
	var policyEngine *policy.Engine
	var policyCfg *policy.Config
	if *policyPath != "" {
		var err error
		policyCfg, err = policy.Load(*policyPath)
		if err != nil {
			logger.Error("failed to load policy", "path", *policyPath, "error", err)
			os.Exit(1)
		}
		policyEngine = policy.NewEngine(policyCfg)
		interceptors = append(interceptors, proxy.NewPolicyInterceptor(policyEngine))
		logger.Info("policy loaded", "path", *policyPath, "rules", len(policyCfg.Rules))
	}

	// Scrubber interceptor
	scrubEnabled := *scrubPII
	var customPatterns []policy.CustomPattern
	if policyCfg != nil && policyCfg.Scrubber.Enabled {
		scrubEnabled = true
		customPatterns = policyCfg.Scrubber.CustomPatterns
	}
	scrubber := proxy.NewScrubberInterceptor(scrubEnabled, customPatterns)
	interceptors = append(interceptors, scrubber)

	// Approval interceptor
	approvalMgr := proxy.NewApprovalManager(*approvalTimeout)
	approvalMgr.OnRequest = func(req *proxy.ApprovalRequest) {
		eb.PublishApproval(&store.ApprovalEvent{
			Type: "requested",
			Request: &store.ApprovalRecord{
				ID:        req.ID,
				Timestamp: req.Timestamp,
				SessionID: req.SessionID,
				Direction: req.Direction,
				Method:    req.Method,
				ToolName:  req.ToolName,
				RuleName:  req.RuleName,
				Payload:   req.Payload,
				Decision:  req.Decision,
			},
		})
	}
	interceptors = append(interceptors, proxy.NewApprovalInterceptor(approvalMgr))

	// Tool analytics interceptor (tracks tools/list, optional pruning)
	var alwaysKeep []string
	if *pruneKeep != "" {
		for _, name := range strings.Split(*pruneKeep, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				alwaysKeep = append(alwaysKeep, name)
			}
		}
	}
	toolAnalytics := proxy.NewToolAnalyticsInterceptor(sqliteStore, logger, proxy.PruneConfig{
		UnusedSessions: *pruneUnused,
		KeepTopK:       *pruneKeepTop,
		AlwaysKeep:     alwaysKeep,
	})
	interceptors = append(interceptors, toolAnalytics)

	// Logging interceptor (always last — records final enriched state)
	loggingInterceptor := proxy.NewLoggingInterceptor(sqliteStore, eb)
	interceptors = append(interceptors, loggingInterceptor)

	chain := proxy.NewInterceptorChain(interceptors...)

	// Start dashboard in background
	if *dashAddr != "" {
		dash, err := dashboard.NewServer(*dashAddr, sqliteStore, eb, approvalMgr, scrubber, toolAnalytics, logger)
		if err != nil {
			logger.Error("failed to initialize dashboard", "error", err)
			os.Exit(1)
		}
		go func() {
			if err := dash.Start(ctx); err != nil {
				logger.Error("dashboard error", "error", err)
			}
		}()

		// Auto-open browser
		if !*noBrowser {
			dashURL := fmt.Sprintf("http://localhost%s", *dashAddr)
			go func() {
				// Small delay to let the server start
				time.Sleep(300 * time.Millisecond)
				if err := cli.OpenBrowser(dashURL); err != nil {
					logger.Debug("could not open browser", "error", err)
				}
			}()
		}
	}

	// Create and run proxy
	cfg := proxy.Config{
		Command: cmdArgs[0],
		Args:    cmdArgs[1:],
	}
	p := proxy.NewProxy(cfg, chain, logger)

	// Record session
	sqliteStore.CreateSession(ctx, &store.Session{
		ID:        p.SessionID(),
		StartedAt: time.Now(),
		Command:   cfg.Command,
		Args:      cfg.Args,
	})
	defer sqliteStore.EndSession(context.Background(), p.SessionID())

	// Run proxy — blocks until downstream exits
	if err := p.Run(ctx); err != nil {
		logger.Error("proxy exited", "error", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "ContextGate — MCP Proxy & Inspector")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  contextgate [options] -- <command> [args...]   Proxy an MCP server")
	fmt.Fprintln(os.Stderr, "  contextgate setup                              Interactive setup wizard")
	fmt.Fprintln(os.Stderr, "  contextgate wrap <name> -- <command> [args...] Register in Claude Code")
	fmt.Fprintln(os.Stderr, "  contextgate version                            Print version")
	fmt.Fprintln(os.Stderr, "  contextgate help                               Show this help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Proxy options:")
	fmt.Fprintln(os.Stderr, "  -dashboard string       Dashboard listen address (default \":9000\", \"\" to disable)")
	fmt.Fprintln(os.Stderr, "  -db string              SQLite database path (default \"~/.contextgate/contextgate.db\")")
	fmt.Fprintln(os.Stderr, "  -log-level string       Log level: debug, info, warn, error (default \"info\")")
	fmt.Fprintln(os.Stderr, "  -no-browser             Don't auto-open the dashboard in a browser")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Security options:")
	fmt.Fprintln(os.Stderr, "  -policy string          Path to security policy YAML file")
	fmt.Fprintln(os.Stderr, "  -scrub-pii              Enable PII scrubbing in server responses")
	fmt.Fprintln(os.Stderr, "  -approval-timeout dur   Timeout for approval requests (default \"60s\")")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Context optimization:")
	fmt.Fprintln(os.Stderr, "  -prune-unused int       Prune tools unused in the last N sessions (0 = disabled)")
	fmt.Fprintln(os.Stderr, "  -prune-keep-top int     Keep only the top K most-used tools (0 = disabled)")
	fmt.Fprintln(os.Stderr, "  -prune-keep string      Comma-separated tools that should never be pruned")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  contextgate -- npx -y @modelcontextprotocol/server-filesystem /tmp")
	fmt.Fprintln(os.Stderr, "  contextgate --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp")
	fmt.Fprintln(os.Stderr, "  contextgate --scrub-pii -- npx -y @modelcontextprotocol/server-filesystem /tmp")
	fmt.Fprintln(os.Stderr, "  contextgate --prune-unused 3 -- npx -y @modelcontextprotocol/server-filesystem /tmp")
	fmt.Fprintln(os.Stderr, "  contextgate setup")
	fmt.Fprintln(os.Stderr, "  contextgate wrap my-fs -- npx -y @modelcontextprotocol/server-filesystem /tmp")
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".contextgate")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "contextgate.db")
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
