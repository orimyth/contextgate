<p align="center">
  <h1 align="center">ContextGate</h1>
  <p align="center">
    <strong>Security & observability layer for AI agents.</strong>
    <br />
    See every tool call. Block dangerous ones. Scrub secrets. Prune unused tools.
  </p>
</p>

---

ContextGate sits between your LLM host and MCP servers as a transparent proxy. It captures every JSON-RPC message in both directions and streams them to a live dashboard — while enforcing security policies, scrubbing PII, gating destructive operations behind human approval, and pruning unused tools to save context tokens.

- **Single binary, zero dependencies** — one `go build`, no runtime requirements
- **Works with any MCP server** — filesystem, GitHub, databases, custom servers
- **Zero-latency logging** — async buffered writes, no impact on agent performance
- **Protocol-version agnostic** — works with any MCP spec version

## Features

### Flight Recorder (Phase 1)
Every JSON-RPC message between the host and MCP server is captured, stored in SQLite, and streamed to a real-time dashboard.

- Live message feed with SSE (Server-Sent Events)
- Detail panel with full pretty-printed JSON-RPC payloads
- Stats bar with live counters (requests, responses, errors, blocked)
- Filters by direction and message type
- JSON API for programmatic access

### Iron Dome (Phase 2)
A YAML-driven policy engine that evaluates every message against security rules before it reaches the MCP server.

- **Deny** — block tool calls outright (e.g., prevent writes to `.env` files)
- **Require Approval** — gate destructive operations behind human review in the dashboard
- **Audit** — flag messages for detailed logging without blocking
- **PII Scrubbing** — automatically redact API keys, emails, SSNs, and IP addresses from server responses
- **Custom Patterns** — define your own regex patterns for scrubbing proprietary tokens

### Context Compressor (Phase 3)
Tracks which tools MCP servers expose and which ones the agent actually uses. Optionally prunes unused tools from `tools/list` responses to reduce context token overhead.

- **Tool Analytics** — dashboard section showing per-tool call counts, session coverage, and last-used timestamps
- **Pruning** — automatically remove tools with zero usage from `tools/list` responses
- **Always-keep list** — protect critical tools from being pruned
- **Top-K mode** — keep only the K most-used tools

## Quick Start

### Install

```bash
git clone https://github.com/contextgate/contextgate.git
cd contextgate
make build
```

### Option A: Interactive Setup (recommended)

```bash
./contextgate setup
```

This auto-detects your MCP clients (Claude Desktop, Claude Code, Cursor), shows your existing servers, and wraps them with one prompt.

### Option B: Claude Code One-Liner

```bash
./contextgate wrap my-fs -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

This registers a ContextGate-wrapped MCP server directly into Claude Code.

### Option C: Manual

Wrap any MCP server command:

```bash
contextgate -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

The dashboard opens automatically at **http://localhost:9000**.

## Client Configuration

<details>
<summary><strong>Claude Desktop</strong></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/path/to/contextgate",
      "args": ["--dashboard", ":9000", "--", "npx", "-y",
               "@modelcontextprotocol/server-filesystem", "/Users/you/Documents"]
    }
  }
}
```
</details>

<details>
<summary><strong>Cursor</strong></summary>

Edit `.cursor/mcp.json` or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/path/to/contextgate",
      "args": ["--dashboard", ":9000", "--", "npx", "-y",
               "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]
    }
  }
}
```
</details>

<details>
<summary><strong>Claude Code</strong></summary>

```bash
claude mcp add --transport stdio --scope user my-server \
  -- /path/to/contextgate --dashboard :9000 \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Or use the shorthand: `contextgate wrap my-server -- npx -y @modelcontextprotocol/server-filesystem /tmp`
</details>

## Security Policy

Create a YAML policy file to control what your AI agent can and cannot do:

```yaml
version: "1"

rules:
  # Block writing to .env files
  - name: protect-env-files
    action: deny
    methods: ["tools/call"]
    tools: ["write_file", "filesystem_write"]
    patterns:
      - '\.env'

  # Block arbitrary command execution
  - name: block-shell-execution
    action: deny
    methods: ["tools/call"]
    tools: ["execute_command", "run_shell", "run_terminal_command"]

  # Require human approval for destructive operations
  - name: approve-deletions
    action: require_approval
    methods: ["tools/call"]
    tools: ["delete_file", "remove_directory"]

  # Audit all tool calls
  - name: audit-all-tools
    action: audit
    methods: ["tools/call"]

# PII scrubbing configuration
scrubber:
  enabled: true
  custom_patterns:
    - name: internal_token
      pattern: 'ctx_[A-Za-z0-9]{32,}'
      label: internal_token
```

Run with a policy:

```bash
contextgate --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Policy Rule Reference

| Field | Description |
|-------|-------------|
| `name` | Human-readable rule identifier |
| `action` | `deny`, `require_approval`, or `audit` |
| `methods` | JSON-RPC methods to match (e.g., `tools/call`, `tools/list`) |
| `tools` | Tool names to match (from the `params.name` field) |
| `patterns` | Regex patterns matched against the full message payload |

**Priority**: When multiple rules match, `deny` takes priority over `require_approval`, which takes priority over `audit`.

### Built-in PII Patterns

When PII scrubbing is enabled (via `--scrub-pii` or `scrubber.enabled: true` in the policy file), the following patterns are automatically redacted from **server-to-host** responses:

| Pattern | Label | Example |
|---------|-------|---------|
| OpenAI API keys | `api_key` | `sk-abc123...` |
| GitHub PATs | `api_key` | `ghp_abc123...` |
| AWS access keys | `api_key` | `AKIA...` |
| Email addresses | `email` | `user@example.com` |
| SSNs | `ssn` | `123-45-6789` |
| IPv4 addresses | `ip_address` | `192.168.1.1` |

Redacted values are replaced with `[REDACTED:label]`.

## Tool Pruning

MCP servers often expose 20-50+ tools, but agents typically use only a few per session. Each unused tool wastes context tokens on its name, description, and JSON schema. ContextGate can prune unused tools from `tools/list` responses:

```bash
# Remove tools with zero calls in the last 3 sessions
contextgate --prune-unused 3 -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Keep only the top 10 most-used tools
contextgate --prune-keep-top 10 -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Protect specific tools from pruning
contextgate --prune-unused 3 --prune-keep "read_file,write_file" -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Pruning decisions are based on historical usage data stored in SQLite. The first session sees all tools; pruning activates from the second session onward.

## Dashboard

Real-time web UI at `localhost:9000` with Server-Sent Events — no polling, no WebSockets.

- **Live feed** — messages appear instantly as they flow through the proxy
- **Detail panel** — click any row for the full pretty-printed JSON-RPC payload
- **Stats bar** — live counters for requests, responses, errors, and blocked messages
- **Tool analytics** — per-tool call counts, session coverage, pruning status
- **Approval notifications** — approve or deny gated operations directly in the dashboard
- **Filters** — by direction and message type
- **JSON API** — `GET /api/messages`, `GET /api/stats`, `GET /api/tools/analytics`, `GET /events` (SSE stream)

## Architecture

```
Host (Claude / Cursor)
    │ stdin/stdout
    ▼
 ContextGate
    ├─ Interceptor Chain
    │   ├─ PolicyInterceptor      → deny / require_approval / audit
    │   ├─ ScrubberInterceptor    → redact PII in responses
    │   ├─ ApprovalInterceptor    → gate operations behind human review
    │   ├─ ToolAnalyticsInterceptor → track + prune tools
    │   └─ LoggingInterceptor     → persist to SQLite + publish to EventBus
    ├─ SQLite (async buffered writes)
    ├─ EventBus (fan-out pub/sub)
    └─ Dashboard (HTMX + SSE, :9000)
    │
    ▼ subprocess
 Real MCP Server
```

Raw JSON-RPC interception — no SDK wrapping, no re-registration of tools. Messages pass through a pluggable interceptor chain where each interceptor can forward, modify, or block.

## CLI Reference

```
contextgate [options] -- <command> [args...]   Proxy an MCP server
contextgate setup                              Interactive setup wizard
contextgate wrap <name> -- <cmd> [args...]     Register in Claude Code
contextgate version                            Print version
contextgate help                               Show help
```

### Proxy Options

| Flag | Default | Description |
|------|---------|-------------|
| `-dashboard` | `:9000` | Dashboard address (`""` to disable) |
| `-db` | `~/.contextgate/contextgate.db` | SQLite database path |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-no-browser` | `false` | Don't auto-open dashboard |

### Security Options

| Flag | Default | Description |
|------|---------|-------------|
| `-policy` | | Path to security policy YAML file |
| `-scrub-pii` | `false` | Enable PII scrubbing in server responses |
| `-approval-timeout` | `60s` | Timeout for human approval requests |

### Context Optimization

| Flag | Default | Description |
|------|---------|-------------|
| `-prune-unused` | `0` | Prune tools unused in last N sessions (0 = disabled) |
| `-prune-keep-top` | `0` | Keep only top K most-used tools (0 = disabled) |
| `-prune-keep` | | Comma-separated tools that should never be pruned |

## Roadmap

- [x] **Phase 1: Flight Recorder** — proxy, SQLite logging, live HTMX dashboard, JSON API
- [x] **Phase 2: Iron Dome** — YAML policy engine, PII scrubbing, human-in-the-loop approval
- [x] **Phase 3: Context Compressor** — tool analytics, usage tracking, dynamic tool pruning
- [ ] **Phase 4: Launch** — `brew install`, GoReleaser, demo GIFs, Docker

## Development

```bash
make build          # Build binary
make test           # Run tests
go test -v ./...    # Verbose tests
```

### Project Structure

```
├── main.go                          # Entry point, flag parsing, wiring
├── configs/
│   └── example-policy.yaml          # Example security policy
├── internal/
│   ├── cli/                         # CLI commands (setup, wrap, detect)
│   ├── dashboard/                   # HTMX dashboard server + templates
│   ├── eventbus/                    # Fan-out pub/sub for real-time events
│   ├── policy/                      # YAML policy engine (rules, actions)
│   ├── proxy/                       # Core proxy + interceptor chain
│   └── store/                       # SQLite persistence layer
```

### Extending

The `Interceptor` interface is the primary extension point:

```go
type Interceptor interface {
    Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error)
}
```

Return semantics:
- `(modifiedBytes, nil)` — forward the (possibly modified) message
- `(nil, nil)` — drop the message silently
- `(nil, err)` — block the message and return a JSON-RPC error

## Contributing

Contributions welcome. Fork, branch, test (`make test`), PR.

## License

[MIT](LICENSE)
