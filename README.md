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

## How It Works

ContextGate wraps any MCP server command. The basic pattern is:

```
contextgate [options] -- <server command>
                      ^^
            separator between contextgate
            options and your server command
```

For example, if you normally run your MCP server like this:

```bash
npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

Just put `contextgate --` in front:

```bash
contextgate -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

That's it. The dashboard opens at **http://localhost:9000** and you can watch every message in real time.

## Quick Start

### Install

**macOS (Homebrew):**
```bash
brew install orimyth/contextgate/contextgate
```

**Go install:**
```bash
go install github.com/orimyth/contextgate@latest
```

**Download a binary:** grab the latest release from [GitHub Releases](https://github.com/orimyth/contextgate/releases) for your OS and architecture (macOS, Linux, Windows).

**Build from source:**
```bash
git clone https://github.com/orimyth/contextgate.git
cd contextgate
make build
```

### Option A: Interactive Setup (recommended)

```bash
./contextgate setup
```

This auto-detects your MCP clients (Claude Desktop, Claude Code, Cursor), shows your existing servers, and offers to wrap them automatically.

### Option B: Claude Code

Register an MCP server wrapped with ContextGate in one command:

```bash
./contextgate wrap my-fs -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

This calls `claude mcp add` under the hood — no manual config needed.

### Option C: Direct

Run ContextGate directly (useful for testing or non-Claude clients):

```bash
./contextgate -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

## Client Configuration

<details>
<summary><strong>Claude Desktop</strong></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`.

Replace `command` with the path to ContextGate, and move your original server command into `args` after the `--` separator:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/path/to/contextgate",
      "args": [
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
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
    "my-server": {
      "command": "/path/to/contextgate",
      "args": [
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/you/projects"
      ]
    }
  }
}
```
</details>

<details>
<summary><strong>Claude Code (manual)</strong></summary>

If you prefer to register manually instead of using `contextgate wrap`:

```bash
claude mcp add my-server \
  -t stdio \
  -s user \
  -- /path/to/contextgate -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

Breakdown:
- `my-server` — name you'll see in Claude Code
- `-t stdio` — transport type (always stdio for ContextGate)
- `-s user` — scope (user-wide, or use `project` for per-project)
- first `--` — separates `claude mcp add` options from the command
- second `--` — separates ContextGate options from the server command
</details>

## Security Policy

Create a YAML file to control what your AI agent can and cannot do:

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

# Auto-redact secrets from server responses
scrubber:
  enabled: true
  custom_patterns:
    - name: internal_token
      pattern: 'ctx_[A-Za-z0-9]{32,}'
      label: internal_token
```

Enable it with the `--policy` flag:

```bash
contextgate --policy policy.yaml -- <server command>
```

A full example is included at `configs/example-policy.yaml`.

### Policy Rule Reference

| Field | Description |
|-------|-------------|
| `name` | Human-readable rule identifier |
| `action` | `deny`, `require_approval`, or `audit` |
| `methods` | JSON-RPC methods to match (e.g., `tools/call`, `tools/list`) |
| `tools` | Tool names to match (from the `params.name` field) |
| `patterns` | Regex patterns matched against the full message payload |

**Priority**: When multiple rules match, `deny` > `require_approval` > `audit`.

### PII Scrubbing

Enable with `--scrub-pii` or `scrubber.enabled: true` in your policy file. The following patterns are automatically redacted from server responses:

| Pattern | Redacted as |
|---------|-------------|
| OpenAI keys (`sk-...`) | `[REDACTED:api_key]` |
| GitHub tokens (`ghp_...`, `gho_...`) | `[REDACTED:api_key]` |
| AWS keys (`AKIA...`) | `[REDACTED:api_key]` |
| Email addresses | `[REDACTED:email]` |
| SSNs (`123-45-6789`) | `[REDACTED:ssn]` |
| IPv4 addresses | `[REDACTED:ip_address]` |

Add custom patterns in your policy YAML under `scrubber.custom_patterns`.

## Tool Pruning

MCP servers often expose 20-50+ tools, but agents typically use only a few. Each unused tool wastes context tokens. ContextGate can automatically remove unused tools from `tools/list` responses.

```bash
# Prune tools that had zero calls in the last 3 sessions
contextgate --prune-unused 3 -- <server command>

# Only keep the 10 most-used tools
contextgate --prune-keep-top 10 -- <server command>

# Combine: prune unused, but always keep specific tools
contextgate --prune-unused 3 --prune-keep read_file,write_file -- <server command>
```

Pruning uses historical usage data from SQLite. All tools are visible in the first session; pruning kicks in from the second session onward.

## Dashboard

Real-time web UI at `localhost:9000` — no polling, no WebSockets, just SSE.

- **Live feed** — messages appear instantly as they flow through the proxy
- **Detail panel** — click any row for the full pretty-printed JSON-RPC payload
- **Stats bar** — live counters for requests, responses, errors, and blocked messages
- **Tool analytics** — per-tool call counts, session coverage, pruning status
- **Approval notifications** — approve or deny gated operations directly in the dashboard
- **Filters** — by direction and message type

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/messages` | Query logged messages |
| `GET /api/stats` | Aggregate statistics |
| `GET /api/tools/analytics` | Tool usage analytics |
| `GET /events` | SSE stream (real-time) |

## Architecture

```
Host (Claude / Cursor)
    │ stdin/stdout
    ▼
 ContextGate
    ├─ Interceptor Chain
    │   ├─ PolicyInterceptor        → deny / require_approval / audit
    │   ├─ ScrubberInterceptor      → redact PII in responses
    │   ├─ ApprovalInterceptor      → gate operations behind human review
    │   ├─ ToolAnalyticsInterceptor → track + prune tools
    │   └─ LoggingInterceptor       → persist to SQLite + publish to EventBus
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
contextgate [flags] -- <command>    Wrap an MCP server
contextgate setup                   Interactive setup wizard
contextgate wrap <name> -- <cmd>    Register wrapped server in Claude Code
contextgate version                 Print version
contextgate help                    Show help
```

### Flags

**General:**

| Flag | Default | Description |
|------|---------|-------------|
| `-dashboard` | `:9000` | Dashboard address (`""` to disable) |
| `-db` | `~/.contextgate/contextgate.db` | SQLite database path |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-no-browser` | `false` | Don't auto-open dashboard |

**Security:**

| Flag | Default | Description |
|------|---------|-------------|
| `-policy` | | Path to policy YAML file |
| `-scrub-pii` | `false` | Redact PII from server responses |
| `-approval-timeout` | `60s` | Timeout for approval requests |

**Pruning:**

| Flag | Default | Description |
|------|---------|-------------|
| `-prune-unused` | `0` | Remove tools unused in last N sessions |
| `-prune-keep-top` | `0` | Keep only top K most-used tools |
| `-prune-keep` | | Tools that should never be pruned (comma-separated) |

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
