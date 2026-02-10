package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1"
rules:
  - name: block-env
    action: deny
    methods: ["tools/call"]
    tools: ["write_file"]
    patterns:
      - '\.env'
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Name != "block-env" {
		t.Fatalf("expected rule name 'block-env', got %q", cfg.Rules[0].Name)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(`{{{invalid`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_InvalidRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1"
rules:
  - name: bad-regex
    action: deny
    patterns:
      - '[invalid'
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestEngine_DenyMatchesMethod(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "block-shell", Action: ActionDeny, Methods: []string{"tools/call"}, Tools: []string{"run_shell"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "run_shell", `{}`)
	if result.Action != ActionDeny {
		t.Fatalf("expected deny, got %q", result.Action)
	}
	if result.DenyRule != "block-shell" {
		t.Fatalf("expected deny rule 'block-shell', got %q", result.DenyRule)
	}
}

func TestEngine_DenyMatchesPattern(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "block-env", Action: ActionDeny, Methods: []string{"tools/call"}, Tools: []string{"write_file"}, Patterns: []string{`\.env`}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "write_file", `{"name":"write_file","arguments":{"path":"/app/.env"}}`)
	if result.Action != ActionDeny {
		t.Fatalf("expected deny, got %q", result.Action)
	}

	// Should not match without .env in payload
	result = e.Evaluate("host_to_server", "tools/call", "write_file", `{"name":"write_file","arguments":{"path":"/app/config.json"}}`)
	if result.Action == ActionDeny {
		t.Fatal("should not deny without .env in payload")
	}
}

func TestEngine_RequireApproval(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "approve-delete", Action: ActionRequireApproval, Methods: []string{"tools/call"}, Tools: []string{"delete_file"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "delete_file", `{}`)
	if result.Action != ActionRequireApproval {
		t.Fatalf("expected require_approval, got %q", result.Action)
	}
	if result.ApprovalRule != "approve-delete" {
		t.Fatalf("expected approval rule 'approve-delete', got %q", result.ApprovalRule)
	}
}

func TestEngine_Audit(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "audit-all", Action: ActionAudit, Methods: []string{"tools/call"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "read_file", `{}`)
	if result.Action != ActionAudit {
		t.Fatalf("expected audit, got %q", result.Action)
	}
}

func TestEngine_DenyTakesPrecedence(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "audit-all", Action: ActionAudit, Methods: []string{"tools/call"}},
			{Name: "approve-delete", Action: ActionRequireApproval, Methods: []string{"tools/call"}, Tools: []string{"delete_file"}},
			{Name: "block-delete", Action: ActionDeny, Methods: []string{"tools/call"}, Tools: []string{"delete_file"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "delete_file", `{}`)
	if result.Action != ActionDeny {
		t.Fatalf("expected deny to take precedence, got %q", result.Action)
	}
	if len(result.MatchedRules) != 3 {
		t.Fatalf("expected 3 matched rules, got %d", len(result.MatchedRules))
	}
}

func TestEngine_RequireApprovalOverAudit(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "audit-all", Action: ActionAudit, Methods: []string{"tools/call"}},
			{Name: "approve-delete", Action: ActionRequireApproval, Methods: []string{"tools/call"}, Tools: []string{"delete_file"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "delete_file", `{}`)
	if result.Action != ActionRequireApproval {
		t.Fatalf("expected require_approval over audit, got %q", result.Action)
	}
}

func TestEngine_DirectionFilter(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "server-only", Action: ActionAudit, Direction: "server_to_host", Methods: []string{"tools/call"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	// Should not match host_to_server
	result := e.Evaluate("host_to_server", "tools/call", "", `{}`)
	if result.Action != "" {
		t.Fatalf("expected no match for wrong direction, got %q", result.Action)
	}

	// Should match server_to_host
	result = e.Evaluate("server_to_host", "tools/call", "", `{}`)
	if result.Action != ActionAudit {
		t.Fatalf("expected audit for correct direction, got %q", result.Action)
	}
}

func TestEngine_NoMatch(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{Name: "block-shell", Action: ActionDeny, Methods: []string{"tools/call"}, Tools: []string{"run_shell"}},
		},
	}
	cfg.Compile()
	e := NewEngine(cfg)

	result := e.Evaluate("host_to_server", "tools/call", "read_file", `{}`)
	if result.Action != "" {
		t.Fatalf("expected no action, got %q", result.Action)
	}
	if len(result.MatchedRules) != 0 {
		t.Fatalf("expected 0 matched rules, got %d", len(result.MatchedRules))
	}
}

func TestExtractToolName(t *testing.T) {
	tests := []struct {
		name   string
		params json.RawMessage
		want   string
	}{
		{"valid", json.RawMessage(`{"name":"write_file","arguments":{}}`), "write_file"},
		{"no name", json.RawMessage(`{"arguments":{}}`), ""},
		{"nil params", nil, ""},
		{"invalid JSON", json.RawMessage(`{invalid`), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractToolName(tt.params)
			if got != tt.want {
				t.Fatalf("ExtractToolName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoad_ScrubberConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
version: "1"
rules: []
scrubber:
  enabled: true
  custom_patterns:
    - name: internal-token
      pattern: 'tok_[a-zA-Z0-9]{32}'
      label: internal_token
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Scrubber.Enabled {
		t.Fatal("expected scrubber enabled")
	}
	if len(cfg.Scrubber.CustomPatterns) != 1 {
		t.Fatalf("expected 1 custom pattern, got %d", len(cfg.Scrubber.CustomPatterns))
	}
	if cfg.Scrubber.CustomPatterns[0].Label != "internal_token" {
		t.Fatalf("expected label 'internal_token', got %q", cfg.Scrubber.CustomPatterns[0].Label)
	}
}
