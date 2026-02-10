package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Action represents what to do when a rule matches.
type Action string

const (
	ActionDeny            Action = "deny"
	ActionRequireApproval Action = "require_approval"
	ActionAudit           Action = "audit"
)

// Rule represents a single policy rule.
type Rule struct {
	Name      string   `yaml:"name"`
	Action    Action   `yaml:"action"`
	Methods   []string `yaml:"methods"`
	Tools     []string `yaml:"tools"`
	Direction string   `yaml:"direction,omitempty"`
	Patterns  []string `yaml:"patterns"`

	compiledPatterns []*regexp.Regexp
}

// Config is the top-level YAML structure.
type Config struct {
	Version  string         `yaml:"version"`
	Rules    []Rule         `yaml:"rules"`
	Scrubber ScrubberConfig `yaml:"scrubber"`
}

// ScrubberConfig controls PII scrubbing behavior.
type ScrubberConfig struct {
	Enabled        bool            `yaml:"enabled"`
	CustomPatterns []CustomPattern `yaml:"custom_patterns"`
}

// CustomPattern allows users to define additional scrubbing patterns.
type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Label   string `yaml:"label"`
}

// Load reads and parses a policy YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}

	if err := cfg.Compile(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Compile pre-compiles all regex patterns in all rules.
func (c *Config) Compile() error {
	for i := range c.Rules {
		r := &c.Rules[i]
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("rule %q pattern %q: %w", r.Name, p, err)
			}
			r.compiledPatterns = append(r.compiledPatterns, re)
		}
	}
	return nil
}

// ExtractToolName extracts the tool name from a tools/call JSON-RPC params.
// MCP tools/call has params: {"name": "tool_name", "arguments": {...}}
func ExtractToolName(params json.RawMessage) string {
	if params == nil {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
