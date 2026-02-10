package proxy

import (
	"context"
	"encoding/json"
	"regexp"
	"sync/atomic"

	"github.com/contextgate/contextgate/internal/policy"
)

// piiPattern represents a named PII detection pattern.
type piiPattern struct {
	Name  string
	Regex *regexp.Regexp
	Label string // replacement label, e.g. "api_key" → [REDACTED:api_key]
}

// default PII patterns
var defaultPIIPatterns = []piiPattern{
	{Name: "openai_key", Regex: regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`), Label: "api_key"},
	{Name: "github_pat", Regex: regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`), Label: "api_key"},
	{Name: "github_oauth", Regex: regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`), Label: "api_key"},
	{Name: "github_user", Regex: regexp.MustCompile(`ghu_[A-Za-z0-9]{36,}`), Label: "api_key"},
	{Name: "github_server", Regex: regexp.MustCompile(`ghs_[A-Za-z0-9]{36,}`), Label: "api_key"},
	{Name: "github_refresh", Regex: regexp.MustCompile(`ghr_[A-Za-z0-9]{36,}`), Label: "api_key"},
	{Name: "aws_key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "api_key"},
	{Name: "email", Regex: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), Label: "email"},
	{Name: "ssn", Regex: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Label: "ssn"},
	{Name: "ipv4", Regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), Label: "ip_address"},
}

// ScrubberInterceptor redacts PII from server-to-host messages.
type ScrubberInterceptor struct {
	patterns      []piiPattern
	enabled       bool
	totalScrubbed atomic.Int64
}

// NewScrubberInterceptor creates a scrubber with default + custom patterns.
func NewScrubberInterceptor(enabled bool, customPatterns []policy.CustomPattern) *ScrubberInterceptor {
	s := &ScrubberInterceptor{
		patterns: append([]piiPattern{}, defaultPIIPatterns...),
		enabled:  enabled,
	}

	for _, cp := range customPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			continue
		}
		s.patterns = append(s.patterns, piiPattern{
			Name:  cp.Name,
			Regex: re,
			Label: cp.Label,
		})
	}

	return s
}

func (s *ScrubberInterceptor) Intercept(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
	if !s.enabled {
		return msg.RawBytes, nil
	}

	// Only scrub server→host traffic
	if msg.Direction != DirServerToHost {
		return msg.RawBytes, nil
	}

	scrubbed, count := s.scrubJSON(msg.RawBytes)

	if count > 0 {
		s.totalScrubbed.Add(int64(count))
		if msg.Metadata == nil {
			msg.Metadata = make(map[string]any)
		}
		msg.Metadata[MetaKeyScrubCount] = count
	}

	return scrubbed, nil
}

// scrubJSON parses JSON, walks string values, applies PII regexes,
// and re-serializes. JSON structure keys are not modified.
func (s *ScrubberInterceptor) scrubJSON(raw []byte) ([]byte, int) {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		result, count := s.scrubString(string(raw))
		return []byte(result), count
	}

	count := 0
	scrubbed := s.walkAndScrub(parsed, &count)

	result, err := json.Marshal(scrubbed)
	if err != nil {
		return raw, 0
	}
	return result, count
}

// walkAndScrub recursively walks a parsed JSON value and scrubs string values.
func (s *ScrubberInterceptor) walkAndScrub(v any, count *int) any {
	switch val := v.(type) {
	case string:
		scrubbed, c := s.scrubString(val)
		*count += c
		return scrubbed
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, v := range val {
			result[k] = s.walkAndScrub(v, count)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, v := range val {
			result[i] = s.walkAndScrub(v, count)
		}
		return result
	default:
		return v
	}
}

// scrubString applies all PII patterns to a string.
func (s *ScrubberInterceptor) scrubString(input string) (string, int) {
	count := 0
	result := input
	for _, p := range s.patterns {
		matches := p.Regex.FindAllStringIndex(result, -1)
		if len(matches) > 0 {
			count += len(matches)
			replacement := "[REDACTED:" + p.Label + "]"
			result = p.Regex.ReplaceAllString(result, replacement)
		}
	}
	return result, count
}

// TotalScrubbed returns the total number of PII items scrubbed.
func (s *ScrubberInterceptor) TotalScrubbed() int64 {
	return s.totalScrubbed.Load()
}
