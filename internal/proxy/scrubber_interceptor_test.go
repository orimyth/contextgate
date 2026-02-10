package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/policy"
)

func newTestScrubber(enabled bool) *ScrubberInterceptor {
	return NewScrubberInterceptor(enabled, nil)
}

func scrubMsg(t *testing.T, s *ScrubberInterceptor, dir Direction, payload string) (string, *InterceptedMessage) {
	t.Helper()
	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		Direction: dir,
		RawBytes:  []byte(payload),
	}
	result, err := s.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return string(result), msg
}

func TestScrubber_APIKey_SK(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"key is sk-abcdefghijklmnopqrstuvwxyz1234567890"}`)
	if strings.Contains(result, "sk-") {
		t.Fatalf("expected API key to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:api_key]") {
		t.Fatalf("expected [REDACTED:api_key], got: %s", result)
	}
}

func TestScrubber_APIKey_GHP(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"token ghp_abcdefghijklmnopqrstuvwxyz1234567890"}`)
	if strings.Contains(result, "ghp_") {
		t.Fatalf("expected GitHub PAT to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:api_key]") {
		t.Fatalf("expected [REDACTED:api_key], got: %s", result)
	}
}

func TestScrubber_AWS(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"aws key AKIAIOSFODNN7EXAMPLE"}`)
	if strings.Contains(result, "AKIA") {
		t.Fatalf("expected AWS key to be scrubbed, got: %s", result)
	}
}

func TestScrubber_Email(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"contact user@example.com for info"}`)
	if strings.Contains(result, "user@example.com") {
		t.Fatalf("expected email to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:email]") {
		t.Fatalf("expected [REDACTED:email], got: %s", result)
	}
}

func TestScrubber_SSN(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"ssn 123-45-6789"}`)
	if strings.Contains(result, "123-45-6789") {
		t.Fatalf("expected SSN to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:ssn]") {
		t.Fatalf("expected [REDACTED:ssn], got: %s", result)
	}
}

func TestScrubber_IPAddress(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"server at 192.168.1.100"}`)
	if strings.Contains(result, "192.168.1.100") {
		t.Fatalf("expected IP to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:ip_address]") {
		t.Fatalf("expected [REDACTED:ip_address], got: %s", result)
	}
}

func TestScrubber_JSONKeysPreserved(t *testing.T) {
	s := newTestScrubber(true)
	// The key "email" should NOT be scrubbed, only the value
	result, _ := scrubMsg(t, s, DirServerToHost, `{"email":"test@example.com"}`)
	if !strings.Contains(result, `"email"`) {
		t.Fatalf("expected JSON key 'email' to be preserved, got: %s", result)
	}
	if strings.Contains(result, "test@example.com") {
		t.Fatalf("expected email value to be scrubbed, got: %s", result)
	}
}

func TestScrubber_NestedJSON(t *testing.T) {
	s := newTestScrubber(true)
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":{"data":{"secret":"sk-abcdefghijklmnopqrstuvwxyz1234567890"}}}`)
	if strings.Contains(result, "sk-") {
		t.Fatalf("expected nested API key to be scrubbed, got: %s", result)
	}
}

func TestScrubber_MultiplePII(t *testing.T) {
	s := newTestScrubber(true)
	result, msg := scrubMsg(t, s, DirServerToHost, `{"result":"key sk-aaaabbbbccccddddeeeefffff and email test@test.com"}`)
	if strings.Contains(result, "sk-") || strings.Contains(result, "test@test.com") {
		t.Fatalf("expected both PII items scrubbed, got: %s", result)
	}
	count, _ := msg.Metadata[MetaKeyScrubCount].(int)
	if count < 2 {
		t.Fatalf("expected scrub count >= 2, got %d", count)
	}
}

func TestScrubber_HostToServer_Ignored(t *testing.T) {
	s := newTestScrubber(true)
	payload := `{"params":{"key":"sk-abcdefghijklmnopqrstuvwxyz1234567890"}}`
	result, _ := scrubMsg(t, s, DirHostToServer, payload)
	if result != payload {
		t.Fatalf("expected host_to_server to pass through unchanged, got: %s", result)
	}
}

func TestScrubber_Disabled(t *testing.T) {
	s := newTestScrubber(false)
	payload := `{"result":"sk-abcdefghijklmnopqrstuvwxyz1234567890"}`
	result, _ := scrubMsg(t, s, DirServerToHost, payload)
	if result != payload {
		t.Fatalf("expected disabled scrubber to pass through, got: %s", result)
	}
}

func TestScrubber_CustomPatterns(t *testing.T) {
	s := NewScrubberInterceptor(true, []policy.CustomPattern{
		{Name: "custom-token", Pattern: `tok_[a-zA-Z0-9]{16}`, Label: "custom_token"},
	})
	result, _ := scrubMsg(t, s, DirServerToHost, `{"result":"token tok_abcdef1234567890"}`)
	if strings.Contains(result, "tok_") {
		t.Fatalf("expected custom token to be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, "[REDACTED:custom_token]") {
		t.Fatalf("expected [REDACTED:custom_token], got: %s", result)
	}
}

func TestScrubber_TotalCount(t *testing.T) {
	s := newTestScrubber(true)
	scrubMsg(t, s, DirServerToHost, `{"result":"sk-abcdefghijklmnopqrstuvwxyz1234567890"}`)
	scrubMsg(t, s, DirServerToHost, `{"result":"test@example.com"}`)

	if s.TotalScrubbed() < 2 {
		t.Fatalf("expected total scrubbed >= 2, got %d", s.TotalScrubbed())
	}
}
