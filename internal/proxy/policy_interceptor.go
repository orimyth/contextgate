package proxy

import (
	"context"
	"fmt"

	"github.com/contextgate/contextgate/internal/policy"
)

// Metadata keys for inter-interceptor communication.
const (
	MetaKeyPolicyAction = "policy_action"
	MetaKeyPolicyRule   = "policy_rule"
	MetaKeyMatchedRules = "matched_rules"
	MetaKeyAudit        = "audit"
	MetaKeyScrubCount   = "scrub_count"
)

// PolicyInterceptor evaluates policy rules against messages.
// Deny actions block immediately. RequireApproval and Audit
// annotate the message metadata for downstream interceptors.
type PolicyInterceptor struct {
	engine *policy.Engine
}

func NewPolicyInterceptor(engine *policy.Engine) *PolicyInterceptor {
	return &PolicyInterceptor{engine: engine}
}

func (p *PolicyInterceptor) Intercept(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
	if msg.ParseErr != nil {
		return msg.RawBytes, nil
	}

	toolName := ""
	if msg.Parsed.Method == "tools/call" {
		toolName = policy.ExtractToolName(msg.Parsed.Params)
	}

	result := p.engine.Evaluate(
		string(msg.Direction),
		msg.Parsed.Method,
		toolName,
		string(msg.RawBytes),
	)

	if len(result.MatchedRules) == 0 {
		return msg.RawBytes, nil
	}

	if msg.Metadata == nil {
		msg.Metadata = make(map[string]any)
	}
	msg.Metadata[MetaKeyMatchedRules] = result.MatchedRules

	switch result.Action {
	case policy.ActionDeny:
		msg.Metadata[MetaKeyPolicyAction] = string(policy.ActionDeny)
		msg.Metadata[MetaKeyPolicyRule] = result.DenyRule
		return nil, fmt.Errorf("blocked by policy rule %q", result.DenyRule)

	case policy.ActionRequireApproval:
		msg.Metadata[MetaKeyPolicyAction] = string(policy.ActionRequireApproval)
		msg.Metadata[MetaKeyPolicyRule] = result.ApprovalRule
		return msg.RawBytes, nil

	case policy.ActionAudit:
		msg.Metadata[MetaKeyPolicyAction] = string(policy.ActionAudit)
		msg.Metadata[MetaKeyAudit] = true
		return msg.RawBytes, nil
	}

	return msg.RawBytes, nil
}
