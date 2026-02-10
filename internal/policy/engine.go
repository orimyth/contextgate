package policy

// MatchResult holds the outcome of evaluating all rules against a message.
type MatchResult struct {
	Action       Action
	MatchedRules []string
	DenyRule     string
	ApprovalRule string
}

// Engine evaluates rules against messages.
type Engine struct {
	config *Config
}

// NewEngine creates a policy evaluation engine.
func NewEngine(cfg *Config) *Engine {
	return &Engine{config: cfg}
}

// Evaluate checks all rules against the given message attributes.
// Priority: deny > require_approval > audit.
func (e *Engine) Evaluate(direction, method, toolName, payload string) MatchResult {
	var result MatchResult

	for _, rule := range e.config.Rules {
		if !ruleMatches(&rule, direction, method, toolName, payload) {
			continue
		}

		result.MatchedRules = append(result.MatchedRules, rule.Name)

		switch rule.Action {
		case ActionDeny:
			if result.Action != ActionDeny {
				result.Action = ActionDeny
				result.DenyRule = rule.Name
			}
		case ActionRequireApproval:
			if result.Action != ActionDeny {
				result.Action = ActionRequireApproval
				result.ApprovalRule = rule.Name
			}
		case ActionAudit:
			if result.Action == "" {
				result.Action = ActionAudit
			}
		}
	}

	return result
}

func ruleMatches(rule *Rule, direction, method, toolName, payload string) bool {
	if rule.Direction != "" && rule.Direction != direction {
		return false
	}

	if len(rule.Methods) > 0 && !contains(rule.Methods, method) {
		return false
	}

	if len(rule.Tools) > 0 {
		if toolName == "" || !contains(rule.Tools, toolName) {
			return false
		}
	}

	// All patterns must match (AND semantics)
	for _, re := range rule.compiledPatterns {
		if !re.MatchString(payload) {
			return false
		}
	}

	return true
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
