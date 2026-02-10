package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/contextgate/contextgate/internal/policy"
)

// ApprovalDecision represents the human's decision.
type ApprovalDecision int

const (
	DecisionPending  ApprovalDecision = iota
	DecisionApproved
	DecisionDenied
	DecisionTimeout
)

func (d ApprovalDecision) String() string {
	switch d {
	case DecisionApproved:
		return "approved"
	case DecisionDenied:
		return "denied"
	case DecisionTimeout:
		return "timeout"
	default:
		return "pending"
	}
}

// ApprovalRequest represents a pending approval request.
type ApprovalRequest struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	Direction string    `json:"direction"`
	Method    string    `json:"method"`
	ToolName  string    `json:"tool_name"`
	RuleName  string    `json:"rule_name"`
	Payload   string    `json:"payload"`
	Decision  string    `json:"decision"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`

	done chan ApprovalDecision
}

// ApprovalManager coordinates approval requests between
// the interceptor (which blocks) and the dashboard (which resolves).
type ApprovalManager struct {
	mu      sync.RWMutex
	pending map[string]*ApprovalRequest
	timeout time.Duration
	nextID  int

	// OnRequest is called when a new approval is submitted.
	OnRequest func(req *ApprovalRequest)
}

func NewApprovalManager(timeout time.Duration) *ApprovalManager {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &ApprovalManager{
		pending: make(map[string]*ApprovalRequest),
		timeout: timeout,
	}
}

// Submit creates a new approval request and returns a channel that will
// receive the decision. The caller blocks on this channel.
func (am *ApprovalManager) Submit(req *ApprovalRequest) <-chan ApprovalDecision {
	am.mu.Lock()
	am.nextID++
	req.ID = fmt.Sprintf("apr-%d", am.nextID)
	req.Decision = "pending"
	req.done = make(chan ApprovalDecision, 1)
	am.pending[req.ID] = req
	am.mu.Unlock()

	if am.OnRequest != nil {
		am.OnRequest(req)
	}

	// Timeout goroutine
	go func() {
		timer := time.NewTimer(am.timeout)
		defer timer.Stop()
		<-timer.C

		am.mu.Lock()
		if _, exists := am.pending[req.ID]; exists {
			now := time.Now()
			req.Decision = DecisionTimeout.String()
			req.DecidedAt = &now
			delete(am.pending, req.ID)
			select {
			case req.done <- DecisionTimeout:
			default:
			}
		}
		am.mu.Unlock()
	}()

	return req.done
}

// Resolve marks a pending request as approved or denied.
func (am *ApprovalManager) Resolve(id string, approved bool) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	req, exists := am.pending[id]
	if !exists {
		return fmt.Errorf("approval request %q not found or already resolved", id)
	}

	now := time.Now()
	req.DecidedAt = &now
	if approved {
		req.Decision = DecisionApproved.String()
	} else {
		req.Decision = DecisionDenied.String()
	}

	delete(am.pending, id)

	decision := DecisionDenied
	if approved {
		decision = DecisionApproved
	}
	select {
	case req.done <- decision:
	default:
	}

	return nil
}

// Pending returns all pending approval requests.
func (am *ApprovalManager) Pending() []*ApprovalRequest {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]*ApprovalRequest, 0, len(am.pending))
	for _, r := range am.pending {
		result = append(result, r)
	}
	return result
}

// PendingCount returns the number of pending requests.
func (am *ApprovalManager) PendingCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.pending)
}

// ApprovalInterceptor blocks messages that require human approval.
type ApprovalInterceptor struct {
	manager *ApprovalManager
}

func NewApprovalInterceptor(manager *ApprovalManager) *ApprovalInterceptor {
	return &ApprovalInterceptor{manager: manager}
}

func (a *ApprovalInterceptor) Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error) {
	if msg.Metadata == nil {
		return msg.RawBytes, nil
	}

	action, _ := msg.Metadata[MetaKeyPolicyAction].(string)
	if action != string(policy.ActionRequireApproval) {
		return msg.RawBytes, nil
	}

	ruleName, _ := msg.Metadata[MetaKeyPolicyRule].(string)
	toolName := ""
	if msg.Parsed.Method == "tools/call" {
		toolName = policy.ExtractToolName(msg.Parsed.Params)
	}

	req := &ApprovalRequest{
		Timestamp: msg.Timestamp,
		SessionID: msg.SessionID,
		Direction: string(msg.Direction),
		Method:    msg.Parsed.Method,
		ToolName:  toolName,
		RuleName:  ruleName,
		Payload:   string(msg.RawBytes),
	}

	ch := a.manager.Submit(req)

	select {
	case decision := <-ch:
		switch decision {
		case DecisionApproved:
			return msg.RawBytes, nil
		case DecisionDenied:
			return nil, fmt.Errorf("denied by human review (rule: %s)", ruleName)
		case DecisionTimeout:
			return nil, fmt.Errorf("approval timed out (rule: %s)", ruleName)
		default:
			return nil, fmt.Errorf("unexpected approval decision")
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled while awaiting approval")
	}
}
