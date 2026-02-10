package proxy

import "context"

// Interceptor processes an intercepted MCP message and decides whether
// to forward, modify, or block it.
//
// Return semantics:
//   - (modifiedBytes, nil): forward the (possibly modified) message
//   - (nil, nil): drop the message silently
//   - (nil, err): block the message and send a JSON-RPC error back
type Interceptor interface {
	Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error)
}

// InterceptorFunc is a convenience adapter for using a function as an Interceptor.
type InterceptorFunc func(ctx context.Context, msg *InterceptedMessage) ([]byte, error)

func (f InterceptorFunc) Intercept(ctx context.Context, msg *InterceptedMessage) ([]byte, error) {
	return f(ctx, msg)
}

// InterceptorChain runs interceptors in order. Processing stops on the
// first interceptor that blocks or drops a message.
type InterceptorChain struct {
	interceptors []Interceptor
}

func NewInterceptorChain(interceptors ...Interceptor) *InterceptorChain {
	return &InterceptorChain{interceptors: interceptors}
}

// Process runs the message through all interceptors. The raw bytes may
// be modified by each interceptor in sequence.
func (c *InterceptorChain) Process(ctx context.Context, msg *InterceptedMessage) ([]byte, error) {
	raw := msg.RawBytes
	for _, i := range c.interceptors {
		// Update raw bytes for next interceptor (in case previous one modified them)
		msg.RawBytes = raw
		modified, err := i.Intercept(ctx, msg)
		if err != nil {
			return nil, err
		}
		if modified == nil {
			return nil, nil // dropped
		}
		raw = modified
	}
	return raw, nil
}
