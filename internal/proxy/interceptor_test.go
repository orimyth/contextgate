package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInterceptorChain_PassThrough(t *testing.T) {
	passthrough := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		return msg.RawBytes, nil
	})

	chain := NewInterceptorChain(passthrough)
	msg := &InterceptedMessage{
		Timestamp: time.Now(),
		RawBytes:  []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`),
	}

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(msg.RawBytes) {
		t.Errorf("result = %q, want %q", result, msg.RawBytes)
	}
}

func TestInterceptorChain_Modify(t *testing.T) {
	modifier := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		return []byte(`{"modified":true}`), nil
	})

	chain := NewInterceptorChain(modifier)
	msg := &InterceptedMessage{
		RawBytes: []byte(`{"original":true}`),
	}

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != `{"modified":true}` {
		t.Errorf("result = %q, want modified", result)
	}
}

func TestInterceptorChain_Block(t *testing.T) {
	blocker := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		return nil, errors.New("blocked")
	})

	chain := NewInterceptorChain(blocker)
	msg := &InterceptedMessage{
		RawBytes: []byte(`{"test":true}`),
	}

	_, err := chain.Process(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "blocked" {
		t.Errorf("error = %q, want %q", err.Error(), "blocked")
	}
}

func TestInterceptorChain_Drop(t *testing.T) {
	dropper := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		return nil, nil
	})

	chain := NewInterceptorChain(dropper)
	msg := &InterceptedMessage{
		RawBytes: []byte(`{"test":true}`),
	}

	result, err := chain.Process(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("result = %q, want nil", result)
	}
}

func TestInterceptorChain_Order(t *testing.T) {
	var order []int

	first := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		order = append(order, 1)
		return msg.RawBytes, nil
	})
	second := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		order = append(order, 2)
		return msg.RawBytes, nil
	})
	third := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		order = append(order, 3)
		return msg.RawBytes, nil
	})

	chain := NewInterceptorChain(first, second, third)
	msg := &InterceptedMessage{RawBytes: []byte(`{}`)}

	chain.Process(context.Background(), msg)

	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Errorf("execution order = %v, want [1 2 3]", order)
	}
}

func TestInterceptorChain_BlockStopsChain(t *testing.T) {
	var reached bool

	blocker := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		return nil, errors.New("blocked")
	})
	after := InterceptorFunc(func(_ context.Context, msg *InterceptedMessage) ([]byte, error) {
		reached = true
		return msg.RawBytes, nil
	})

	chain := NewInterceptorChain(blocker, after)
	msg := &InterceptedMessage{RawBytes: []byte(`{}`)}

	chain.Process(context.Background(), msg)

	if reached {
		t.Error("interceptor after blocker should not have been reached")
	}
}
