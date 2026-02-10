package eventbus

import (
	"testing"
	"time"

	"github.com/contextgate/contextgate/internal/store"
)

func TestSubscribeAndPublish(t *testing.T) {
	eb := New(10)

	ch, unsub := eb.Subscribe("test-1")
	defer unsub()

	entry := &store.LogEntry{
		Method:    "tools/call",
		Direction: "host_to_server",
	}

	eb.Publish(entry)

	select {
	case received := <-ch:
		if received.Method != "tools/call" {
			t.Errorf("method = %q, want %q", received.Method, "tools/call")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published entry")
	}
}

func TestFanOut(t *testing.T) {
	eb := New(10)

	ch1, unsub1 := eb.Subscribe("sub-1")
	defer unsub1()
	ch2, unsub2 := eb.Subscribe("sub-2")
	defer unsub2()

	entry := &store.LogEntry{Method: "test"}
	eb.Publish(entry)

	for _, ch := range []<-chan *store.LogEntry{ch1, ch2} {
		select {
		case received := <-ch:
			if received.Method != "test" {
				t.Errorf("method = %q, want %q", received.Method, "test")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for entry")
		}
	}
}

func TestUnsubscribe(t *testing.T) {
	eb := New(10)

	_, unsub := eb.Subscribe("sub-1")
	unsub()

	if eb.SubscriberCount() != 0 {
		t.Errorf("subscriber count = %d, want 0", eb.SubscriberCount())
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	eb := New(1) // buffer of 1

	ch, unsub := eb.Subscribe("slow")
	defer unsub()

	// Fill the buffer
	eb.Publish(&store.LogEntry{Method: "msg-1"})
	// This should not block even though buffer is full
	eb.Publish(&store.LogEntry{Method: "msg-2"})

	select {
	case received := <-ch:
		if received.Method != "msg-1" {
			t.Errorf("method = %q, want %q", received.Method, "msg-1")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}
