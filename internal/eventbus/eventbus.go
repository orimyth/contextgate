package eventbus

import (
	"sync"

	"github.com/contextgate/contextgate/internal/store"
)

const defaultBufSize = 256

// EventBus implements fan-out pub/sub for log entries.
// Each subscriber gets a buffered channel. If a subscriber
// is slow, entries are dropped for that subscriber (the
// dashboard can query the store for missed entries).
type EventBus struct {
	mu           sync.RWMutex
	subscribers  map[string]chan *store.LogEntry
	approvalSubs map[string]chan *store.ApprovalEvent
	bufSize      int
}

func New(bufSize int) *EventBus {
	if bufSize <= 0 {
		bufSize = defaultBufSize
	}
	return &EventBus{
		subscribers:  make(map[string]chan *store.LogEntry),
		approvalSubs: make(map[string]chan *store.ApprovalEvent),
		bufSize:      bufSize,
	}
}

// Subscribe creates a new subscription. Returns the channel and
// an unsubscribe function that must be called when done.
func (eb *EventBus) Subscribe(id string) (<-chan *store.LogEntry, func()) {
	ch := make(chan *store.LogEntry, eb.bufSize)

	eb.mu.Lock()
	eb.subscribers[id] = ch
	eb.mu.Unlock()

	unsub := func() {
		eb.mu.Lock()
		delete(eb.subscribers, id)
		close(ch)
		eb.mu.Unlock()
	}
	return ch, unsub
}

// Publish sends a log entry to all subscribers. Non-blocking:
// slow subscribers will miss entries.
func (eb *EventBus) Publish(entry *store.LogEntry) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, ch := range eb.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

// SubscribeApprovals creates a subscription for approval events.
func (eb *EventBus) SubscribeApprovals(id string) (<-chan *store.ApprovalEvent, func()) {
	ch := make(chan *store.ApprovalEvent, eb.bufSize)

	eb.mu.Lock()
	eb.approvalSubs[id] = ch
	eb.mu.Unlock()

	unsub := func() {
		eb.mu.Lock()
		delete(eb.approvalSubs, id)
		close(ch)
		eb.mu.Unlock()
	}
	return ch, unsub
}

// PublishApproval sends an approval event to all approval subscribers.
func (eb *EventBus) PublishApproval(event *store.ApprovalEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, ch := range eb.approvalSubs {
		select {
		case ch <- event:
		default:
		}
	}
}

// SubscriberCount returns the number of active subscribers.
func (eb *EventBus) SubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers)
}
