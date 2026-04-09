package approval

import (
	"sync"
	"time"
)

// Request represents a pending approval request.
type Request struct {
	Domain  string
	Dest    string
	Time    time.Time
	result  chan bool // true = allow, false = deny
	decided bool
}

// Queue manages pending approval requests.
// TCP proxy goroutines block on a Request until it's resolved by watch.
type Queue struct {
	mu       sync.Mutex
	pending  map[string]*Request // keyed by domain
	order    []string            // insertion order for queue display
	onChange func()              // called when queue state changes
}

// NewQueue creates an empty approval queue.
func NewQueue() *Queue {
	return &Queue{
		pending: make(map[string]*Request),
	}
}

// OnChange sets a callback that fires when the queue state changes.
func (q *Queue) OnChange(fn func()) {
	q.mu.Lock()
	q.onChange = fn
	q.mu.Unlock()
}

// Submit adds a request to the queue and blocks until resolved or timeout.
// If a request for the same domain is already pending, joins the existing wait.
// Returns true for allow, false for deny.
func (q *Queue) Submit(domain, dest string, timeout time.Duration) bool {
	q.mu.Lock()
	req, exists := q.pending[domain]
	if exists && req.decided {
		// Already decided (possibly from a previous timeout) — reuse result
		// The result channel was already sent to, so we can't recv again.
		// But decided requests shouldn't be in pending. This is defensive.
		q.mu.Unlock()
		return false
	}
	if !exists {
		req = &Request{
			Domain: domain,
			Dest:   dest,
			Time:   time.Now(),
			result: make(chan bool, 1), // buffered so Resolve doesn't block
		}
		q.pending[domain] = req
		q.order = append(q.order, domain)
		q.mu.Unlock()
		q.notifyChange()
	} else {
		q.mu.Unlock()
	}

	// Block until resolved or timeout
	select {
	case allowed := <-req.result:
		// Re-send so other waiters on the same domain also get the result
		select {
		case req.result <- allowed:
		default:
		}
		return allowed
	case <-time.After(timeout):
		return false // timeout = deny, but request stays in queue
	}
}

// Resolve resolves a pending request by domain.
func (q *Queue) Resolve(domain string, allow bool) bool {
	q.mu.Lock()
	req, exists := q.pending[domain]
	if !exists {
		q.mu.Unlock()
		return false
	}
	req.decided = true
	delete(q.pending, domain)
	// Remove from order
	for i, d := range q.order {
		if d == domain {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
	q.mu.Unlock()

	// Send result (buffered channel, won't block)
	select {
	case req.result <- allow:
	default:
	}

	q.notifyChange()
	return true
}

// Pending returns the current pending requests in insertion order.
func (q *Queue) Pending() []Request {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]Request, 0, len(q.order))
	for _, domain := range q.order {
		if req, ok := q.pending[domain]; ok {
			result = append(result, Request{
				Domain: req.Domain,
				Dest:   req.Dest,
				Time:   req.Time,
			})
		}
	}
	return result
}

// Size returns the number of pending requests.
func (q *Queue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

func (q *Queue) notifyChange() {
	q.mu.Lock()
	fn := q.onChange
	q.mu.Unlock()
	if fn != nil {
		fn()
	}
}
