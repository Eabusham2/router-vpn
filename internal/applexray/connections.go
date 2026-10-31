package applexray

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Connections owns pending dials and published dispatcher connections. Context
// AfterFunc callbacks alone cannot provide a synchronous shutdown boundary.
// The zero value is ready to use; a closed set cannot be reused for a new tunnel.
type Connections struct {
	mu       sync.Mutex
	requests map[*Request]io.Closer
	closed   bool
	once     sync.Once
	closeErr error
}

// Request retains the caller's values/deadline while allowing the native owner
// to cancel a pending dispatch synchronously. Release unregisters a request;
// the actual transport calls it only after its own teardown has completed.
type Request struct {
	Context context.Context
	owner   *Connections
	cancel  context.CancelFunc
	// Immutable once the request is registered. A dial caller owns only the
	// pending result; its callback is stopped at successful publication.
	dialParent context.Context
	stopDial   func() bool
}

func (s *Connections) Begin(parent context.Context) (*Request, error) {
	return s.begin(parent, false)
}

// BeginDial preserves caller values and enforces cancellation/deadlines until
// publication. After DialContext/ListenPacket returns, the native owner and the
// returned connection own its lifetime, as required by net.Dialer semantics.
// DNS pools legitimately cancel a completed dial before writing their query.
// This does not detach an ordinary Begin request or the native owner's Close.
func (s *Connections) BeginDial(parent context.Context) (*Request, error) {
	return s.begin(parent, true)
}

func (s *Connections) begin(parent context.Context, dial bool) (*Request, error) {
	if parent == nil {
		return nil, errors.New("native Xray request has no context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || parent.Err() != nil || dial && !dialCallerCurrent(parent) {
		return nil, net.ErrClosed
	}
	lifetime := parent
	if dial {
		lifetime = context.WithoutCancel(parent)
	}
	ctx, cancel := context.WithCancel(lifetime)
	r := &Request{Context: ctx, owner: s, cancel: cancel}
	if dial {
		r.dialParent = parent
		// The callback only cancels this already-constructed context. It never
		// needs the owner lock or a not-yet-published cancellation handle.
		r.stopDial = context.AfterFunc(parent, cancel)
	}
	if s.requests == nil {
		s.requests = make(map[*Request]io.Closer)
	}
	s.requests[r] = nil
	return r, nil
}

func dialCallerCurrent(parent context.Context) bool {
	if parent.Err() != nil {
		return false
	}
	deadline, bounded := parent.Deadline()
	return !bounded || time.Now().Before(deadline)
}

func (r *Request) Cancel() {
	if r.stopDial != nil {
		r.stopDial()
	}
	r.cancel()
}

// Publish adopts the complete deadline/packet wrapper, not just its physical
// socket. A dispatch that finishes after Close is torn down instead of escaping
// into the replacement session. Call exactly once for a successful request.
func (r *Request) Publish(conn io.Closer) error {
	if conn == nil {
		r.Release()
		return errors.New("native Xray dispatch returned no connection")
	}
	s := r.owner
	s.mu.Lock()
	previous, pending := s.requests[r]
	if s.closed || !pending || r.Context.Err() != nil {
		s.mu.Unlock()
		_ = conn.Close()
		r.Release()
		return net.ErrClosed
	}
	if previous != nil {
		s.mu.Unlock()
		_ = conn.Close()
		return errors.New("native Xray request already published")
	}
	if r.stopDial != nil {
		stopped := r.stopDial()
		// A callback already running, or a caller cancelled before this
		// handover, cannot publish even if cancellation has not been scheduled
		// onto the request yet. Owner.Close shares this publication lock.
		if !stopped || !dialCallerCurrent(r.dialParent) {
			s.mu.Unlock()
			_ = conn.Close()
			r.Release()
			return net.ErrClosed
		}
	}
	s.requests[r] = conn
	s.mu.Unlock()
	return nil
}

func (r *Request) Release() {
	r.Cancel()
	r.owner.mu.Lock()
	delete(r.owner.requests, r)
	r.owner.mu.Unlock()
}

func (s *Connections) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		all := s.requests
		s.requests = nil
		s.mu.Unlock()
		// Invalidate every pending and published request first. No dependence on
		// callback scheduling, and no owner lock held while interrupting I/O.
		for request := range all {
			request.Cancel()
		}
		for _, conn := range all {
			if conn != nil {
				s.closeErr = errors.Join(s.closeErr, conn.Close())
			}
		}
	})
	return s.closeErr
}
