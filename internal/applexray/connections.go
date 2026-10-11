package applexray

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
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
}

func (s *Connections) Begin(parent context.Context) (*Request, error) {
	if parent == nil {
		return nil, errors.New("native Xray request has no context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || parent.Err() != nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(parent)
	r := &Request{Context: ctx, owner: s, cancel: cancel}
	if s.requests == nil {
		s.requests = make(map[*Request]io.Closer)
	}
	s.requests[r] = nil
	return r, nil
}

func (r *Request) Cancel() { r.cancel() }

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
	s.requests[r] = conn
	s.mu.Unlock()
	return nil
}

func (r *Request) Release() {
	r.cancel()
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
			request.cancel()
		}
		for _, conn := range all {
			if conn != nil {
				s.closeErr = errors.Join(s.closeErr, conn.Close())
			}
		}
	})
	return s.closeErr
}
