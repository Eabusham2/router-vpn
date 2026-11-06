package mobilemultihop

import (
 "context"
 "errors"
 "net"
 "sync"
 "sync/atomic"
)

// Each fixed stop retains its entered HTTP worker, dials, stream I/O and
// original closes. A new request cannot replace an unjoined attempt.
type leaseStopIO struct {
	mu sync.Mutex
	ctx context.Context
	cancel context.CancelFunc
	retired atomic.Bool
	pending int
	connections map[*leaseStopConn]bool
	drained chan struct{}
	drainedOnce sync.Once
	changed chan struct{}
}
func newLeaseStopIO(parent context.Context) *leaseStopIO {
	ctx, cancel := context.WithCancel(parent)
	return &leaseStopIO{ctx:ctx, cancel:cancel,
		connections:make(map[*leaseStopConn]bool), drained:make(chan struct{}),changed:make(chan struct{},1)}
}
func (s *leaseStopIO) notify() {
	select { case s.changed <- struct{}{}: default: }
}
func (s *leaseStopIO) checkDrainedLocked() {
	if s.retired.Load() && s.pending == 0 && len(s.connections) == 0 {
		s.drainedOnce.Do(func(){close(s.drained)})
	}
	s.notify()
}
func (s *leaseStopIO) begin(parent context.Context) (context.Context, func(), error) {
	if parent == nil || parent.Err() != nil { return nil, nil, net.ErrClosed }
	s.mu.Lock()
	if s.retired.Load() || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	s.pending++
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.ctx, cancel)
	var once sync.Once
	finish := func() {
		once.Do(func() {
			stop()
			cancel()
			s.mu.Lock()
			s.pending--
			s.checkDrainedLocked()
			s.mu.Unlock()
		})
	}
	if s.retired.Load() || ctx.Err() != nil {
		finish()
		return nil, nil, net.ErrClosed
	}
	return ctx, finish, nil
}
func (s *leaseStopIO) beginIO() (func(), error) {
	s.mu.Lock()
	if s.retired.Load() || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.pending++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.pending--
		s.checkDrainedLocked()
		s.mu.Unlock()
	}, nil
}
func (s *leaseStopIO) keep(connection net.Conn) (net.Conn, error) {
	if connection == nil { return nil, errors.New("lease stop dial returned no owned stream") }
	owned := &leaseStopConn{Conn:connection, scope:s}
	s.mu.Lock()
	// Every caller holds an entered data operation until keep returns. Thus
	// a late returned socket cannot arrive after the scope has acknowledged drain.
	if s.pending == 0 {
		s.mu.Unlock()
		return nil,errors.Join(errors.New("lease stop stream has no entered original operation"),connection.Close())
	}
	retired := s.retired.Load() || s.ctx.Err() != nil
	s.connections[owned] = true
	s.notify()
	s.mu.Unlock()
	if retired {
		owned.startClose()
		return owned,net.ErrClosed
	}
	return owned, nil
}
func (s *leaseStopIO) retire() {
	s.mu.Lock()
	if s.retired.Swap(true) {
		s.mu.Unlock()
		return
	}
	connections := make([]*leaseStopConn,0,len(s.connections))
	for connection := range s.connections { connections = append(connections, connection) }
	s.checkDrainedLocked()
	s.mu.Unlock()
	s.cancel()
	for _, connection := range connections { connection.startClose() }
}
func (s *leaseStopIO) wait(ctx context.Context) error {
	if ctx == nil || !s.retired.Load() { return net.ErrClosed }
	attempts := make(map[*leaseStopConn]*leaseStopClose)
	for {
		if err := ctx.Err(); err != nil { return err }
		s.mu.Lock()
		connections := make([]*leaseStopConn,0,len(s.connections))
		for connection := range s.connections { connections = append(connections,connection) }
		s.mu.Unlock()
		for _,connection := range connections {
			if attempts[connection] == nil { attempts[connection] = connection.startClose() }
		}
		for _,attempt := range attempts {
			select {
			case <-attempt.done:
				if attempt.err != nil && !errors.Is(attempt.err,net.ErrClosed) { return attempt.err }
			default:
			}
		}
		select {
		case <-ctx.Done(): return ctx.Err()
		case <-s.drained: return ctx.Err()
		case <-s.changed:
		}
	}
}
type leaseStopClose struct {
	done chan struct{}
	err error
}
type leaseStopConn struct {
	net.Conn
	scope *leaseStopIO
	mu sync.Mutex
	closed bool
	closing *leaseStopClose
}
func (c *leaseStopConn) Read(p []byte) (int,error) {
	finish,err := c.scope.beginIO()
	if err != nil { return 0,err }
	defer finish()
	return c.Conn.Read(p)
}
func (c *leaseStopConn) Write(p []byte) (int,error) {
	finish,err := c.scope.beginIO()
	if err != nil { return 0,err }
	defer finish()
	return c.Conn.Write(p)
}
func (c *leaseStopConn) startClose() *leaseStopClose {
	c.mu.Lock()
	if c.closing != nil {
		if c.closed {
			existing := c.closing
			c.mu.Unlock()
			return existing
		}
		select {
		case <-c.closing.done:
			// A failed close remains owned. A later explicit cleanup attempt
			// retries that same connection object, never a numeric handle.
		default:
			existing := c.closing
			c.mu.Unlock()
			return existing
		}
	}
	attempt := &leaseStopClose{done:make(chan struct{})}
	c.closing = attempt
	c.mu.Unlock()
	go func() {
		attempt.err = c.Conn.Close()
		closed := attempt.err == nil || errors.Is(attempt.err,net.ErrClosed)
		c.mu.Lock()
		c.closed = closed
		c.mu.Unlock()
		if closed {
			c.scope.mu.Lock()
			delete(c.scope.connections,c)
			close(attempt.done)
			c.scope.checkDrainedLocked()
			c.scope.mu.Unlock()
		} else {
			close(attempt.done)
			c.scope.notify()
		}
	}()
	return attempt
}
func (c *leaseStopConn) Close() error {
	attempt := c.startClose()
	<-attempt.done
	return attempt.err
}

