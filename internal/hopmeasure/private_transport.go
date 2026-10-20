package hopmeasure

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

// net/http can return a cancelled request before a native DialContext returns.
// Retain those workers and their sockets through actual Close completion so
// the service's drained bit also applies to private node measurements.
type privateMeasurementTransport struct {
	*http.Transport
	service     *Service
	tag         string
	mu          sync.Mutex
	closed      bool
	workers     sync.WaitGroup
	connections map[*privateMeasurementConn]struct{}
}

func (t *privateMeasurementTransport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed || network != "tcp" || t.service.valid(ctx) != nil {
		t.mu.Unlock()
		return nil, errors.New("private measurement transport retired")
	}
	t.workers.Add(1)
	t.mu.Unlock()
	connection, err := t.service.engine.Dial(ctx, t.tag, address)
	if connection == nil {
		t.workers.Done()
		return nil, errors.New("private measurement native dial failed")
	}
	owned := &privateMeasurementConn{Conn: connection, owner: t, done: make(chan struct{})}
	t.mu.Lock()
	t.connections[owned] = struct{}{}
	closed := t.closed
	t.mu.Unlock()
	if err != nil || closed || t.service.valid(ctx) != nil {
		_ = owned.Close()
		return nil, errors.New("private measurement native dial failed or retired")
	}
	return owned, nil
}

func (t *privateMeasurementTransport) CloseIdleConnections() {
	t.mu.Lock()
	t.closed = true
	connections := make([]*privateMeasurementConn, 0, len(t.connections))
	for connection := range t.connections {
		connections = append(connections, connection)
	}
	t.mu.Unlock()
	t.Transport.CloseIdleConnections()
	for _, connection := range connections {
		_ = connection.Close()
	}
	// closed forbids further Add; an already-started native dial either adds
	// its owned connection or closes a late connection before calling Done.
	t.workers.Wait()
}

type privateMeasurementConn struct {
	net.Conn
	owner *privateMeasurementTransport
	once  sync.Once
	done  chan struct{}
	err   error
}

func (c *privateMeasurementConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		if c.err != nil && !errors.Is(c.err, net.ErrClosed) && !errors.Is(c.err, io.ErrClosedPipe) {
			c.err = errors.New("private measurement native socket close failed")
			c.owner.service.Invalidate()
		}
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		close(c.done)
		c.owner.workers.Done()
	})
	<-c.done
	return c.err
}
