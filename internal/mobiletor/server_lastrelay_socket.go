package mobiletor

import (
	"errors"
	"io"
	"net"
	"sync"
)

// Both the remote client and native server keep the same in-flight cleanup
// attempt until it finishes; this pure record must remain in the mobile copy.
type serverLastRelayDrain struct {
	done chan struct{}
	err  error
}

// The retained network owns this wrapper, rather than the raw socket. Cleanup
// therefore joins every entered I/O operation even if a lower Close returns
// early. A failed Close stays reachable and is retried by the same handle.
type serverLastRelaySocket struct {
	net.Conn
	current         func() bool
	mu              sync.Mutex
	closeMu         sync.Mutex
	closing, closed bool
	workers         sync.WaitGroup
}

func (s *serverLastRelaySocket) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.current != nil && !s.current() {
		return net.ErrClosed
	}
	s.workers.Add(1)
	return nil
}
func (s *serverLastRelaySocket) Read(data []byte) (int, error) {
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.workers.Done()
	n, err := s.Conn.Read(data)
	if s.current != nil && !s.current() {
		return 0, net.ErrClosed
	}
	return n, err
}
func (s *serverLastRelaySocket) Write(data []byte) (int, error) {
	if err := s.begin(); err != nil {
		return 0, err
	}
	defer s.workers.Done()
	n, err := s.Conn.Write(data)
	if s.current != nil && !s.current() {
		return 0, net.ErrClosed
	}
	return n, err
}
func (s *serverLastRelaySocket) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.mu.Unlock()
	if err := s.Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	s.workers.Wait()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
