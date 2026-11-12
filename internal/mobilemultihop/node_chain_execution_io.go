package mobilemultihop

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const nodeChainExecutionLeasePath = "/api/multihop/chain/lease"

// This private I/O owner is shared by discovery, active lease control and the
// sealed DELETE capability. A failed join retains the exact entered operation;
// neither a later request nor a successful HTTP status can replace it.
type nodeChainExecutionIO struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	current                  func(context.Context) error
	dial                     func(context.Context, string, string) (net.Conn, error)
	tag, api, address, token string
	gate                     chan struct{}
	closed                   atomic.Bool
	mu                       sync.Mutex
	pending                  *leaseStopIO
	testTLS                  *tls.Config // package tests only; shipping uses the OS verifier
}

func newNodeChainExecutionIO(tag, api, token string, dial func(context.Context, string, string) (net.Conn, error), current func(context.Context) error) (*nodeChainExecutionIO, error) {
	u, err := privateAPI(api)
	if err != nil || !exactID.MatchString(tag) || token == "" || strings.ContainsAny(token, "\r\n") || dial == nil || current == nil {
		return nil, nodeChainExecutionError
	}
	ctx, cancel := context.WithCancel(context.Background())
	owner := &nodeChainExecutionIO{ctx: ctx, cancel: cancel, current: current, dial: dial, tag: tag, api: api, address: u.Host, token: token, gate: make(chan struct{}, 1)}
	owner.gate <- struct{}{}
	return owner, nil
}

func (s *nodeChainExecutionIO) run(parent context.Context, work func(context.Context, *leaseStopIO) ([]byte, error)) (data []byte, failure error) {
	if s == nil || parent == nil || work == nil || s.closed.Load() {
		return nil, nodeChainExecutionError
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	previous := s.pending
	s.mu.Unlock()
	if previous != nil {
		if err := previous.wait(ctx); err != nil {
			return nil, routedRequestFailure{"previous ordered control operation has not joined", err}
		}
	}
	operation := newLeaseStopIO(s.ctx)
	call, finish, err := operation.begin(ctx)
	if err != nil {
		operation.retire()
		return nil, err
	}
	s.mu.Lock()
	s.pending = operation
	s.mu.Unlock()
	defer func() {
		operation.retire()
		if err := operation.wait(ctx); err != nil {
			data = nil
			failure = errors.Join(failure, routedRequestFailure{"ordered control original I/O did not join", err})
			return
		}
		s.mu.Lock()
		if s.pending == operation {
			s.pending = nil
		}
		s.mu.Unlock()
		if s.closed.Load() || ctx.Err() != nil {
			data = nil
			failure = errors.Join(failure, ctx.Err(), net.ErrClosed)
		}
	}()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		defer finish()
		if s.closed.Load() || call.Err() != nil {
			done <- result{err: net.ErrClosed}
			return
		}
		if err := s.current(call); err != nil {
			done <- result{err: err}
			return
		}
		body, err := work(call, operation)
		if err == nil {
			err = s.current(call)
		}
		if err == nil {
			err = call.Err()
		}
		if s.closed.Load() {
			err = errors.Join(err, net.ErrClosed)
		}
		if err != nil {
			body = nil
		}
		done <- result{body, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	case answer := <-done:
		return answer.data, answer.err
	}
}

func (s *nodeChainExecutionIO) observe(ctx context.Context) error {
	_, err := s.run(ctx, func(context.Context, *leaseStopIO) ([]byte, error) { return nil, nil })
	return err
}

func (s *nodeChainExecutionIO) exchange(ctx context.Context, method, path string, payload []byte, limit int) ([]byte, error) {
	if len(payload) > 4096 || limit < 1 || limit > 512<<10 ||
		path != nodeChainExecutionLeasePath && !(path == "/health" && method == http.MethodGet) ||
		method != http.MethodGet && method != http.MethodPut && method != http.MethodPost && method != http.MethodDelete ||
		method == http.MethodGet && len(payload) != 0 {
		return nil, nodeChainExecutionError
	}
	body := append([]byte(nil), payload...)
	return s.run(ctx, func(call context.Context, operation *leaseStopIO) ([]byte, error) {
		target, err := privateAPI(s.api)
		if err != nil {
			return nil, nodeChainExecutionError
		}
		target.Path = path
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
			TLSHandshakeTimeout: 2500 * time.Millisecond, MaxResponseHeaderBytes: 16 << 10,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(parent context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != s.address || s.closed.Load() {
					return nil, nodeChainExecutionError
				}
				dialCtx, finish, err := operation.begin(parent)
				if err != nil {
					return nil, err
				}
				defer finish()
				if err := s.current(dialCtx); err != nil {
					return nil, err
				}
				connection, dialErr := s.dial(dialCtx, s.tag, s.address)
				var keepErr error
				if connection != nil {
					connection, keepErr = operation.keep(connection)
				}
				currentErr := s.current(dialCtx)
				if connection == nil || dialErr != nil || keepErr != nil || currentErr != nil || dialCtx.Err() != nil || s.closed.Load() {
					if owned, ok := connection.(*leaseStopConn); ok {
						owned.startClose()
					}
					return nil, errors.Join(dialErr, keepErr, currentErr, dialCtx.Err(), nodeChainExecutionError)
				}
				return connection, nil
			}}
		if s.testTLS != nil {
			transport.TLSClientConfig = s.testTLS.Clone()
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return nodeChainExecutionError }}
		request, err := http.NewRequestWithContext(call, method, target.String(), strings.NewReader(string(body)))
		if err != nil {
			return nil, nodeChainExecutionError
		}
		request.Header.Set("Cache-Control", "no-store")
		request.Header.Set("Accept-Encoding", "identity")
		request.Header.Set("Authorization", "Bearer "+s.token)
		if len(body) != 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, routedRequestFailure{"ordered private request failed", err}
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, controlError{response.StatusCode}
		}
		if readErr != nil || closeErr != nil || len(data) > limit || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
			return nil, errors.Join(errors.New("ordered private response exceeded its exact bound or framing"), readErr, closeErr)
		}
		return data, nil
	})
}

// close marks admission terminal before waiting. The exact pending operation
// remains reachable on a failed deadline/close; an explicit retry joins it.
func (s *nodeChainExecutionIO) close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return nodeChainExecutionError
	}
	s.closed.Store(true)
	s.cancel()
	s.mu.Lock()
	active := s.pending
	s.mu.Unlock()
	if active != nil {
		active.retire()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	s.mu.Lock()
	active = s.pending
	s.mu.Unlock()
	if active != nil {
		active.retire()
		if err := active.wait(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		if s.pending == active {
			s.pending = nil
		}
		s.mu.Unlock()
	}
	return ctx.Err()
}
