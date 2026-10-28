package mobiletor

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerTorFront is the one exact-peer, authenticated TCP front of a server
// lease. Opening it grants no forwarding: Enable follows the owner's live DNS
// and Tor proof. It never creates a TUN, changes a route, or resolves on the host.
type ServerTorFront struct {
	ctx                context.Context
	cancel             context.CancelFunc
	listener           net.Listener
	peer               netip.Addr
	username, password string
	network            *Network
	allowed            atomic.Bool
	mu                 sync.Mutex
	closing            bool
	failure            error
	clients            map[net.Conn]struct{}
	workers            sync.WaitGroup
	done               chan struct{}
	stop               func() bool
	comparison         ServerTorComparisonFront
}

// ServerTorComparisonFront is installed once, before forwarding is enabled.
// Its own exact native owner retains and drains measurement operations; the
// front owns only the authenticated client sockets and their entered workers.
type ServerTorComparisonFront interface {
	Serve(context.Context, net.Conn) error
	Cancel()
}

func (f *ServerTorFront) SetComparison(owner ServerTorComparisonFront) error {
	if f == nil || owner == nil {
		return errServerLastRelay
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || f.ctx.Err() != nil || f.allowed.Load() || f.comparison != nil {
		return errServerLastRelay
	}
	f.comparison = owner
	return nil
}

func StartServerTorFront(ctx context.Context, host, peer string, port int, username, password string, dial DialContext) (*ServerTorFront, error) {
	h, eh := netip.ParseAddr(host)
	p, ep := netip.ParseAddr(peer)
	if ctx == nil || ctx.Err() != nil || eh != nil || ep != nil || h.String() != host || p.String() != peer ||
		h.IsUnspecified() || p.IsUnspecified() || h.Zone() != "" || p.Zone() != "" || port < 1024 || port > 65535 ||
		!desktopHex(username, 24) || !desktopHex(password, 24) || username == password || dial == nil {
		return nil, errors.New("server Tor front requires its captured peer, listener and authentication")
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, errors.New("server Tor captured front could not bind")
	}
	return newServerTorFront(ctx, l, p, username, password, dial)
}

func newServerTorFront(ctx context.Context, l net.Listener, peer netip.Addr, username, password string, dial DialContext) (*ServerTorFront, error) {
	owned, cancel := context.WithCancel(ctx)
	network, err := NewNetwork(owned, dial, nil)
	if err != nil {
		cancel()
		_ = l.Close()
		return nil, err
	}
	f := &ServerTorFront{ctx: owned, cancel: cancel, listener: l, peer: peer.Unmap(), username: username, password: password,
		network: network, clients: make(map[net.Conn]struct{}), done: make(chan struct{})}
	f.workers.Add(1)
	go f.accept()
	f.stop = context.AfterFunc(ctx, f.retire)
	return f, nil
}

func (f *ServerTorFront) Current() bool {
	if f == nil || f.ctx.Err() != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.closing
}
func (f *ServerTorFront) Allowed() bool { return f.Current() && f.allowed.Load() }
func (f *ServerTorFront) Enable() error {
	if !f.Current() {
		return net.ErrClosed
	}
	f.allowed.Store(true)
	if !f.Current() {
		f.allowed.Store(false)
		return net.ErrClosed
	}
	return nil
}
func (f *ServerTorFront) Address() string { return f.listener.Addr().String() }

func (f *ServerTorFront) accept() {
	defer f.workers.Done()
	for {
		connection, err := f.listener.Accept()
		if err != nil {
			if f.Current() {
				f.recordFailure()
				f.retire()
			}
			return
		}
		address, err := netip.ParseAddrPort(connection.RemoteAddr().String())
		f.mu.Lock()
		accept := !f.closing && f.ctx.Err() == nil && err == nil && address.Addr().Unmap() == f.peer && len(f.clients) < 512
		if accept {
			f.clients[connection] = struct{}{}
			f.workers.Add(1)
		}
		f.mu.Unlock()
		if !accept {
			_ = connection.Close()
			continue
		}
		go f.serve(connection)
	}
}
func (f *ServerTorFront) serve(client net.Conn) {
	defer f.workers.Done()
	defer func() { _ = client.Close(); f.mu.Lock(); delete(f.clients, client); f.mu.Unlock() }()
	if client.SetDeadline(time.Now().Add(15*time.Second)) != nil {
		return
	}
	address, err := f.handshake(client)
	if err != nil {
		return
	}
	if !f.Allowed() {
		_ = proxyReply(client, 2)
		return
	}
	if address == serverLastRelayAddress {
		f.mu.Lock()
		comparison := f.comparison
		f.mu.Unlock()
		if comparison == nil || proxyReply(client, 0) != nil {
			return
		}
		_ = comparison.Serve(f.ctx, client)
		return
	}
	remote, err := f.network.DialContext(f.ctx, "tcp", address)
	if err != nil || remote == nil {
		_ = proxyReply(client, 1)
		return
	}
	defer remote.Close()
	if !f.Allowed() || proxyReply(client, 0) != nil || client.SetDeadline(time.Time{}) != nil {
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(remote, client); _ = remote.Close(); _ = client.Close() }()
	_, _ = io.Copy(client, remote)
	_ = remote.Close()
	_ = client.Close()
	<-done
}
func (f *ServerTorFront) handshake(c net.Conn) (string, error) {
	bad := errors.New("server Tor front requires exact private TCP authentication")
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return "", bad
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", bad
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == 2
	}
	if !ok {
		_, _ = c.Write([]byte{5, 255})
		return "", bad
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return "", bad
	}
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 || int(h[1]) != len(f.username) {
		return "", bad
	}
	u := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, u); err != nil {
		return "", bad
	}
	if _, err := io.ReadFull(c, h[:1]); err != nil || int(h[0]) != len(f.password) {
		return "", bad
	}
	p := make([]byte, int(h[0]))
	if _, err := io.ReadFull(c, p); err != nil {
		return "", bad
	}
	ok = subtle.ConstantTimeCompare(u, []byte(f.username))&subtle.ConstantTimeCompare(p, []byte(f.password)) == 1
	clear(u)
	clear(p)
	if !ok {
		_, _ = c.Write([]byte{1, 1})
		return "", bad
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return "", bad
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 || req[1] != 1 && req[1] != serverLastRelayCommand || req[2] != 0 {
		_ = proxyReply(c, 7)
		return "", bad
	}
	var host string
	switch req[3] {
	case 1, 4:
		size := 4
		if req[3] == 4 {
			size = 16
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(c, raw); err != nil {
			return "", bad
		}
		ip, _ := netip.AddrFromSlice(raw)
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			_ = proxyReply(c, 2)
			return "", bad
		}
		host = ip.String()
	case 3:
		if _, err := io.ReadFull(c, h[:1]); err != nil || h[0] == 0 {
			return "", bad
		}
		raw := make([]byte, int(h[0]))
		if _, err := io.ReadFull(c, raw); err != nil {
			return "", bad
		}
		host = string(raw)
		if !serverTorDomain(host) {
			_ = proxyReply(c, 8)
			return "", bad
		}
	default:
		_ = proxyReply(c, 8)
		return "", bad
	}
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return "", bad
	}
	port := binary.BigEndian.Uint16(h[:])
	if port == 0 {
		return "", bad
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if req[1] == serverLastRelayCommand {
		if req[3] != 3 || address != serverLastRelayAddress {
			_ = proxyReply(c, 8)
			return "", bad
		}
	} else if serverLastRelayReserved(host) {
		_ = proxyReply(c, 2)
		return "", bad
	}
	return address, nil
}

func serverTorDomain(host string) bool {
	if len(host) < 1 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (f *ServerTorFront) recordFailure() {
	f.mu.Lock()
	f.failure = errors.New("server Tor front did not close cleanly")
	f.mu.Unlock()
}
func (f *ServerTorFront) retire() {
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		return
	}
	f.closing = true
	f.allowed.Store(false)
	comparison := f.comparison
	clients := make([]net.Conn, 0, len(f.clients))
	for c := range f.clients {
		clients = append(clients, c)
	}
	f.mu.Unlock()
	f.cancel()
	if comparison != nil {
		comparison.Cancel()
	}
	if err := f.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		f.recordFailure()
	}
	for _, c := range clients {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			f.recordFailure()
		}
	}
	go func() {
		if f.network.Close(context.Background()) != nil {
			f.recordFailure()
		}
		f.workers.Wait()
		close(f.done)
	}()
}
func (f *ServerTorFront) Close(ctx context.Context) error {
	if f == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("server Tor front close requires a context")
	}
	f.retire()
	if f.stop != nil {
		f.stop()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.failure
	}
}
