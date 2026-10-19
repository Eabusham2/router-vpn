package mobiletor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// TCPProxy owns the authenticated, process-local SOCKS5 proxy used by ordinary
// Tor to reach guard relays. It has no physical dialer or resolver of its own.
// Every destination is a literal relay address and every Internet socket is
// obtained from the captured VPN dialer. Close retains pending dials, actual
// socket closes, and both relay workers until they really finish.
type TCPProxy struct {
	ctx        context.Context
	cancel     context.CancelFunc
	network    *Network
	listener   net.Listener
	username   string
	password   string
	mu         sync.Mutex
	closing    bool
	failure    error
	clients    map[*proxyClient]struct{}
	workers    sync.WaitGroup
	stopping   chan struct{}
	done       chan struct{}
	parentStop func() bool
}

type proxyClient struct {
	net.Conn
	proxy *TCPProxy
	once  sync.Once
	err   error
}

func (c *proxyClient) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		if c.err != nil && !errors.Is(c.err, net.ErrClosed) && !errors.Is(c.err, io.ErrClosedPipe) {
			c.proxy.recordFailure()
		}
	})
	return c.err
}

// StartTCPProxy creates fresh private authentication for one Tor session. The
// owning Control receives the binding directly; no credentials enter profiles,
// process arguments, host APIs, status, or error strings.
func StartTCPProxy(ctx context.Context, dial DialContext) (*TCPProxy, error) {
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, errors.New("ordinary Tor requires its active protected TCP owner")
	}
	var secret [64]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, errors.New("ordinary Tor proxy authentication could not be created")
	}
	owned, cancel := context.WithCancel(ctx)
	network, err := NewNetwork(owned, dial, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		_ = network.Close(context.Background())
		return nil, errors.New("ordinary Tor private proxy could not listen")
	}
	p := &TCPProxy{ctx: owned, cancel: cancel, network: network, listener: listener,
		username: hex.EncodeToString(secret[:32]), password: hex.EncodeToString(secret[32:]),
		clients: make(map[*proxyClient]struct{}), stopping: make(chan struct{}), done: make(chan struct{})}
	p.workers.Add(1)
	go p.accept()
	p.parentStop = context.AfterFunc(ctx, p.beginClose)
	return p, nil
}

func (p *TCPProxy) binding() (address, username, password string, err error) {
	if p == nil {
		return "", "", "", errors.New("ordinary Tor private proxy is missing")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.ctx.Err() != nil {
		return "", "", "", net.ErrClosed
	}
	address = p.listener.Addr().String()
	endpoint, parseErr := netip.ParseAddrPort(address)
	if parseErr != nil || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || endpoint.Port() < 1024 || len(p.username) != 64 || len(p.password) != 64 {
		return "", "", "", errors.New("ordinary Tor private proxy binding is invalid")
	}
	return address, p.username, p.password, nil
}

func (p *TCPProxy) Stopping() <-chan struct{} { return p.stopping }
func (p *TCPProxy) Done() <-chan struct{}     { return p.done }

func (p *TCPProxy) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failure
}

func (p *TCPProxy) recordFailure() {
	p.mu.Lock()
	p.failure = errors.New("ordinary Tor protected proxy did not close cleanly")
	p.mu.Unlock()
}

func (p *TCPProxy) accept() {
	defer p.workers.Done()
	for {
		connection, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			unexpected := !p.closing && p.ctx.Err() == nil
			p.mu.Unlock()
			if unexpected {
				p.recordFailure()
				p.beginClose()
			}
			return
		}
		client := &proxyClient{Conn: connection, proxy: p}
		p.mu.Lock()
		if p.closing || p.ctx.Err() != nil || len(p.clients) >= 512 {
			p.mu.Unlock()
			_ = client.Close()
			continue
		}
		p.clients[client] = struct{}{}
		p.workers.Add(1)
		p.mu.Unlock()
		go p.serve(client)
	}
}

func (p *TCPProxy) serve(client *proxyClient) {
	defer p.workers.Done()
	defer func() {
		_ = client.Close()
		p.mu.Lock()
		delete(p.clients, client)
		p.mu.Unlock()
	}()
	if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return
	}
	destination, err := p.handshake(client)
	if err != nil {
		return
	}
	connection, err := p.network.DialContext(p.ctx, "tcp", destination.String())
	if err != nil {
		_ = proxyReply(client, 1)
		return
	}
	defer connection.Close()
	if p.ctx.Err() != nil || proxyReply(client, 0) != nil || client.SetDeadline(time.Time{}) != nil {
		return
	}
	// The two application pumps are explicitly joined. Closing the underlying
	// socket alone is not evidence that a captured protocol's Read has exited.
	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		_, _ = io.Copy(connection, client)
		_ = connection.Close()
		_ = client.Close()
	}()
	_, _ = io.Copy(client, connection)
	_ = connection.Close()
	_ = client.Close()
	<-forwardDone
}

func (p *TCPProxy) handshake(connection net.Conn) (netip.AddrPort, error) {
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil || header[0] != 5 || header[1] == 0 {
		return netip.AddrPort{}, errors.New("ordinary Tor proxy greeting is invalid")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return netip.AddrPort{}, err
	}
	authentication := false
	for _, method := range methods {
		authentication = authentication || method == 2
	}
	if !authentication {
		_, _ = connection.Write([]byte{5, 0xff})
		return netip.AddrPort{}, errors.New("ordinary Tor proxy requires private authentication")
	}
	if _, err := connection.Write([]byte{5, 2}); err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := io.ReadFull(connection, header[:]); err != nil || header[0] != 1 || int(header[1]) != len(p.username) {
		return netip.AddrPort{}, errors.New("ordinary Tor proxy authentication is invalid")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, username); err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := io.ReadFull(connection, header[:1]); err != nil || int(header[0]) != len(p.password) {
		return netip.AddrPort{}, errors.New("ordinary Tor proxy authentication is invalid")
	}
	password := make([]byte, int(header[0]))
	if _, err := io.ReadFull(connection, password); err != nil {
		return netip.AddrPort{}, err
	}
	valid := subtle.ConstantTimeCompare(username, []byte(p.username)) & subtle.ConstantTimeCompare(password, []byte(p.password))
	if valid != 1 {
		_, _ = connection.Write([]byte{1, 1})
		return netip.AddrPort{}, errors.New("ordinary Tor proxy authentication is invalid")
	}
	if _, err := connection.Write([]byte{1, 0}); err != nil {
		return netip.AddrPort{}, err
	}
	var request [4]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[2] != 0 {
		_ = proxyReply(connection, 7)
		return netip.AddrPort{}, errors.New("ordinary Tor proxy only carries TCP CONNECT")
	}
	var address netip.Addr
	switch request[3] {
	case 1:
		var raw [4]byte
		if _, err := io.ReadFull(connection, raw[:]); err != nil {
			return netip.AddrPort{}, err
		}
		address = netip.AddrFrom4(raw)
	case 4:
		var raw [16]byte
		if _, err := io.ReadFull(connection, raw[:]); err != nil {
			return netip.AddrPort{}, err
		}
		address = netip.AddrFrom16(raw).Unmap()
	default:
		_ = proxyReply(connection, 8)
		return netip.AddrPort{}, errors.New("ordinary Tor proxy requires a literal relay address")
	}
	var port [2]byte
	if _, err := io.ReadFull(connection, port[:]); err != nil {
		return netip.AddrPort{}, err
	}
	endpoint := netip.AddrPortFrom(address, binary.BigEndian.Uint16(port[:]))
	if endpoint.Port() == 0 || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		_ = proxyReply(connection, 2)
		return netip.AddrPort{}, errors.New("ordinary Tor proxy destination is not a public relay")
	}
	return endpoint, nil
}

func proxyReply(connection net.Conn, status byte) error {
	// BND.ADDR is deliberately unspecified: the lower may be an encrypted
	// predecessor, and its socket address must not be relabeled as a local bind.
	_, err := connection.Write([]byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func (p *TCPProxy) beginClose() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	close(p.stopping)
	clients := make([]*proxyClient, 0, len(p.clients))
	for client := range p.clients {
		clients = append(clients, client)
	}
	p.mu.Unlock()
	p.cancel()
	if err := p.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.recordFailure()
	}
	for _, client := range clients {
		go func(c *proxyClient) { _ = c.Close() }(client)
	}
	go func() {
		if err := p.network.Close(context.Background()); err != nil {
			p.recordFailure()
		}
		p.workers.Wait()
		close(p.done)
	}()
}

func (p *TCPProxy) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ordinary Tor proxy close context is missing")
	}
	p.beginClose()
	p.parentStop()
	select {
	case <-p.done:
		return p.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
