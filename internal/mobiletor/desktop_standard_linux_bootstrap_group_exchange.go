//go:build linux

package mobiletor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// Exchange retains its original socket/grant until joined exact retirement
// or group Close. A failed reply never cancels sibling scopes. The caller validates replies and cancels losing
// query contexts only after choosing a usable answer, then must Close the group.
func (g *DesktopLinuxBootstrapDNSGroup) Exchange(query context.Context, upstream DesktopLinuxBootstrapDNSUpstream, question []byte) ([]byte, error) {
	return g.exchangeAttempt(query, upstream, question, nil)
}
func (g *DesktopLinuxBootstrapDNSGroup) exchangeAttempt(query context.Context, upstream DesktopLinuxBootstrapDNSUpstream, question []byte, attempt *desktopLinuxBootstrapTLSAttempt) (answer []byte, failure error) {
	return g.exchangeOwnedAttempt(query, upstream, question, attempt, nil)
}
func (g *DesktopLinuxBootstrapDNSGroup) exchangeOwnedAttempt(query context.Context, upstream DesktopLinuxBootstrapDNSUpstream, question []byte, attempt *desktopLinuxBootstrapTLSAttempt, dnssec *DesktopLinuxBootstrapDNSSECQuestion) (answer []byte, failure error) {
	var t *desktopLinuxStandardBootstrap
	// Registered first: no member is recyclable until all later IO/cancellation
	// callbacks have joined and the immutable response/error is final.
	defer func() {
		if t == nil {
			return
		}
		g.mu.Lock()
		t.groupJoined = true
		var unavailable *desktopLinuxBootstrapTLSUnavailable
		if !errors.As(failure, &unavailable) {
			t.groupPinned = false
		}
		g.active--
		g.mu.Unlock()
		g.wg.Done()
	}()

	if g == nil || query == nil || g.ctx == nil || g.owner == nil || g.owner.baseline == nil {
		return nil, errors.New("bootstrap group omitted original query")
	}
	deadline, ok := query.Deadline()
	questionError := desktopLinuxBootstrapQuestion(question)
	if dnssec != nil {
		questionError = dnssec.matches(g, upstream, question)
	}
	if !ok || deadline.After(g.deadline) || query.Err() != nil || g.ctx.Err() != nil || upstream.Validate() != nil || questionError != nil {
		return nil, errors.New("bootstrap group query outside original bounds")
	}
	if attempt != nil && (upstream.Network != "tls" || attempt.config == nil || attempt.deadline.After(deadline) || !attempt.deadline.After(time.Now())) {
		return nil, errors.New("opportunistic attempt escaped original bounded TLS stage")
	}
	ctx, cancel := context.WithDeadline(g.ctx, deadline)
	defer cancel()
	joined := make(chan struct{})
	stopQuery := context.AfterFunc(query, func() { cancel(); close(joined) })
	defer func() {
		if !stopQuery() {
			<-joined
		}
	}()
	defer func() {
		failure = errors.Join(failure, ctx.Err())
		if failure != nil {
			answer = nil
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e := desktopnetwork.LockContext(ctx, &g.mu); e != nil {
		return nil, e
	}
	if g.closing || g.closed || g.blocked != nil {
		g.mu.Unlock()
		return nil, errors.New("bootstrap group no longer admits queries")
	}
	if err := g.retireJoined(ctx); err != nil {
		g.mu.Unlock()
		return nil, err
	}
	if err := g.capacity(); err != nil {
		g.mu.Unlock()
		return nil, err
	}
	if _, err := g.observe(ctx); err != nil {
		if ctx.Err() == nil || g.owner.baseline.netlink.uncertain != nil || g.owner.baseline.netlink.bootstrap != nil {
			g.blocked = err
		}
		g.mu.Unlock()
		return nil, err
	}
	route, e := upstream.route(ctx, 0, netip.AddrPort{})
	if e != nil {
		g.mu.Unlock()
		return nil, e
	}
	t = &desktopLinuxStandardBootstrap{groupPinned: attempt != nil, route: route, remote: upstream.Endpoint, network: upstream.socketNetwork(), upstream: &upstream, group: g}
	g.members = append(g.members, t)
	g.inventoryBytes += desktopLinuxBootstrapGroupGrantBytes
	g.active++
	g.admitted++
	g.wg.Add(1)
	g.mu.Unlock()
	b, lease, network := g.owner.baseline, g.lease, t.network
	var random [4]byte
	if _, e = rand.Read(random[:]); e != nil {
		return nil, e
	}
	t.mark = binary.BigEndian.Uint32(random[:]) | 0x80000000
	dialDeadline := deadline
	if attempt != nil {
		dialDeadline = attempt.deadline
	}
	var controlFailure error
	dialer := net.Dialer{Deadline: dialDeadline, KeepAlive: -1, ControlContext: func(control context.Context, actualNetwork, address string, raw syscall.RawConn) error {
		defer func() {
			if controlFailure == nil && control.Err() != nil {
				controlFailure = control.Err()
			}
		}()
		if address != t.remote.String() || actualNetwork != network+"4" && actualNetwork != network+"6" {
			controlFailure = errors.New("bootstrap dial changed original destination")
			return controlFailure
		}
		if e := desktopnetwork.LockContext(control, &g.mu); e != nil {
			controlFailure = e
			return e
		}
		defer g.mu.Unlock()
		if g.closing || g.blocked != nil {
			controlFailure = errors.Join(g.blocked, errors.New("bootstrap group stopped socket admission"))
			return controlFailure
		}
		var setup error
		if e := raw.Control(func(fd uintptr) { setup = t.prepareSocket(ctx, int(fd), b, lease) }); e != nil {
			controlFailure = e
			return e
		}
		if setup != nil && t.grant != nil && (t.grant.sent && !t.grant.complete() || t.grant.poison != nil) {
			g.blocked = errors.Join(g.blocked, setup)
		}
		if setup == nil && attempt != nil && !time.Now().Before(attempt.deadline) {
			setup = errors.New("opportunistic TLS stage exhausted during local grant setup")
		}
		controlFailure = setup
		return setup
	}}
	t.conn, e = dialer.DialContext(ctx, network, t.remote.String())
	if e != nil {
		if attempt != nil && controlFailure == nil {
			return nil, g.unavailableTLS(ctx, t, e)
		}
		return nil, e
	}
	t.connected = true
	if e = t.currentSocket(ctx); e != nil {
		return nil, e
	}
	// The original raw connection remains the retirement owner. tls.Close sends
	// close_notify under its own five-second deadline; teardown must not replace
	// the captured operation budget or send after the finite permit is removed.
	connection := t.conn
	var secure *tls.Conn
	if upstream.Network == "tls" {
		config, e := upstream.tlsConfig()
		if e != nil {
			return nil, e
		}
		if attempt != nil {
			config = attempt.config.Clone()
		}
		secure = tls.Client(connection, config)
		connection = secure
	}
	if e = connection.SetDeadline(dialDeadline); e != nil {
		return nil, e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if secure != nil {
		if e = secure.HandshakeContext(ctx); e != nil {
			if attempt != nil {
				return nil, g.unavailableTLS(ctx, t, e)
			}
			return nil, e
		}
		if e = t.currentSocket(ctx); e != nil {
			return nil, e
		}
	}
	if attempt != nil {
		if e = connection.SetDeadline(deadline); e != nil {
			return nil, e
		}
	}
	if network == "tcp" {
		if dnssec == nil {
			answer, e = desktopLinuxBootstrapStreamExchange(connection, question)
		} else {
			answer, e = desktopLinuxBootstrapFramedExchange(connection, question, 65535)
		}
		if e != nil {
			return nil, e
		}
	} else {
		n, e := t.conn.Write(question)
		if e != nil || n != len(question) {
			return nil, errors.Join(e, io.ErrShortWrite)
		}
		bound := 16 << 10
		if dnssec != nil {
			bound = 65535
		}
		buffer := make([]byte, bound+1)
		n, e = t.conn.Read(buffer)
		if e != nil || n > bound {
			return nil, errors.Join(e, errors.New("bootstrap UDP answer exceeds bound"))
		}
		answer = buffer[:n]
	}
	if e = t.currentSocket(ctx); e != nil {
		return nil, e
	}
	if e := desktopnetwork.LockContext(ctx, &g.mu); e != nil {
		return nil, e
	}
	defer g.mu.Unlock()
	if g.closing || g.blocked != nil {
		return nil, errors.Join(g.blocked, errors.New("bootstrap group stopped response adoption"))
	}
	present, e := t.observe(ctx, b)
	if e != nil || !present || t.grant != nil && !t.grantLive {
		return nil, errors.Join(e, errors.New("bootstrap grant changed before response adoption"))
	}
	return answer, ctx.Err()
}
