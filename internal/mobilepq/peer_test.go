package mobilepq

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type nativePeerProbe struct {
	mu                                      sync.Mutex
	keys, peers                             [][]byte
	phases                                  []bool
	closes                                  int
	closed                                  bool
	failStart, failPost, failKey, failClose bool
	enter, release                          chan struct{}
}

func (p *nativePeerProbe) SetPQKey(public, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.failKey {
		return errors.New("private key details")
	}
	p.peers = append(p.peers, append([]byte(nil), public...))
	p.keys = append(p.keys, append([]byte(nil), key...))
	return nil
}
func (p *nativePeerProbe) Start(post bool) error {
	if !post && p.enter != nil {
		close(p.enter)
		<-p.release
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) == 0 || p.closed || post && p.failPost || !post && p.failStart {
		return errors.New("private startup details")
	}
	p.phases = append(p.phases, post)
	return nil
}
func (p *nativePeerProbe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.closes++
	if p.failClose {
		return errors.New("private cleanup details")
	}
	return nil
}
func peerFixture(t *testing.T) (*PeerOwner, *nativePeerProbe, *testProtocol, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	peer := &nativePeerProbe{}
	protocol := &testProtocol{}
	owner, err := NewPeerOwner(context.Background(), protocol, func(context.Context) (net.Conn, error) { return a, nil }, peer, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	owner.controller.timeout = time.Second
	t.Cleanup(func() { b.Close(); owner.Close() })
	return owner, peer, protocol, b
}
func peerBegin(p *PeerOwner) <-chan error {
	done := make(chan error, 1)
	go func() { done <- p.Start(false) }()
	return done
}
func TestPeerCannotStartOrPublishUntilAuthenticatedKeyAndPostStart(t *testing.T) {
	owner, peer, _, wire := peerFixture(t)
	done := peerBegin(owner)
	if owner.Ready() {
		t.Fatal("unproved peer ready")
	}
	peer.mu.Lock()
	if len(peer.phases) != 0 {
		t.Fatal("base started before negotiated key")
	}
	peer.mu.Unlock()
	send(t, wire, "key")
	await(t, done, false)
	if owner.Ready() {
		t.Fatal("missing native post-start accepted")
	}
	if err := owner.Start(true); err != nil {
		t.Fatal(err)
	}
	if !owner.Ready() {
		t.Fatal("authenticated native peer never became ready")
	}
	send(t, wire, "rekey")
	eventually(t, func() bool { peer.mu.Lock(); defer peer.mu.Unlock(); return len(peer.keys) == 2 })
	peer.mu.Lock()
	if len(peer.phases) != 2 || peer.phases[0] || !peer.phases[1] {
		t.Fatal("incorrect native lifecycle")
	}
	for _, key := range peer.peers {
		if !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
			t.Fatal("peer identity changed")
		}
	}
	peer.mu.Unlock()
	send(t, wire, "expire")
	eventually(t, func() bool { return !owner.Ready() })
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.closes != 1 || !peer.closed {
		t.Fatal("expired tunnel not torn down exactly once")
	}
	if len(peer.keys) != 2 {
		t.Fatal("expiry installed a fallback key")
	}
}
func TestPeerCancellationDuringNativeStartupCannotPublishReady(t *testing.T) {
	owner, peer, _, wire := peerFixture(t)
	peer.enter = make(chan struct{})
	peer.release = make(chan struct{})
	done := peerBegin(owner)
	send(t, wire, "key")
	<-peer.enter
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	eventually(t, func() bool { return owner.ctx.Err() != nil })
	if owner.Ready() {
		t.Fatal("cancelled starting peer ready")
	}
	close(peer.release)
	await(t, done, true)
	await(t, closed, false)
	if owner.Start(true) == nil || owner.Ready() {
		t.Fatal("stale native startup survived cancellation")
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.closes != 1 {
		t.Fatal("peer leaked")
	}
}
func TestPeerStartupAndInstallationFailuresCloseTheOnlyPeer(t *testing.T) {
	for _, kind := range []string{"key", "start", "post"} {
		t.Run(kind, func(t *testing.T) {
			owner, peer, _, wire := peerFixture(t)
			peer.failKey = kind == "key"
			peer.failStart = kind == "start"
			peer.failPost = kind == "post"
			done := peerBegin(owner)
			send(t, wire, "key")
			await(t, done, kind != "post")
			if kind == "post" && owner.Start(true) == nil {
				t.Fatal("failed post-start accepted")
			}
			owner.Close()
			if owner.Ready() {
				t.Fatal("failed native peer ready")
			}
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if peer.closes != 1 {
				t.Fatal("failed peer not closed")
			}
		})
	}
}
func TestPeerNeverStartedAndConcurrentCloseJoin(t *testing.T) {
	owner, peer, protocol, _ := peerFixture(t)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if peer.closes != 1 || protocol.closes != 1 || owner.Start(false) == nil || owner.Start(true) == nil || owner.Ready() {
		t.Fatal("closed native owner reused or leaked")
	}
}
func TestPeerCleanupFailureIsSanitizedAndNotSuccess(t *testing.T) {
	owner, peer, _, _ := peerFixture(t)
	peer.failClose = true
	if err := owner.Close(); !errors.Is(err, ErrCleanup) {
		t.Fatal(err)
	}
	if owner.Ready() {
		t.Fatal("unconfirmed shutdown is healthy")
	}
}
func TestPeerRejectsUnownedAndEmptyKeyInputs(t *testing.T) {
	owner, peer, _, _ := peerFixture(t)
	for _, key := range [][]byte{nil, make([]byte, 32), make([]byte, 31), make([]byte, 33)} {
		if owner.ApplyPQKey(key) == nil {
			t.Fatal("invalid negotiated key installed")
		}
	}
	peer.mu.Lock()
	if len(peer.keys) != 0 {
		t.Fatal("invalid key reached peer")
	}
	peer.mu.Unlock()
	owner.Close()
	if owner.ApplyPQKey(bytes.Repeat([]byte{1}, 32)) == nil {
		t.Fatal("closed peer accepted key")
	}
	if _, err := NewPeerOwner(context.Background(), &testProtocol{}, func(context.Context) (net.Conn, error) { return nil, nil }, peer, make([]byte, 32)); err == nil {
		t.Fatal("missing public identity accepted")
	}
}
