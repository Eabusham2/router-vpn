package mobilepq

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Peer is the already-selected native WG or AWG instance. Start(false) starts
// its transport, Start(true) performs its post-start phase. No second interface,
// protocol fallback or mutable process-global peer is involved.
type Peer interface {
	Start(post bool) error
	SetPQKey(publicKey, key []byte) error
	Close() error
}

// PeerOwner serializes key installation with native startup and teardown.
// The first authenticated key is installed before any encrypted peer starts.
type PeerOwner struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	peer           Peer
	public         [32]byte
	controller     *Controller
	phase          int
	closed         bool
	ready          atomic.Bool
	transportReady atomic.Bool
	peerErr        error
}

func NewPeerOwner(ctx context.Context, protocol Protocol, dial Dial, peer Peer, publicKey []byte) (*PeerOwner, error) {
	if ctx == nil || protocol == nil || dial == nil || peer == nil || len(publicKey) != 32 {
		return nil, errors.New("native PQ requires one captured protocol, transport and peer")
	}
	var nonzero byte
	for _, b := range publicKey {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("native PQ has no captured peer identity")
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &PeerOwner{ctx: ctx, cancel: cancel, peer: peer}
	copy(p.public[:], publicKey)
	controller, err := New(ctx, protocol, p, dial)
	if err != nil {
		cancel()
		return nil, err
	}
	p.controller = controller
	return p, nil
}

func (p *PeerOwner) Start(post bool) error {
	if post {
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil || p.phase != 2 {
			p.mu.Unlock()
			return ErrStopped
		}
		err := p.peer.Start(true)
		if err == nil && p.ctx.Err() == nil {
			p.phase = 3
			p.ready.Store(true)
			p.mu.Unlock()
			return nil
		}
		p.mu.Unlock()
		cleanup := p.Close()
		return errors.Join(errors.New("native PQ peer post-start failed"), cleanup)
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || p.phase != 0 {
		p.mu.Unlock()
		return ErrStopped
	}
	p.phase = 1
	p.mu.Unlock()
	// Controller.Start calls ApplyPQKey. Never hold peer lifecycle access while
	// waiting for it, or shutdown/adoption would deadlock each other.
	if err := p.controller.Start(); err != nil {
		return errors.Join(err, p.Close())
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return errors.Join(ErrStopped, p.Close())
	}
	err := p.peer.Start(false)
	if err == nil && p.ctx.Err() == nil {
		p.phase = 2
		p.transportReady.Store(true)
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	return errors.Join(errors.New("native PQ peer startup failed"), p.Close())
}

// TransportReady permits only native outbound dials after the authenticated
// key and the literal-peer transport are installed. The core starts dependent
// endpoints in dependency order before its global post-start stage. Waiting for
// that later stage here would prevent a nested tunnel from starting at all.
// Flow forwarding and externally reported readiness still require Ready().
func (p *PeerOwner) TransportReady() bool {
	return p != nil && p.transportReady.Load() && p.ctx.Err() == nil && p.controller.Ready()
}

func (p *PeerOwner) Ready() bool {
	return p != nil && p.ready.Load() && p.ctx.Err() == nil && p.controller.Ready()
}
func (p *PeerOwner) Err() error { return p.controller.Err() }
func (p *PeerOwner) ApplyPQKey(key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || len(key) != 32 {
		return ErrStopped
	}
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return errors.New("native PQ refused an empty negotiated key")
	}
	return p.peer.SetPQKey(p.public[:], key)
}
func (p *PeerOwner) RevokePQKey() error {
	p.cancel()
	p.ready.Store(false)
	p.transportReady.Store(false)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.peerErr = p.peer.Close()
		erase(p.public[:])
	}
	if p.peerErr != nil {
		return ErrCleanup
	}
	return nil
}
func (p *PeerOwner) Close() error {
	p.cancel()
	p.ready.Store(false)
	p.transportReady.Store(false)
	// Controller cleanup invokes RevokePQKey and joins in-flight key adoption.
	// Calling this with mu held would block the very operation being joined.
	return p.controller.Close()
}
