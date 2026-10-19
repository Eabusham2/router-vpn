package snowflake_client

import (
	"context"
	"errors"
	"sync"
)

// Peers retains each peer until its GracefulClose has joined Pion callbacks.
// A close request cancels an in-progress Catch before waiting for its lock.
type Peers struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tongue      Tongue
	collectLock sync.Mutex
	peers       []*WebRTCPeer
	available   chan *WebRTCPeer
}

func NewPeers(ctx context.Context, tongue Tongue) (*Peers, error) {
	if ctx == nil || tongue == nil {
		return nil, errors.New("Snowflake peer owner is missing")
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Peers{ctx: lifetime, cancel: cancel, tongue: tongue, available: make(chan *WebRTCPeer, 1)}, nil
}

func (p *Peers) Collect() (*WebRTCPeer, error) {
	p.collectLock.Lock()
	defer p.collectLock.Unlock()
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	active := p.peers[:0]
	for _, peer := range p.peers {
		if peer.Closed() {
			peer.Close()
		} else {
			active = append(active, peer)
		}
	}
	clear(p.peers[len(active):])
	p.peers = active
	if len(active) > 0 {
		return nil, errors.New("Snowflake peer capacity reached")
	}
	peer, err := p.tongue.Catch(p.ctx)
	if err != nil || p.ctx.Err() != nil {
		if peer != nil {
			peer.Close()
		}
		if err == nil {
			err = p.ctx.Err()
		}
		return nil, err
	}
	p.peers = append(p.peers, peer)
	select {
	case p.available <- peer:
		return peer, nil
	case <-p.ctx.Done():
		peer.Close()
		return nil, p.ctx.Err()
	}
}

func (p *Peers) Pop(ctx context.Context) *WebRTCPeer {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.ctx.Done():
			return nil
		case peer := <-p.available:
			if !peer.Closed() && ctx.Err() == nil && p.ctx.Err() == nil {
				return peer
			}
		}
	}
}
func (p *Peers) Stop() { p.cancel() }
func (p *Peers) End() {
	p.cancel()
	p.collectLock.Lock()
	defer p.collectLock.Unlock()
	for _, peer := range p.peers {
		peer.Close()
	}
	p.peers = nil
}
