package mobilepq

import (
	"context"
	"errors"
	"sync"
)

// DeferredProtocol keeps syntax/configuration checks free of native protocol
// handles. The pinned core constructs endpoints during CheckConfig without
// starting its endpoint manager. Allocate cryptographic state only when the
// captured controller first polls/receives during actual startup.
//
// This wrapper never owns a socket, resolver or interface. Its private copy of
// the captured keys is erased after initialization, cancellation or Close.
// Close joins a concurrent factory call/Step and cannot return while either can
// publish another native handle or key.
type DeferredProtocol struct {
	mu       sync.Mutex
	ctx      context.Context
	registry *FactoryRegistry
	config   Config
	protocol Protocol
	closed   bool
	closeErr error
	stop     func() bool
}

func NewDeferredProtocol(ctx context.Context, config Config, registry *FactoryRegistry) (*DeferredProtocol, error) {
	if ctx == nil || ctx.Err() != nil || registry == nil {
		return nil, errors.New("deferred PQ requires a current context and native registry")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config.Secret = append([]byte(nil), config.Secret...)
	config.Public = append([]byte(nil), config.Public...)
	config.Peer = append([]byte(nil), config.Peer...)
	p := &DeferredProtocol{ctx: ctx, registry: registry, config: config}
	// Install under the mutex: an already-cancelled context may schedule Close
	// immediately; it must observe the installed stop function and private copy.
	p.mu.Lock()
	p.stop = context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Unlock()
	return p, nil
}

func (p *DeferredProtocol) Step(kind uint32, packet []byte) (Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return Event{}, ErrStopped
	}
	if kind > 2 || len(packet) > 65535 || kind != 1 && len(packet) != 0 {
		return Event{}, errors.New("invalid deferred PQ event")
	}
	if p.protocol == nil {
		protocol, err := p.registry.Open(p.config)
		p.config.Erase()
		if err != nil {
			p.closeLocked()
			return Event{}, err
		}
		p.protocol = protocol
		if p.ctx.Err() != nil {
			p.closeLocked()
			return Event{}, ErrStopped
		}
	}
	event, err := p.protocol.Step(kind, packet)
	if p.ctx.Err() != nil {
		erase(event.Key)
		p.closeLocked()
		return Event{}, ErrStopped
	}
	if err != nil {
		erase(event.Key)
		return Event{}, err
	}
	return event, nil
}

func (p *DeferredProtocol) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	if p.stop != nil {
		p.stop()
	}
	p.config.Erase()
	if p.protocol != nil {
		if p.protocol.Close() != nil {
			p.closeErr = ErrCleanup
		}
		p.protocol = nil
	}
}

func (p *DeferredProtocol) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	return p.closeErr
}
