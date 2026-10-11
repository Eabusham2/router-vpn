package mobilepq

import (
	"errors"
	"sync"
)

// NativeFactory constructs an independent pinned protocol owner. The installed
// factory contains no peer/session state; every Open creates a new native handle.
// Platform code supplies the FFI implementation, not a socket or routing owner.
type NativeFactory interface {
	Open(secret, public, peer []byte, version int) (Protocol, error)
}

type FactoryRegistry struct {
	mu      sync.Mutex
	factory NativeFactory
}

func (r *FactoryRegistry) Install(factory NativeFactory) error {
	if factory == nil {
		return errors.New("missing pinned PQ protocol factory")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != nil {
		return errors.New("native PQ protocol factory is already installed")
	}
	r.factory = factory
	return nil
}

func (r *FactoryRegistry) Open(config Config) (Protocol, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	factory := r.factory
	r.mu.Unlock()
	if factory == nil {
		return nil, errors.New("pinned PQ protocol factory is not installed")
	}
	// Native code copies the keys during Open. Never lend the configuration's
	// backing storage to a caller that might retain or modify it.
	secret := append([]byte(nil), config.Secret...)
	public := append([]byte(nil), config.Public...)
	peer := append([]byte(nil), config.Peer...)
	defer erase(secret)
	defer erase(public)
	defer erase(peer)
	protocol, err := factory.Open(secret, public, peer, config.Version)
	if err != nil || protocol == nil {
		if protocol != nil {
			_ = protocol.Close()
		}
		return nil, errors.New("pinned PQ protocol rejected its captured key material")
	}
	return protocol, nil
}

// NativeProtocols is an immutable constructor registry, never an active VPN or
// an active peer. Platform startup installs its compiled FFI factory once.
var NativeProtocols FactoryRegistry
