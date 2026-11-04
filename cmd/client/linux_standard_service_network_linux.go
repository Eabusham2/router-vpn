//go:build linux

package main

import (
	"context"
	"errors"
	"runtime"

	"router-vpn/internal/desktopnetwork"
)

type linuxStandardNetworkObserver interface {
	CurrentContext(context.Context) error
	Close() error
}

// This is one retained, monotonically invalidated event epoch. No event is
// exempted by interface name, and no TUN/route receipt is synthesized. A fresh
// session may own a fresh observer; this object can never be reopened/rebased.
type linuxStandardServiceNetwork struct {
	session  *linuxStandardServiceSession
	owner    *linuxLegacyStandardExitOwner
	observer linuxStandardNetworkObserver
	lifetime context.Context
	cancel   context.CancelFunc
	failure  error
	closed   bool
}

func openLinuxStandardNetworkObserver(operation, lifetime context.Context) (linuxStandardNetworkObserver, error) {
	return desktopnetwork.OpenWithLifetime(operation, lifetime, nil)
}

// Caller holds the service gate and original native namespace. The first real
// uncached DNS exchange establishes original child/listener readiness only.
// Its result is not published. A second exchange and every later proof run
// under the one armed epoch. Startup before this milestone remains covered by
// the unchanged preparation snapshot, not by a fabricated event receipt.
func (s *linuxStandardService) proveDNSWithNetwork(ctx context.Context) error {
	open := s.openNetwork
	if open == nil {
		open = openLinuxStandardNetworkObserver
	}
	return s.proveDNSWithNetworkObservers(ctx, open, func(ctx context.Context, owner *linuxLegacyStandardExitOwner) error {
		return owner.ProveSelectedDNS(ctx)
	})
}

func (s *linuxStandardService) proveDNSWithNetworkObservers(ctx context.Context, open func(context.Context, context.Context) (linuxStandardNetworkObserver, error), prove func(context.Context, *linuxLegacyStandardExitOwner) error) (failure error) {
	if ctx == nil || ctx.Err() != nil || s.session == nil || s.session.owner == nil || s.session.joined || s.session.cleanupPending || open == nil || prove == nil {
		return errors.New("network epoch requires its original live selected-DNS operation")
	}
	session := s.session
	owner := session.owner
	defer func() {
		if failure != nil && session.network != nil && session.network.session == session && session.network.owner == owner && session.network.failure == nil {
			session.network.failure = failure
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := owner.namespaceCurrent(); err != nil {
		return err
	}
	if session.network == nil {
		if err := prove(ctx, owner); err != nil {
			return err
		}
		if s.session != session || session.owner != owner || ctx.Err() != nil {
			return errors.New("network readiness lost its original session")
		}
		lifetime, cancel := context.WithCancel(context.Background())
		n := &linuxStandardServiceNetwork{session: session, owner: owner, lifetime: lifetime, cancel: cancel}
		// Retain even a partial/failed original observer. A retry must not
		// install another stream and erase an invalidation or unjoined reader.
		session.network = n
		n.observer, n.failure = open(ctx, lifetime)
		if n.failure != nil {
			return n.failure
		}
		if n.observer == nil {
			n.failure = errors.New("network initialization returned no original observer")
			return n.failure
		}
	}
	if err := s.networkCurrent(ctx, session, true); err != nil {
		return err
	}
	if err := prove(ctx, owner); err != nil {
		session.network.failure = err
		return err
	}
	return s.networkCurrent(ctx, session, true)
}

func (s *linuxStandardService) networkCurrent(ctx context.Context, session *linuxStandardServiceSession, required bool) error {
	if session == nil || s.session != session || session.owner == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("network observation lost its original service session")
	}
	n := session.network
	if n == nil {
		if required {
			return errors.New("standard service has no armed original network epoch")
		}
		return nil
	}
	if n.session != session || n.owner != session.owner || n.closed || n.lifetime == nil || n.lifetime.Err() != nil || n.observer == nil {
		return errors.New("network epoch lost its retained owner or reader")
	}
	if n.failure != nil {
		return n.failure
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.owner.namespaceCurrent(); err != nil {
		n.failure = err
		return err
	}
	if err := n.observer.CurrentContext(ctx); err != nil {
		n.failure = err
		return err
	}
	if s.session != session || session.network != n || session.owner != n.owner || ctx.Err() != nil {
		n.failure = errors.New("network readback changed its original session")
		return n.failure
	}
	if err := n.owner.namespaceCurrent(); err != nil {
		n.failure = err
		return err
	}
	return nil
}

// Retire only this session's original observer before its engine creates
// teardown notifications. An invalid proof does not grant cleanup authority;
// the existing original process/protection Stop still verifies that authority.
// A failed native Close keeps this object and the engine's cleanup owner.
func (s *linuxStandardService) closeNetwork(ctx context.Context, session *linuxStandardServiceSession) error {
	if session == nil || s.session != session || ctx == nil || ctx.Err() != nil {
		return errors.New("network retirement lost its original bounded session")
	}
	n := session.network
	if n == nil {
		return nil
	}
	if n.session != session || n.owner != session.owner {
		return errors.New("network retirement cannot close a replacement observer")
	}
	if n.closed {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.owner.namespaceCurrent(); err != nil {
		return err
	}
	if n.observer != nil {
		// Report an already latched invalidation before Close; it does not
		// prevent joining this exact reader or the original engine afterward.
		_ = n.observer.CurrentContext(ctx)
		if err := n.observer.Close(); err != nil {
			return err
		}
	}
	if s.session != session || session.network != n {
		return errors.New("network retirement lost its original session after join")
	}
	n.cancel()
	n.closed = true
	return ctx.Err()
}
