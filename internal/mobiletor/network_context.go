package mobiletor

import (
	"context"
	"sync"
	"time"
)

// A caller owns cancellation only while its socket is being opened. Some
// native detours retain the passed context for their established stream, so
// canceling a temporary dial context on successful return would kill that
// stream. Publication transfers that lifetime to the socket and VPN session.
type networkContext struct {
	context.Context
	caller       context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	published    bool
	stop         func() bool
	callbackDone chan struct{}
	stopOnce     sync.Once
	releaseOnce  sync.Once
}

func (n *Network) operationContext(caller context.Context) *networkContext {
	ctx, cancel := context.WithCancel(n.ctx)
	s := &networkContext{Context: ctx, caller: caller, cancel: cancel, callbackDone: make(chan struct{})}
	s.stop = context.AfterFunc(caller, func() {
		s.mu.Lock()
		if !s.published {
			s.cancel()
		}
		s.mu.Unlock()
		close(s.callbackDone)
	})
	return s
}

func (s *networkContext) Value(key any) any { return s.caller.Value(key) }

func (s *networkContext) Err() error {
	err := s.Context.Err()
	if err == nil {
		return nil
	}
	s.mu.Lock()
	published := s.published
	s.mu.Unlock()
	if !published {
		if callerErr := s.caller.Err(); callerErr != nil {
			return callerErr
		}
	}
	return err
}

func (s *networkContext) Deadline() (time.Time, bool) {
	s.mu.Lock()
	published := s.published
	s.mu.Unlock()
	if !published {
		if deadline, ok := s.caller.Deadline(); ok {
			if own, hasOwn := s.Context.Deadline(); !hasOwn || deadline.Before(own) {
				return deadline, true
			}
		}
	}
	return s.Context.Deadline()
}

func (s *networkContext) stopCaller() {
	s.stopOnce.Do(func() {
		if !s.stop() {
			<-s.callbackDone
		}
	})
}

func (s *networkContext) publish() error {
	s.mu.Lock()
	err := s.caller.Err()
	if err == nil {
		err = s.Context.Err()
	}
	if err == nil {
		s.published = true
	}
	s.mu.Unlock()
	// Joining a callback here prevents a retired caller from modifying the
	// established stream after ownership has transferred to its socket.
	s.stopCaller()
	return err
}

func (s *networkContext) release() {
	s.releaseOnce.Do(func() {
		s.cancel()
		s.stopCaller()
	})
}
