package mobilemultihop

import "context"

type nodeChainTrialRevocation struct {
	done chan struct{}
	err  error
}

// Both the lease-renewal monitor and Close cancel this trial before entering
// its terminal barrier. A second native revoke temporarily invalidates the
// first barrier's readback, including the guard on the original lease DELETE.
func (s *nodeChainExecutionTrial) revokeTerminal(ctx context.Context) (*nodeChainTrialRevocation, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.runtime.mu.Lock()
		current := s.runtime.active == s
		s.runtime.mu.Unlock()
		if !current || s.lifetime.Err() == nil {
			return nil, nodeChainExecutionError
		}
		s.mu.Lock()
		pending := s.terminalRevoke
		if pending == nil {
			pending = &nodeChainTrialRevocation{done: make(chan struct{})}
			s.terminalRevoke = pending
			s.mu.Unlock()
			err := s.runtime.engine.RevokeApplicationContext(ctx)
			if err == nil {
				err = ctx.Err()
			}
			s.mu.Lock()
			pending.err = err
			if err != nil {
				s.terminalRevoke = nil
			}
			close(pending.done)
			s.mu.Unlock()
			return pending, err
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			if pending.err == nil {
				return pending, ctx.Err()
			}
			// The failed caller reports its own error. This waiter still owns
			// its independent deadline and may retry the original native guard.
		}
	}
}
