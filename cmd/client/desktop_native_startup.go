package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// This immutable admission belongs to one accepted launch. Proof observation
// may borrow its remainder but cannot restart or extend its work allowance.
type desktopNativeStartup struct {
	launch    *desktopNodeLaunch
	operation context.Context
	work      context.Context
	stop      context.CancelFunc
	admission mobilemultihop.DesktopStartupAdmission
	raw       string
}

func desktopNativeStartupBinding(ctx context.Context, launch *desktopNodeLaunch) (kind, session, source, config string, err error) {
	if launch == nil {
		return "", "", "", "", errors.New("native startup has no captured launch")
	}
	if launch.tor != nil {
		owner := launch.tor
		if err = desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
			return
		}
		defer owner.mu.Unlock()
		return "tor", owner.expected.SessionID, owner.expected.SourceSHA256, owner.expected.ConfigSHA256, ctx.Err()
	}
	if launch.external != nil {
		owner := launch.external
		if err = desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
			return
		}
		defer owner.mu.Unlock()
		return "external", owner.session, owner.expected.SourceSHA256, owner.expected.ConfigSHA256, ctx.Err()
	}
	return "", "", "", "", errors.New("native startup launch is not an external or Tor capture")
}
func captureDesktopNativeStartup(operation context.Context, launch *desktopNodeLaunch) (context.Context, error) {
	if operation == nil || launch == nil {
		return nil, errors.New("native startup has no original operation")
	}
	if err := operation.Err(); err != nil {
		return nil, err
	}
	if previous := launch.startup.Load(); previous != nil {
		if previous.launch != launch || previous.operation != operation {
			return nil, errors.New("native startup cannot borrow another operation")
		}
		return previous.work, previous.current(previous.work)
	}
	budget := 180 * time.Second
	if launch.tor != nil {
		budget = 150 * time.Second
	}
	work, stop := context.WithTimeout(operation, budget)
	kind, session, source, config, err := desktopNativeStartupBinding(work, launch)
	if err != nil {
		stop()
		return nil, err
	}
	deadline, _ := work.Deadline()
	admission, err := mobilemultihop.NewDesktopStartupAdmission(kind, session, source, config, deadline)
	if err != nil {
		stop()
		return nil, err
	}
	raw, err := admission.Canonical()
	if err != nil {
		stop()
		return nil, err
	}
	captured := &desktopNativeStartup{launch: launch, operation: operation, work: work, stop: stop, admission: admission, raw: raw}
	if err := work.Err(); err != nil {
		stop()
		return nil, err
	}
	if !launch.startup.CompareAndSwap(nil, captured) {
		stop()
		return captureDesktopNativeStartup(operation, launch)
	}
	return work, work.Err()
}
func (s *desktopNativeStartup) current(ctx context.Context) error {
	if s == nil || s.launch == nil {
		return errors.New("native startup lost original admission")
	}
	if err := s.work.Err(); err != nil {
		return err
	}
	kind, session, source, config, err := desktopNativeStartupBinding(ctx, s.launch)
	if err != nil {
		return err
	}
	if _, err = mobilemultihop.ParseDesktopStartupAdmission(s.raw, kind, session, source, config); err != nil {
		return err
	}
	return errors.Join(ctx.Err(), s.work.Err())
}
func desktopNativeStartupEnvironment(ctx context.Context, launch *desktopNodeLaunch, environment []string) ([]string, error) {
	if launch == nil {
		return nil, errors.New("native startup environment has no launch")
	}
	captured := launch.startup.Load()
	if captured == nil {
		return nil, errors.New("native startup environment preceded admission")
	}
	if err := captured.current(ctx); err != nil {
		return nil, err
	}
	return envWithValue(environment, mobilemultihop.DesktopStartupAdmissionEnvironment, captured.raw), nil
}
func desktopNativeStartupObservation(parent context.Context, launch *desktopNodeLaunch) (context.Context, context.CancelFunc, error) {
	if parent == nil || launch == nil {
		return nil, nil, errors.New("native proof has no original startup")
	}
	captured := launch.startup.Load()
	if captured == nil {
		return nil, nil, errors.New("native proof preceded accepted startup")
	}
	ctx, cancel := context.WithDeadline(parent, time.Unix(0, captured.admission.DeadlineNS))
	stop := context.AfterFunc(captured.work, func() {
		// The observer already has this exact deadline. Turning its expiration
		// into Cancel would race that timer and erase DeadlineExceeded.
		if captured.work.Err() != context.DeadlineExceeded {
			cancel()
		}
	})
	done := func() { stop(); cancel() }
	if err := captured.current(ctx); err != nil {
		done()
		return nil, nil, err
	}
	return ctx, done, nil
}

func (a *app) checkNativeStartupConnectionContext(ctx context.Context) error {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.controllerClosingLocked() || a.connectionContext != nil && a.connectionContext.Err() != nil {
		return errConnectionOperationCancelled
	}
	return ctx.Err()
}
