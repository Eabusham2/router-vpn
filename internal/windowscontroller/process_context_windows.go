//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"syscall"
)

func (p *Process) borrowContext(ctx context.Context) (syscall.Handle, func(), error) {
	if p == nil {
		return 0, nil, ErrClosed
	}
	if err := lockObservation(ctx, &p.mu); err != nil {
		return 0, nil, err
	}
	defer p.mu.Unlock()
	if p.closing || p.handle == 0 {
		return 0, nil, ErrClosed
	}
	p.operations.Add(1)
	return p.handle, p.operations.Done, nil
}
func (p *Process) AliveContext(ctx context.Context) error {
	handle, release, err := p.borrowContext(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := syscall.WaitForSingleObject(handle, 0)
	if err != nil {
		return errors.Join(err, ctx.Err())
	}
	if status != syscall.WAIT_TIMEOUT {
		return errors.Join(errors.New("captured Windows controller process is no longer live"), ctx.Err())
	}
	return ctx.Err()
}
func (child *GUIChild) AliveContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Windows child observation omitted caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if child == nil || child.process == nil || child.retiring.Load() {
		return ErrClosed
	}
	if err := child.process.AliveContext(ctx); err != nil {
		return err
	}
	if child.retiring.Load() {
		return errors.Join(ErrClosed, ctx.Err())
	}
	return ctx.Err()
}

// Token readback consists of finite kernel queries. The caller is checked on
// both sides, with genuine token failures retained if expiry races the query.
func CurrentIdentityContext(ctx context.Context) (TokenIdentity, error) {
	if ctx == nil {
		return TokenIdentity{}, errors.New("Windows token observation omitted caller")
	}
	if err := ctx.Err(); err != nil {
		return TokenIdentity{}, err
	}
	identity, err := currentIdentity()
	return identity, errors.Join(err, ctx.Err())
}
