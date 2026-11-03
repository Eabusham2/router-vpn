//go:build darwin

package macosprocess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"

	"router-vpn/internal/mobiletor"
)

// Bootstrap authenticates only the retained native controller/engine and
// private inputs. It grants no PF rights and supplies no firewall retirement
// receipt. The app still owns the actual command waiter and native policies.
type Bootstrap struct {
	capture                    *Capture
	protocol                   protocol
	parent, child              Identity
	parentSide                 bool
	gate                       chan struct{}
	complete, stopped, revoked atomic.Bool
	closed                     atomic.Bool
}

func bind(ctx context.Context, capture *Capture, channel *mobiletor.DesktopDarwinControl, parentPID, childPID int, parentSide bool) (*Bootstrap, error) {
	b := &Bootstrap{capture: capture, parentSide: parentSide, gate: make(chan struct{}, 1)}
	b.gate <- struct{}{}
	b.protocol = protocol{channel: channel, current: b.current}
	if capture == nil || channel == nil || parentPID <= 1 || childPID <= 1 || parentPID == childPID {
		return b, errors.New("native bootstrap lacks its distinct original tasks")
	}
	b.protocol.selection = capture.Selection()
	b.protocol.peer = uint32(parentPID)
	if parentSide {
		b.protocol.peer = uint32(childPID)
	}
	var err error
	b.parent, err = CaptureIdentity(parentPID)
	if err != nil {
		return b, err
	}
	b.child, err = CaptureIdentity(childPID)
	if err != nil {
		return b, err
	}
	if !b.parent.Matches(capture.controller) || !b.child.Matches(capture.engine) {
		return b, errors.New("native child or controller main image differs from its own captured installed image")
	}
	if err = b.current(ctx); err != nil {
		return b, err
	}
	if parentSide {
		err = handshakeParent(ctx, &b.protocol)
	} else {
		err = handshakeChild(ctx, &b.protocol)
	}
	if err != nil {
		b.revoked.Store(true)
		return b, err
	}
	b.complete.Store(true)
	return b, nil
}

// BindCreated requires the application's actual successful exec.Cmd.Start.
// The command's one Wait goroutine remains exclusively with that application.
func BindCreated(ctx context.Context, capture *Capture, channel *mobiletor.DesktopDarwinControl, command *exec.Cmd) (*Bootstrap, error) {
	if command == nil || command.Process == nil || command.Path != EnginePath || command.Dir != captureWorkspace(capture) {
		return nil, errors.New("native bootstrap did not receive its fixed created runtime command")
	}
	return bind(ctx, capture, channel, os.Getpid(), command.Process.Pid, true)
}
func captureWorkspace(c *Capture) string {
	if c == nil {
		return ""
	}
	return c.scope.Workspace
}

// BindInherited uses the actual OS parent and self, not decoded wire PIDs.
// It consumes FD3 only after the fixed input descriptors have been captured.
func BindInherited(ctx context.Context, capture *Capture) (*Bootstrap, error) {
	channel, err := mobiletor.CaptureDesktopDarwinControl()
	if err != nil {
		return nil, err
	}
	b, err := bind(ctx, capture, channel, os.Getppid(), os.Getpid(), false)
	if err != nil {
		_ = channel.Close()
	}
	return b, err
}
func (b *Bootstrap) enter(ctx context.Context) error {
	if b == nil || ctx == nil || b.gate == nil {
		return errors.New("native child bootstrap has no bounded owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
		if err := ctx.Err(); err != nil {
			b.gate <- struct{}{}
			return err
		}
		return nil
	}
}
func (b *Bootstrap) current(ctx context.Context) error {
	if b.closed.Load() || b.revoked.Load() || b.stopped.Load() || b.capture == nil || !b.parent.Valid() || !b.child.Valid() {
		return errors.New("native bootstrap has no current original image capture")
	}
	if ctx == nil {
		return errors.New("native bootstrap requires an owner context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.capture.Current(ctx); err != nil {
		return err
	}
	parent, err := CaptureIdentity(b.parent.PID)
	if err != nil || parent != b.parent {
		return errors.Join(err, errors.New("native bootstrap lost its original controller process or exec"))
	}
	child, err := CaptureIdentity(b.child.PID)
	if err != nil || child != b.child {
		return errors.Join(err, errors.New("native bootstrap lost its original runtime process or exec"))
	}
	return ctx.Err()
}
func (b *Bootstrap) Current(ctx context.Context) error {
	if b == nil || ctx == nil {
		return errors.New("native child bootstrap has no bounded owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !b.complete.Load() {
		return errors.New("native child has not completed its original handshake")
	}
	// Readback does not wait behind an idle stop receiver. Immutable capture
	// files remain held until the actual creator joins this process.
	err := b.current(ctx)
	if err != nil && ctx.Err() == nil {
		b.revoked.Store(true)
	}
	return err
}

func (b *Bootstrap) Stop(ctx context.Context) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete.Load() || !b.parentSide || b.stopped.Load() {
		return errors.New("native stop has no current original creator handshake")
	}
	err := b.protocol.stop(ctx)
	if err != nil {
		b.revoked.Store(true)
		return err
	}
	b.stopped.Store(true)
	return nil
}
func (b *Bootstrap) WaitStop(ctx context.Context, closeNative func(context.Context) error) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete.Load() || b.parentSide || b.stopped.Load() {
		return errors.New("native cleanup has no current inherited handshake")
	}
	err := b.protocol.waitStop(ctx, closeNative)
	if err != nil {
		b.revoked.Store(true)
		return err
	}
	b.stopped.Store(true)
	return nil
}

// Close interrupts the private transport, never closes capture files or
// claims that native cleanup or the actual child waiter has completed.
func (b *Bootstrap) Close() error {
	if b == nil {
		return nil
	}
	b.closed.Store(true)
	if b.protocol.channel != nil {
		return b.protocol.channel.Close()
	}
	return nil
}
