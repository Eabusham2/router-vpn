//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobiletor"
)

// This owner proves process retirement only. Native PF/journal retirement
// belongs to the enclosing host, which must finish before releasing it.
type desktopMacOSProcess struct {
	parent             *desktopMacOSSessionCapture
	scope              macosprocess.Scope
	capture            *macosprocess.Capture
	channel            *mobiletor.DesktopDarwinControl
	bootstrap          *macosprocess.Bootstrap
	command            *exec.Cmd
	childChannel       *os.File
	gate               chan struct{}
	joined             chan struct{}
	started, retiring  atomic.Bool
	stopLifetime       func() bool
	waitErr            error // Read only after joined closes; one command.Wait writer.
	closed             bool
	nativeAcknowledged bool
	nativeStopped      bool
	nativeStopErr      error
}

func desktopMacOSProcessArguments(scope macosprocess.Scope) []string {
	return []string{"routervpn-external", "--runtime-dir", scope.Workspace, "--session", scope.Session, "--physical-source-sha256", scope.Source, "--config-sha256", scope.Config, "--darwin-control", "inherited-v1"}
}
func startDesktopMacOSProcess(ctx context.Context, parent *desktopMacOSSessionCapture, scope macosprocess.Scope) (*desktopMacOSProcess, error) {
	return startDesktopMacOSProcessWithVerifier(ctx, parent, scope, verifyBundledNativeContext)
}

// Only complete package metadata/version verification has a fixture seam;
// fixed paths, native image identity, descriptors and child creation do not.
func startDesktopMacOSProcessWithVerifier(ctx context.Context, parent *desktopMacOSSessionCapture, scope macosprocess.Scope, verify func(context.Context, string) (string, error)) (*desktopMacOSProcess, error) {
	if ctx == nil || parent == nil || verify == nil {
		return nil, errors.New("macOS child requires its original captured application")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := parent.Current(ctx); err != nil {
		return nil, err
	}
	p := &desktopMacOSProcess{parent: parent, scope: scope, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	// The initially empty gate holds construction until every partial native
	// owner is published to this retained dependent. Parent close can wait for it.
	if err := parent.session.Retain(ctx, p); err != nil {
		return nil, err
	}
	defer func() { p.gate <- struct{}{} }()
	launch, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopParent := context.AfterFunc(parent.parent.ctx, cancel)
	defer func() { stopParent(); cancel() }()
	image, err := verify(launch, macOSOwnedControllerRoot)
	if err != nil {
		return p, err
	}
	if image != macosprocess.EnginePath {
		return p, errors.New("macOS child verifier returned another installed runtime path")
	}
	workspace, err := os.OpenFile(scope.Workspace, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return p, err
	}
	defer workspace.Close()
	controller := parent.controller
	p.capture, err = macosprocess.OpenCapture(launch, scope, workspace, controller.installLock, controller.processLock, controller.input)
	if err != nil {
		return p, err
	}
	// Join complete package verification to the retained image/catalog snapshot.
	if _, err = verify(launch, macOSOwnedControllerRoot); err != nil {
		return p, err
	}
	if err = p.capture.Current(launch); err != nil {
		return p, err
	}
	if err = parent.Current(launch); err != nil {
		return p, err
	}
	p.channel, p.childChannel, err = mobiletor.NewDesktopDarwinControlPair()
	if err != nil {
		return p, err
	}
	p.command = exec.Command(macosprocess.EnginePath, desktopMacOSProcessArguments(scope)...)
	p.command.Dir, p.command.Env = scope.Workspace, macOSOwnedEnvironment()
	p.command.Stdout, p.command.Stderr = os.Stdout, os.Stderr
	p.command.ExtraFiles = append([]*os.File{p.childChannel}, p.capture.Files()...)
	if err = p.command.Start(); err != nil {
		return p, err
	}
	p.started.Store(true)
	// Exactly one waiter owns this actual created command for its whole life.
	go func() { p.waitErr = p.command.Wait(); close(p.joined) }()
	p.stopLifetime = context.AfterFunc(parent.parent.ctx, func() {
		p.retiring.Store(true)
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Close(cleanup)
	})
	if err = p.childChannel.Close(); err != nil {
		return p, err
	}
	p.childChannel = nil
	p.bootstrap, err = macosprocess.BindCreated(launch, p.capture, p.channel, p.command)
	if err != nil {
		return p, err
	}
	if err = parent.Current(launch); err != nil {
		return p, err
	}
	return p, p.currentLocked(launch)
}
func (p *desktopMacOSProcess) enter(ctx context.Context) error {
	if p == nil || ctx == nil || p.gate == nil {
		return errors.New("macOS child has no bounded original owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
		if err := ctx.Err(); err != nil {
			p.gate <- struct{}{}
			return err
		}
		return nil
	}
}
func (p *desktopMacOSProcess) currentLocked(ctx context.Context) error {
	if p.closed || p.retiring.Load() || !p.started.Load() || p.bootstrap == nil {
		return errors.New("macOS child has no live captured handshake")
	}
	select {
	case <-p.joined:
		return errors.New("macOS child has already exited")
	default:
	}
	if err := p.parent.Current(ctx); err != nil {
		return err
	}
	return p.bootstrap.Current(ctx)
}
func (p *desktopMacOSProcess) Current(ctx context.Context) error {
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	return p.currentLocked(ctx)
}

// StopAndJoin requires the native child cleanup acknowledgment before final
// release, then joins the actual sole waiter. Failure remains owned for Close;
// forced Close alone must never settle a PF lease or protection transaction.
func (p *desktopMacOSProcess) StopAndJoin(ctx context.Context) error {
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	return p.stopAndJoinLocked(ctx)
}
func (p *desktopMacOSProcess) stopAndJoinLocked(ctx context.Context) error {
	if p.nativeStopped {
		return p.waitErr
	}
	if p.closed || !p.started.Load() || p.bootstrap == nil {
		return errors.New("macOS native cleanup lacks its original completed child handshake")
	}
	// Cancellation/replacement revokes admission, not the original cleanup
	// capability. Bootstrap independently rechecks both native main images,
	// private inputs and inherited locks before the exact stop exchange.
	p.retiring.Store(true)
	if !p.nativeAcknowledged {
		if err := p.bootstrap.Stop(ctx); err != nil {
			p.nativeStopErr = err
			return err
		}
		p.nativeAcknowledged = true
	}
	select {
	case <-ctx.Done():
		p.nativeStopErr = ctx.Err()
		return ctx.Err()
	case <-p.joined:
	}
	if p.waitErr != nil {
		p.nativeStopErr = p.waitErr
		return p.waitErr
	}
	p.nativeStopped = true
	return nil
}

// NativeCleanup proves both the authenticated native cleanup receipt and its
// original successful child waiter. Forced Close alone never satisfies it.
func (p *desktopMacOSProcess) NativeCleanup(ctx context.Context) error {
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if !p.nativeStopped {
		return errors.Join(p.nativeStopErr, errors.New("macOS runtime has no joined native cleanup acknowledgment"))
	}
	select {
	case <-p.joined:
		return p.waitErr
	default:
		return errors.New("macOS runtime cleanup has not joined its original child")
	}
}

func (p *desktopMacOSProcess) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.closed {
		return nil
	}
	p.retiring.Store(true)
	if p.started.Load() && p.bootstrap != nil && !p.nativeStopped {
		// A failed/ambiguous stop remains recorded separately. This method
		// may subsequently prove process exit, never native PF retirement.
		_ = p.stopAndJoinLocked(ctx)
	}
	if p.channel != nil {
		_ = p.channel.Close()
	}
	if p.started.Load() {
		select {
		case <-p.joined:
		default:
			if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.joined:
		}
	}
	if p.stopLifetime != nil {
		p.stopLifetime()
		p.stopLifetime = nil
	}
	if p.childChannel != nil {
		if err := p.childChannel.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		p.childChannel = nil
	}
	if p.capture != nil {
		if err := p.capture.Close(); err != nil {
			return err
		}
	}
	p.closed = true
	return nil
}
