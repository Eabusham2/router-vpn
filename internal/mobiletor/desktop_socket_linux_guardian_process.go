//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"net"
	"os"

	"router-vpn/internal/linuxprocess"
)

// The source owns this clone-created pidfd even before preparation returns.
// The guardian supplies its own original proc directory on the authenticated
// channel; no numeric-PID lookup or decoded record creates a witness.
type desktopLinuxGuardianProcess struct {
	gate             chan struct{}
	parent           *linuxprocess.Witness
	child            *linuxprocess.CreatedWitness
	pidfd, directory *os.File
	record           DesktopLinuxGuardianRecord
	complete, closed bool
	closeErr         error
}

func desktopLinuxNewGuardianProcess(pidfd int) *desktopLinuxGuardianProcess {
	w := &desktopLinuxGuardianProcess{gate: make(chan struct{}, 1)}
	w.gate <- struct{}{}
	if pidfd >= 0 {
		w.pidfd = os.NewFile(uintptr(pidfd), "routervpn-original-guardian-pidfd")
	}
	return w
}

func (w *desktopLinuxGuardianProcess) enter(ctx context.Context) error {
	if w == nil || w.gate == nil || ctx == nil || ctx.Err() != nil {
		return net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.gate:
		return nil
	}
}

func (w *desktopLinuxGuardianProcess) capture(ctx context.Context, createdPID int) error {
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { w.gate <- struct{}{} }()
	if w.closed || w.complete || w.parent != nil || w.child != nil || w.pidfd == nil || w.directory == nil || createdPID < 1 {
		return errors.New("Linux guardian requires its unused clone and original transferred task directory")
	}
	var err error
	w.parent, err = linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return err
	}
	w.record.Engine, err = w.parent.Current(ctx)
	if err != nil {
		return err
	}
	task, taskErr := linuxprocess.CaptureDirectory(ctx, w.directory, createdPID)
	w.directory = nil // CaptureDirectory consumes even a partial result.
	w.child, err = linuxprocess.CaptureCreated(ctx, w.pidfd, task, w.parent, w.record.Engine.Image)
	w.pidfd = nil // CaptureCreated consumes both partial native owners.
	if err != nil || taskErr != nil {
		return errors.Join(err, taskErr)
	}
	w.record.Guardian, err = w.child.Current(ctx)
	if err != nil || w.record.Validate() != nil {
		return errors.Join(err, errors.New("Linux guardian changed its original native creation relationship"))
	}
	if actual, err := w.parent.Current(ctx); err != nil || actual != w.record.Engine || ctx.Err() != nil {
		return errors.Join(err, ctx.Err(), errors.New("Linux guardian lost its original engine during capture"))
	}
	w.complete = true
	return nil
}

func (w *desktopLinuxGuardianProcess) observe(ctx context.Context, retired bool) (DesktopLinuxGuardianRecord, error) {
	if err := w.enter(ctx); err != nil {
		return DesktopLinuxGuardianRecord{}, err
	}
	defer func() { w.gate <- struct{}{} }()
	if !w.complete || w.closeErr != nil || w.closed != retired || w.record.Validate() != nil {
		return DesktopLinuxGuardianRecord{}, errors.New("Linux guardian observation lost its original capture or acknowledged retirement")
	}
	if !retired {
		engine, engineErr := w.parent.Current(ctx)
		guardian, guardianErr := w.child.Current(ctx)
		if engineErr != nil || guardianErr != nil || engine != w.record.Engine || guardian != w.record.Guardian {
			return DesktopLinuxGuardianRecord{}, errors.Join(engineErr, guardianErr, errors.New("Linux guardian changed its retained native witnesses"))
		}
	}
	return w.record, ctx.Err()
}

func (w *desktopLinuxGuardianProcess) close(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { w.gate <- struct{}{} }()
	if w.closed {
		return w.closeErr
	}
	if w.child != nil {
		if err := w.child.Close(ctx); err != nil {
			return err
		}
		w.child = nil
	}
	if w.parent != nil {
		if err := w.parent.Close(ctx); err != nil {
			return err
		}
		w.parent = nil
	}
	for _, file := range []**os.File{&w.directory, &w.pidfd} {
		if *file != nil {
			if err := (*file).Close(); err != nil {
				w.closeErr = errors.Join(w.closeErr, err)
				return w.closeErr
			}
			*file = nil
		}
	}
	if w.closeErr != nil {
		return w.closeErr
	}
	w.closed = true
	return nil
}

// ObservePreparedGuardian runs through the same original unused source as its
// prepared nft inventory. A live process record from another Node source is
// never an interchangeable guardian proof.
func (p *DesktopLinuxSocketPolicy) ObservePreparedGuardian(ctx context.Context, capture DesktopSocketCapture) (DesktopLinuxGuardianRecord, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture {
		return DesktopLinuxGuardianRecord{}, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nativeGuardian == nil || p.nft == nil || p.nft.TableName != desktopLinuxNodeTable(capture) || !p.Current(capture, p.owner) || p.socketActivity || p.closeAcknowledged.Load() {
		return DesktopLinuxGuardianRecord{}, errors.New("Linux guardian proof requires its unused live Node source")
	}
	record, err := p.nativeGuardian.observe(ctx, false)
	if err != nil || uint32(record.Guardian.ProcessID) != p.owner.ProcessID || !p.Current(capture, p.owner) || ctx.Err() != nil {
		return DesktopLinuxGuardianRecord{}, errors.Join(err, ctx.Err(), errors.New("Linux guardian proof lost its original source owner"))
	}
	return record, nil
}

// ObserveRetiredGuardian is valid only after the actual source has joined its
// guardian/monitor, removed its permits, and closed these original witnesses.
// It reports that captured process, not a newly opened replacement by PID.
func (p *DesktopLinuxSocketPolicy) ObserveRetiredGuardian(ctx context.Context, capture DesktopSocketCapture) (DesktopLinuxGuardianRecord, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture {
		return DesktopLinuxGuardianRecord{}, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nativeGuardian == nil || !p.closeAcknowledged.Load() || !p.closing.Load() || !desktopLinuxJoined(p.joined) || !desktopLinuxJoined(p.monitorDone) {
		return DesktopLinuxGuardianRecord{}, errors.New("Linux guardian retirement requires its acknowledged original source join")
	}
	return p.nativeGuardian.observe(ctx, true)
}
