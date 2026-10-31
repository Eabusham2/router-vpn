//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"
)

// DesktopLinuxProtectionOwner is a non-serializable capability retained from
// one actual unused guardian source. A journal's readback record cannot create
// it. Disconnect follows the captured On-connect/Always selection; Release is
// reserved for the authenticated parent's explicit removal transaction.
// Close joins only this capability's native descriptors and preserves any
// remaining fail-closed table, including an unknown mutation outcome.
type DesktopLinuxProtectionOwner interface {
	Prepared(context.Context) (DesktopLinuxProtectionRecord, error)
	Retired(context.Context) (DesktopLinuxProtectionRecord, error)
	Disconnect(context.Context) (bool, error)
	Release(context.Context) error
	Close(context.Context) error
}

type desktopLinuxRetainedProtection struct {
	gate                      chan struct{}
	source                    *DesktopLinuxSocketPolicy
	capture                   DesktopSocketCapture
	policy                    string
	record                    DesktopLinuxProtectionRecord
	netlink                   *desktopLinuxBaselineNetlink
	namespace                 *os.File
	namespaceInfo             os.FileInfo
	complete, removed, closed bool
	uncertain, closeErr       error
}

// RetainProtection must run before this source has created any socket. Even a
// partial return remains owned and closeable; this source cannot issue a
// second capability. The netlink socket and namespace descriptor are opened
// on the same native thread before generation-bracketed preparation readback.
func (p *DesktopLinuxSocketPolicy) RetainProtection(ctx context.Context, capture DesktopSocketCapture, policy string) (DesktopLinuxProtectionOwner, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture || !capture.valid() || (policy != "on-connect" && policy != "always") {
		return nil, errors.New("Linux protection retention requires its exact live source and selected policy")
	}
	p.mu.Lock()
	if p.protectionRetention != nil || !p.Current(capture, p.owner) || p.socketActivity || p.closeAcknowledged.Load() {
		p.mu.Unlock()
		return nil, errors.New("Linux protection retention cannot replace or reuse its original unused source")
	}
	b := &desktopLinuxRetainedProtection{gate: make(chan struct{}, 1), source: p, capture: capture, policy: policy}
	p.protectionRetention = b
	p.mu.Unlock()
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var err error
	b.namespace, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return b, err
	}
	b.namespaceInfo, err = b.namespace.Stat()
	if err != nil {
		return b, err
	}
	b.netlink, err = desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return b, err
	}
	record, _, err := b.observe(ctx, true)
	if err != nil {
		return b, err
	}
	b.record, b.complete = record, true
	return b, nil
}

func (b *desktopLinuxRetainedProtection) enter(ctx context.Context) error {
	if b == nil || b.gate == nil || ctx == nil || ctx.Err() != nil {
		return net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
		return nil
	}
}

func (b *desktopLinuxRetainedProtection) currentNamespace(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || b.closed || b.source == nil || b.netlink == nil || b.namespace == nil || b.namespaceInfo == nil || b.uncertain != nil {
		return errors.Join(b.uncertain, net.ErrClosed)
	}
	retained, err := b.namespace.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if err != nil || currentErr != nil || !os.SameFile(retained, b.namespaceInfo) || !os.SameFile(current, b.namespaceInfo) {
		return errors.Join(err, currentErr, errors.New("Linux protection left its original retained network namespace"))
	}
	return ctx.Err()
}

// The operation's native thread and capability gate remain held throughout.
// A ruleset change during the independent nft read invalidates this snapshot;
// a change after it is rejected by the kernel's conditional delete batch.
func (b *desktopLinuxRetainedProtection) observe(ctx context.Context, prepared bool) (DesktopLinuxProtectionRecord, uint32, error) {
	if err := b.currentNamespace(ctx); err != nil || b.removed {
		return DesktopLinuxProtectionRecord{}, 0, errors.Join(err, errors.New("Linux protection has no retained original baseline"))
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return DesktopLinuxProtectionRecord{}, 0, err
	}
	var record DesktopLinuxProtectionRecord
	if prepared {
		record, err = b.source.ObservePreparedProtection(ctx, b.capture)
	} else {
		record, err = b.source.ObserveRetiredProtection(ctx, b.capture)
	}
	if err != nil || record.Validate() != nil || record.Capture != b.capture || b.complete && record != b.record {
		return DesktopLinuxProtectionRecord{}, 0, errors.Join(err, errors.New("Linux protection changed its original captured source or closed baseline"))
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return DesktopLinuxProtectionRecord{}, 0, errors.Join(err, errors.New("Linux protection changed during its native generation snapshot"))
	}
	return record, after, nil
}

func (b *desktopLinuxRetainedProtection) observation(ctx context.Context, prepared bool) (DesktopLinuxProtectionRecord, error) {
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete {
		return DesktopLinuxProtectionRecord{}, errors.New("Linux protection retention did not finish its native capture")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	record, _, err := b.observe(ctx, prepared)
	return record, err
}

func (b *desktopLinuxRetainedProtection) Prepared(ctx context.Context) (DesktopLinuxProtectionRecord, error) {
	return b.observation(ctx, true)
}

func (b *desktopLinuxRetainedProtection) Retired(ctx context.Context) (DesktopLinuxProtectionRecord, error) {
	return b.observation(ctx, false)
}

func (b *desktopLinuxRetainedProtection) Disconnect(ctx context.Context) (bool, error) {
	if b == nil {
		return false, net.ErrClosed
	}
	if b.policy == "always" {
		_, err := b.Retired(ctx)
		return err == nil, err
	}
	if b.policy != "on-connect" {
		return false, errors.New("Linux protection lost its captured disconnect policy")
	}
	return false, b.Release(ctx)
}

func (b *desktopLinuxRetainedProtection) proveAbsence(ctx context.Context) error {
	if !b.removed {
		return errors.New("Linux protection has no acknowledged original removal")
	}
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	if rows, err := desktopLinuxNFTReadTable(ctx, b.source.nft.table()); err != nil || len(rows) != 0 {
		return errors.Join(err, errors.New("Linux original protection table is not absent"))
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return errors.Join(err, errors.New("Linux protection absence changed during its native generation snapshot"))
	}
	return nil
}

func (b *desktopLinuxRetainedProtection) Release(ctx context.Context) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete {
		return errors.New("Linux protection cannot remove an incompletely captured baseline")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if b.removed {
		// A late cancellation/readback failure never grants a second delete.
		return b.proveAbsence(ctx)
	}
	_, generation, err := b.observe(ctx, false)
	if err != nil {
		return err
	}
	acknowledged, sent, err := b.netlink.delete(ctx, generation, b.record.TableHandle)
	if acknowledged {
		b.removed = true
	}
	var rejection syscall.Errno
	if sent && !acknowledged && !errors.As(err, &rejection) {
		b.uncertain = errors.Join(err, errors.New("Linux protection retained an unknown native removal outcome"))
	}
	if err != nil {
		return err
	}
	if !acknowledged {
		return errors.New("Linux protection removal has no native commit acknowledgement")
	}
	return b.proveAbsence(ctx)
}

func (b *desktopLinuxRetainedProtection) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.closed {
		return b.closeErr
	}
	if err := b.netlink.close(); err != nil {
		b.closeErr = errors.Join(b.closeErr, err)
	}
	if b.namespace != nil {
		if err := b.namespace.Close(); err != nil {
			b.closeErr = errors.Join(b.closeErr, err)
		} else {
			b.namespace = nil
		}
	}
	if b.closeErr == nil {
		b.closed = true
	}
	return b.closeErr
}
