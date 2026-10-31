//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"net"
)

// ObserveJoinedSource is available only through this exact original source
// after Close has joined its actual helper, monitor and native witnesses.
// For an incomplete constructor it reports no fabricated guardian birth or
// baseline identity. The parent must independently observe its original
// closed baseline and join the engine before a preparation can roll back.
func (p *DesktopLinuxSocketPolicy) ObserveJoinedSource(ctx context.Context, capture DesktopSocketCapture) (DesktopLinuxSourceJoinRecord, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture {
		return DesktopLinuxSourceJoinRecord{}, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.nativeGuardian
	if w == nil || p.command == nil || p.command.Process == nil || p.command.Process.Pid < 1 ||
		!p.closing.Load() || !desktopLinuxJoined(p.joined) || !desktopLinuxJoined(p.monitorDone) ||
		p.nft != nil && !p.closeAcknowledged.Load() {
		return DesktopLinuxSourceJoinRecord{}, errors.New("Linux source has not joined its exact created guardian")
	}
	if err := w.enter(ctx); err != nil {
		return DesktopLinuxSourceJoinRecord{}, err
	}
	defer func() { w.gate <- struct{}{} }()
	if !w.closed || w.closeErr != nil || w.child != nil || w.parent != nil || w.pidfd != nil || w.directory != nil {
		return DesktopLinuxSourceJoinRecord{}, errors.New("Linux source still owns unjoined native witnesses")
	}
	record := DesktopLinuxSourceJoinRecord{Capture: capture, ProcessID: uint32(p.command.Process.Pid)}
	if w.complete {
		original := w.record
		record.Original = &original
	}
	if err := record.Validate(); err != nil || ctx.Err() != nil {
		return DesktopLinuxSourceJoinRecord{}, errors.Join(err, ctx.Err())
	}
	return record, nil
}
