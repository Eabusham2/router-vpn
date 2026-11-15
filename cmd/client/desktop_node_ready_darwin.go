//go:build darwin

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
	"time"
)

func desktopMacOSPairedNodeTUNCurrent(ctx context.Context, live desktopNodeMTURecord) error {
	link, _, err := desktopnetwork.InterfaceContext(ctx, live.Index)
	if err != nil {
		return err
	}
	return validateDesktopMacOSNodeChainInterface(live, link)
}

func (h *desktopMacOSPairedNodeHost) readReadyLocked(ctx context.Context, fresh bool) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	var empty mobilemultihop.DesktopNodeReadyRecord
	var none desktopNodeMTURecord
	if err := h.current(ctx, true); err != nil {
		return empty, none, err
	}
	transfer, err := macosprocess.NodeTransferSHA256(h.process.capture.Selection())
	if err != nil || h.transfer != "" && h.transfer != transfer {
		return empty, none, errors.Join(err, errors.New("macOS paired Node readiness changed its original inherited capture"))
	}
	raw, err := readDesktopRuntimeFileContext(ctx, h.launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
	if err != nil {
		return empty, none, err
	}
	record, err := mobilemultihop.ParseDesktopNodeReadyRecord(raw, h.policy, transfer)
	if err != nil {
		return empty, none, err
	}
	live, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return empty, none, err
	}
	if err := validateDesktopMacOSPairedNodeReady(record, live, h.started, time.Now(), h.ready, fresh); err != nil {
		return empty, none, err
	}
	if err := desktopMacOSPairedNodeTUNCurrent(ctx, live); err != nil {
		return empty, none, err
	}
	if err := h.current(ctx, true); err != nil {
		return empty, none, err
	}
	if h.reader != nil && (h.reader.Interface != live.Interface || h.reader.Index != live.Index || h.reader.Reader != live.Reader || h.reader.Path != live.Path) {
		return empty, none, errors.New("macOS Node readback has no admitted original reader succession")
	}
	copyLive := live
	h.reader = &copyLive
	copy := record
	h.ready = &copy
	h.transfer = transfer
	return record, live, nil
}

func validateDesktopMacOSPairedNodeReady(record mobilemultihop.DesktopNodeReadyRecord, live desktopNodeMTURecord, started, now time.Time, captured *mobilemultihop.DesktopNodeReadyRecord, fresh bool) error {
	if started.IsZero() || record.ProvedAt < started.UnixMilli() || record.ProvedAt > now.UnixMilli() || fresh && now.UnixMilli()-record.ProvedAt > 30000 || !fresh && (captured == nil || *captured != record) {
		return errors.New("macOS Router readiness is stale or belongs to another original start")
	}
	// The startup receipt remains immutable. A later alias is admitted only by
	// the retained MTU owner and exact h.reader, after old-interface retirement.
	if !desktopNodeChainDarwinInterfaceName(record.InterfaceName) || !desktopNodeChainDarwinInterfaceName(live.Interface) || fresh && live.Interface != record.InterfaceName || fresh && live.Index != int(record.InterfaceIndex) || live.Session != record.SessionID || live.Config != record.ConfigSHA256 || fresh && live.Reader != 1 {
		return errors.New("macOS Router readiness replaced its original utun")
	}
	expired := live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored"
	if live.Failure != "" && !expired || fresh && (live.Active || live.Restored || live.Expired || live.Failure != "" || live.MTU != record.MTU || live.Generation != 0 || live.Request != "" || live.Lease != "") {
		return errors.New("macOS Router readiness lost its initial native TUN state")
	}
	return nil
}
func (h *desktopMacOSPairedNodeHost) WaitReady(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, _, err := h.readReadyLocked(ctx, true); err == nil {
			return nil
		}
		if err := h.current(ctx, true); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (h *desktopMacOSPairedNodeHost) Activate(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activated || !h.proved || h.ready == nil {
		return errors.New("macOS Router activation has no unused original private proof")
	}
	if _, _, err := h.readReadyLocked(ctx, false); err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation || a.cmd != h.launch.command || a.closing {
		return errors.New("macOS Router proof lost its original request")
	}
	h.activated = true
	a.state.Connected = true
	a.state.Phase = "connected"
	return nil
}
func (h *desktopMacOSPairedNodeHost) Current(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.refreshExpiredReaderLocked(ctx); err != nil {
		return err
	}
	if !h.activated || !h.proved {
		return errors.New("macOS Router has no active original proof")
	}
	_, _, err := h.readReadyLocked(ctx, false)
	return err
}

func (h *desktopMacOSPairedNodeHost) Ready(ctx context.Context) (mobilemultihop.DesktopNodeReadyRecord, error) {
	if err := h.enter(ctx); err != nil {
		return mobilemultihop.DesktopNodeReadyRecord{}, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.refreshExpiredReaderLocked(ctx); err != nil {
		return mobilemultihop.DesktopNodeReadyRecord{}, err
	}
	if !h.activated || !h.proved {
		return mobilemultihop.DesktopNodeReadyRecord{}, errors.New("macOS Router has no original activation")
	}
	ready, _, err := h.readReadyLocked(ctx, false)
	return ready, err
}
