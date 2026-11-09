package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// Observation keeps the captured controller/process capability. It must not
// call a contextless host callback or discover a replacement process by PID.
func (owner *desktopNodeConnectionOwner) currentContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native Router observation has no original caller")
	}
	if owner == nil || owner.capture.lifetime == nil || owner.capture.currentContext == nil || owner.host.start == nil ||
		!filepath.IsAbs(owner.capture.packageRoot) || !filepath.IsAbs(owner.capture.dataRoot) {
		return errors.New("native Router observation lost its contextual captured host")
	}
	if err := errors.Join(ctx.Err(), owner.capture.lifetime.Err()); err != nil {
		return err
	}
	return errors.Join(owner.capture.currentContext(ctx), ctx.Err(), owner.capture.lifetime.Err())
}

func (a *app) desktopOwnedNodeCurrentContext(ctx context.Context, launch *desktopNodeLaunch, processRequired bool) error {
	if ctx == nil {
		return errors.New("native Router observation has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || launch == nil || launch.ownedNode == nil || launch.command == nil {
		return errors.New("native Router observation lost its captured launch")
	}
	owned := launch.ownedNode
	config, meta, _, policyErr := owned.physicalState()
	if policyErr != nil || owned.network == "" {
		return errors.New("native Router observation changed its captured policy or network")
	}
	if owned.imported != nil {
		if err := validateDesktopOwnedImportedSourceContext(ctx, launch, config, meta); err != nil {
			return err
		}
	}
	current := func() error {
		if owned.host != nil {
			if err := owned.host.currentContext(ctx); err != nil {
				return err
			}
		}
		if raw, exists := desktopNodeOwners.Load(a); !exists || raw != launch {
			return errors.New("native Router observation lost its original registration")
		}
		if owned.imported != nil && (owned.imported.app != a || owned.imported.selection.Native == nil || owned.imported.selection.Native.validate(owned.imported.selection) != nil) {
			return errors.New("native imported observation changed its captured entry or paired final")
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		profile, exists := a.profileByIDLocked(launch.profileID)
		current := exists && !a.closing && owned.slot != nil && a.nodeProtection == owned.slot && a.cmd == launch.command && a.state.RouterID == launch.profileID &&
			a.state.RuntimeMode == launch.mode && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == owned.options &&
			desktopOwnedNodeProfileToken(profile) == owned.profileToken && owned.importedSourceCurrentLocked(a)
		a.mu.Unlock()
		if !current {
			return errors.New("native Router observation changed its original runtime or profile")
		}
		if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
			return err
		}
		process, retired := owned.process, owned.retired
		launch.workspaceMu.Unlock()
		if retired {
			return errors.New("native Router observation belongs to a retired owner")
		}
		if processRequired {
			observer, ok := process.(interface{ AliveContext(context.Context) error })
			if !ok || !process.Started() {
				return errors.New("native Router process has no contextual observation capability")
			}
			if err := observer.AliveContext(ctx); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	network, err := owned.networkContext(ctx)
	if err != nil {
		return err
	}
	if network != owned.network {
		return errors.New("native Router observation changed its captured network")
	}
	return current()
}

// These are the same readiness/TUN identities as the compatibility reader.
// Mutex admission and native observation use the caller; bounded regular-file
// reads already in the OS remain synchronously joined through return.
func (a *app) readDesktopOwnedNodeReadyContext(ctx context.Context, launch *desktopNodeLaunch, fresh bool) (mobilemultihop.DesktopNodeReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeReadyRecord
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return empty, err
	}
	owned := launch.ownedNode
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
	if err != nil {
		return empty, err
	}
	policy, err := owned.physicalPolicy()
	if err != nil {
		return empty, err
	}
	record, err := mobilemultihop.ParseDesktopNodeReadyRecord(raw, policy, owned.attempt.digest)
	if err != nil {
		return empty, err
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return empty, err
	}
	started, captured := owned.started, owned.ready
	launch.workspaceMu.Unlock()
	now := time.Now().UnixMilli()
	if started.IsZero() || record.ProvedAt < started.UnixMilli() || record.ProvedAt > now ||
		fresh && now-record.ProvedAt > 30000 || !fresh && (captured == nil || *captured != record) {
		return empty, errors.New("native Router readiness is stale or belongs to a different start")
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	provedExpiry := live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored"
	failed := live.Failure != "" && !provedExpiry
	changedTUN := live.Interface != record.InterfaceName || live.Reader == 1 && live.Index != int(record.InterfaceIndex)
	if err != nil || failed || changedTUN || fresh && (live.Active || live.Failure != "" || live.Reader != 1 || live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU) {
		return empty, errors.Join(err, errors.New("native Router readiness lost its actual TUN owner"))
	}
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return empty, err
	}
	return record, ctx.Err()
}
