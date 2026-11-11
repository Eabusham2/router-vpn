//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

type desktopLinuxExternalConnection struct {
	host      *desktopLinuxNodeHost
	session   *desktopLinuxNodeSession
	preflight *desktopLinuxNodeConnectPreflight
	verify    func(context.Context, string) (string, error)
}

func (owner *desktopLinuxExternalConnection) Stage(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil || owner.preflight == nil {
		return errors.New("Linux external staging lost its original prepared owners")
	}
	if err := owner.preflight.current(ctx); err != nil {
		return err
	}
	if err := owner.host.CheckLegacyTransition(ctx); err != nil {
		return err
	}
	if err := owner.host.Stage(ctx); err != nil {
		return err
	}
	return owner.preflight.current(ctx)
}

func (owner *desktopLinuxExternalConnection) Start(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil || owner.verify == nil {
		return errors.New("Linux external start lost its retained prepared session")
	}
	return owner.session.startWithVerifier(ctx, owner.host, os.Environ(), owner.verify)
}

func (owner *desktopLinuxExternalConnection) Activate(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return errors.New("Linux external activation has no original host")
	}
	return owner.host.Activate(ctx)
}

func (owner *desktopLinuxExternalConnection) Monitor(ctx context.Context) error {
	if owner == nil || owner.host == nil || owner.session == nil {
		return errors.New("Linux external monitoring has no retained session")
	}
	return owner.session.Monitor(ctx, owner.host)
}

func (owner *desktopLinuxExternalConnection) ProcessDone() <-chan struct{} {
	if owner == nil || owner.host == nil || owner.host.process == nil {
		return nil
	}
	return owner.host.process.joined
}

func (owner *desktopLinuxExternalConnection) Close(ctx context.Context) error {
	if owner == nil || owner.host == nil {
		return nil
	}
	if owner.session != nil {
		if err := owner.session.enter(ctx); err != nil {
			return err
		}
		selected := owner.session.active == owner.host
		owner.session.gate <- struct{}{}
		if selected {
			return owner.session.Retire(ctx, owner.host, false)
		}
	}
	return owner.host.Close(ctx)
}

// An indexed launch is only an observation handle. Its exact retained session
// and parent chain must still select it before any proof or measurement adopts
// the native receipt; a replacement can never borrow the old journal.
func (owner *desktopLinuxExternalConnection) CurrentProof(ctx context.Context, proof desktopExternalProof) error {
	if owner == nil || owner.host == nil || owner.session == nil {
		return errors.New("Linux external proof has no retained original owner")
	}
	s, h := owner.session, owner.host
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { s.gate <- struct{}{} }()
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != h || !sameDesktopLinuxParentCapture(s.parent, h.parent) {
		return errors.New("Linux external proof belongs to a replaced session")
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	return h.validateExternalProofLocked(ctx, proof)
}

// This capture records an actual external DNS/public-exit proof. It is never
// converted into an authenticated Router-node proof or a node-ready record.
type desktopLinuxExternalProof struct {
	result   mobilemultihop.ExternalProofResult
	provedAt time.Time
}

func (h *desktopLinuxNodeHost) validateExternalProofLocked(ctx context.Context, proof desktopExternalProof) error {
	if h.external == nil || h.policy != nil || h.launch == nil || h.launch.external == nil ||
		h.transaction == nil || h.transaction.external != h.external || h.started.IsZero() ||
		proof.CheckedAt < h.started.Add(-time.Second).UnixMilli() || !proof.Healthy || !proof.DNSProven ||
		proof.EntryProven != !h.launch.external.direct || proof.EntryID != h.launch.external.entry.ID || proof.Execution != "local" {
		return errors.New("Linux external proof lost its typed original source or actual exit proof")
	}
	if err := desktopExternalPhysicalReceiptContext(ctx, h.launch.external, proof.Physical); err != nil {
		return err
	}
	if err := h.runningPolicyLocked(ctx); err != nil {
		return err
	}
	network, err := desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil || network.TargetOS != "linux" || network.MTU < 1280 {
		return errors.Join(err, errors.New("Linux external proof has no actual native TUN receipt"))
	}
	if err := desktopLinuxNodeTUNCurrentContext(ctx, desktopNodeMTURecord{Interface: network.Name, Index: int(network.Index), MTU: network.MTU}); err != nil {
		return err
	}
	if h.activation != nil && (h.externalProof == nil || h.externalProof.result != proof.ExternalProofResult) {
		return errors.New("Linux external heartbeat changed its original proved path")
	}
	return h.runningPolicyLocked(ctx)
}

func (h *desktopLinuxNodeHost) readExternalLocked(ctx context.Context) (desktopExternalProof, error) {
	if h.parent == nil || h.parent.app == nil {
		return desktopExternalProof{}, errors.New("Linux external proof lost its original application")
	}
	proof, err := h.parent.app.readDesktopExternalProofRecordContext(ctx, h.launch)
	if err == nil {
		err = h.validateExternalProofLocked(ctx, proof)
	}
	return proof, err
}

func (h *desktopLinuxNodeHost) observeLocked(ctx context.Context) error {
	if h.external != nil {
		_, err := h.readExternalLocked(ctx)
		return err
	}
	_, _, err := h.readReadyLocked(ctx, false)
	return err
}

func (active *desktopLinuxNodeActivation) matchesExternal(h *desktopLinuxNodeHost) error {
	if active == nil || h == nil || active.host != h || h.activation != active || active.parent == nil || active.parent != h.parent ||
		active.operation == nil || active.operation != h.operation || active.policy != nil || h.policy != nil || active.chain != nil || h.chain != nil ||
		active.external == nil || active.external != h.external || active.external.Validate() != nil ||
		active.externalProof == nil || active.externalProof != h.externalProof || h.proof != nil || h.ready != nil ||
		active.process == nil || active.process != h.process || active.transaction == nil || active.transaction != h.transaction ||
		active.launch == nil || active.launch != h.launch || active.selection != h.selection || active.network != h.network ||
		active.revision != h.revision || active.options != h.options || active.savedOptions != h.savedOptions ||
		active.lifetime == nil || active.lifetime.Err() != nil || active.cancel == nil ||
		active.activatedAt.IsZero() || active.activatedAt == active.activatedAt.Round(0) ||
		active.externalProof.provedAt.IsZero() || active.externalProof.provedAt == active.externalProof.provedAt.Round(0) ||
		active.activatedAt.Sub(active.externalProof.provedAt) < 0 || active.activatedAt.Sub(active.externalProof.provedAt) > 30*time.Second {
		return errors.New("Linux external session lost its original proved activation")
	}
	t, p := active.transaction, active.process
	if t.policy != nil || t.chain != nil || t.external != active.external || t.process != p || !sameDesktopLinuxParentCapture(t.parent, active.parent) ||
		!sameDesktopLinuxParentCapture(p.parent, active.parent) || t.selection != active.selection || t.operation != active.operation ||
		t.profileID != desktopExternalPathProfileID(active.launch) || t.revision != active.revision || t.network != active.network || t.options != active.options ||
		t.savedOptions != active.savedOptions || p.ctx == nil || p.ctx.Err() != nil || !p.Started() || p.retiring.Load() || p.joined == nil ||
		p.command == nil || p.command != active.launch.command {
		return errors.New("Linux external activation substituted its transaction or original process")
	}
	select {
	case <-p.joined:
		return errors.New("Linux external activation outlived its original engine")
	default:
	}
	return nil
}

func (h *desktopLinuxNodeHost) activateExternalLocked(parent context.Context) error {
	if h.activation != nil || h.externalProof != nil || h.external == nil || h.operation == nil || h.operation.Err() != nil {
		return errors.New("Linux external activation has no unused original live request")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	stop := context.AfterFunc(h.operation, cancel)
	defer func() { stop(); cancel() }()
	proof, err := h.readExternalLocked(ctx)
	if err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(desktopExternalPathProfileID(h.launch))
	if err := h.externalSourcesLocked(a); err != nil {
		return err
	}
	if ctx.Err() != nil || h.parent.currentAppLocked(false) != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil ||
		a.connectionCancelIntent == h.operation || physicalNetworkIdentity() != h.network || !exists ||
		desktopOwnedNodeProfileToken(profile) != h.revision || [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options || a.cmd != h.process.command || a.state.Connected ||
		a.state.RouterID != desktopExternalPathProfileID(h.launch) || a.state.RuntimeMode != h.launch.mode || h.process.ctx.Err() != nil || h.transaction.stopRequested.Load() {
		return errors.New("Linux external proof cannot activate a replaced request, profile or runtime")
	}
	select {
	case <-h.process.joined:
		return errors.New("Linux external proof followed its original engine exit")
	default:
	}
	now := time.Now()
	lifetime, cancelLifetime := context.WithCancel(h.parent.lifetime)
	if lifetime.Err() != nil {
		cancelLifetime()
		return errors.New("Linux external proof lost its controller lifetime")
	}
	h.externalProof = &desktopLinuxExternalProof{result: proof.ExternalProofResult, provedAt: now}
	h.activation = &desktopLinuxNodeActivation{host: h, parent: h.parent, operation: h.operation, process: h.process,
		transaction: h.transaction, external: h.external, externalProof: h.externalProof, launch: h.launch, selection: h.selection,
		network: h.network, revision: h.revision, options: h.options, savedOptions: h.savedOptions,
		activatedAt: now, lifetime: lifetime, cancel: cancelLifetime}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	return nil
}

func (owner *desktopLinuxExternalConnection) ProcessDoneContext(ctx context.Context) (<-chan struct{}, error) {
	if ctx == nil {
		return nil, errors.New("process observation requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return owner.ProcessDone(), ctx.Err()
}
