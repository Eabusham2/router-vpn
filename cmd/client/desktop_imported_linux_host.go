//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

type desktopLinuxImportedCapture struct {
	parent  *desktopLinuxNodeParentCapture
	sources *desktopLinuxImportedSources
	network string
	seal    string
	verify  func(context.Context, string) (string, error)
}

func (capture *desktopLinuxImportedCapture) Seal() string {
	if capture == nil || capture.seal == "" || capture.sourceDigest() != capture.seal {
		return ""
	}
	return capture.seal
}

func (capture *desktopLinuxImportedCapture) sourceDigest() string {
	if capture == nil || capture.parent == nil || capture.sources == nil || capture.network == "" {
		return ""
	}
	s := capture.sources
	raw, err := json.Marshal([]any{"linux-imported-parent-v1", capture.parent.record, capture.network, s.selected, s.original,
		s.options, s.appliedOptions, s.temporary != nil, mtuProfileSnapshotToken(s.selection.Entry), mtuProfileSnapshotToken(s.selection.Exit)})
	if err != nil {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (capture *desktopLinuxImportedCapture) Verify(ctx context.Context) (string, error) {
	if err := capture.current(ctx); err != nil {
		return "", err
	}
	image, err := capture.verify(ctx, linuxOwnedControllerRoot)
	if err != nil || filepath.Clean(image) != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		return "", errors.Join(err, errors.New("Linux imported verification changed its installed image"))
	}
	return image, capture.current(ctx)
}

// The public dispatcher stays closed until the installed-controller fixture
// passes with independent encrypted peers. Private native fixtures call the
// same concrete capture below, never a mutable environment admission switch.
func captureDesktopImportedPlatformContext(ctx context.Context, a *app, sel multihopSelection, modes []string) (multihopSelection, bool, error) {
	if sel.Entry.NodeKind != "external" || a == nil || a.desktopNodeConnectionHost() != nil {
		return sel, false, nil
	}
	return sel, true, errors.New("Linux imported protected host is not yet admitted")
}

func captureDesktopLinuxImportedForApp(ctx context.Context, a *app, sel multihopSelection, modes []string) (multihopSelection, error) {
	return captureDesktopLinuxImportedForAppWith(ctx, a, sel, modes, verifyBundledNativeContext,
		func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		})
}

func captureDesktopLinuxImportedForAppWith(parentContext context.Context, a *app, sel multihopSelection, modes []string,
	verify func(context.Context, string) (string, error), lookup applexray.Lookup) (multihopSelection, error) {
	if parentContext == nil || a == nil || verify == nil || !desktopLinuxImportedEligible(sel) || len(modes) != 1 || modes[0] != sel.ExitMode {
		return sel, errors.New("Linux imported capture requires its bounded original protected WG-to-SS selection")
	}
	ctx, cancel := context.WithTimeout(parentContext, 30*time.Second)
	defer cancel()
	parent, err := captureDesktopLinuxNodeParentContext(ctx, a)
	if err != nil {
		return sel, err
	}
	stop := context.AfterFunc(parent.lifetime, cancel)
	defer stop()
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return sel, err
	}
	sources, err := captureDesktopLinuxImportedSourcesLocked(ctx, a, sel)
	a.mu.Unlock()
	if err != nil {
		return sel, err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil || network == "" {
		return sel, errors.Join(err, errors.New("Linux imported capture lost its physical network"))
	}
	capture := &desktopLinuxImportedCapture{parent: parent, sources: sources, network: network, verify: verify}
	current := func() error {
		if err := capture.current(ctx); err != nil {
			return err
		}
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		defer a.mu.Unlock()
		return sources.currentLocked(a, false)
	}
	if err := current(); err != nil {
		return sel, err
	}
	image, err := verify(ctx, linuxOwnedControllerRoot)
	if err != nil || filepath.Clean(image) != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		return sel, errors.Join(err, errors.New("Linux imported capture verified another installed image"))
	}
	wrappedLookup := func(call context.Context, name string) ([]netip.Addr, error) {
		if err := current(); err != nil {
			return nil, err
		}
		if lookup == nil {
			return nil, errors.New("Linux imported capture has no captured bootstrap resolver")
		}
		answers, err := lookup(call, name)
		return answers, errors.Join(err, current())
	}
	sel, err = captureDesktopImportedMultihop(ctx, linuxOwnedControllerRoot, sel, modes, wrappedLookup)
	if err != nil {
		return sel, err
	}
	capture.seal = capture.sourceDigest()
	sel.Native.importedPlatform = capture
	sel.Native.source = sel.Native.importedCaptureDigest()
	return sel, errors.Join(current(), sel.Native.validate(sel))
}

func (capture *desktopLinuxImportedCapture) current(ctx context.Context) error {
	if capture == nil || capture.parent == nil || capture.sources == nil || capture.verify == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("Linux imported capture lost its original installed parent")
	}
	if capture.seal != "" && capture.Seal() == "" {
		return errors.New("Linux imported capture changed its sealed parent or independent source projections")
	}
	if err := capture.parent.Current(ctx); err != nil {
		return err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil || capture.network == "" || network != capture.network {
		return errors.Join(err, errors.New("Linux imported capture changed its original physical network"))
	}
	return nil
}

func (capture *desktopLinuxImportedCapture) Prepare(ctx context.Context, a *app, sel multihopSelection) (launch *desktopNodeLaunch, failure error) {
	if capture == nil || capture.parent == nil || capture.parent.app != a || sel.Native == nil || sel.Native.importedPlatform != capture ||
		!sel.Native.imported || sel.Native.importedHost != nil || sel.Native.validate(sel) != nil || !desktopLinuxImportedEligible(sel) {
		return nil, errors.New("Linux imported preparation lost its exact captured entry and paired final")
	}
	if err := capture.current(ctx); err != nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	operation := a.connectionContext
	err := errors.Join(a.checkCapturedConnectionOperationLocked(operation), capture.sources.currentLocked(a, false))
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	original, err := mobilemultihop.ParseImportedLaunchInput(sel.Native.importedInput)
	if err != nil {
		return nil, err
	}
	registered := false
	defer func() {
		if !registered {
			_ = original.Close()
		}
	}()
	graph, _, err := nativeMultihopProofConfig(original.Config(), sel.Entry)
	if err != nil || original.SourceSHA256() != sel.Native.importedOriginalSource || graph != sel.Native.configs[sel.ExitMode] {
		return nil, errors.Join(err, errors.New("Linux imported replay changed its independently captured constructor"))
	}
	sessionID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.NewDesktopImportedPolicyWithMTU(original, sessionID, "linux", sel.restoreMTU)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	if meta.EntryID != sel.Entry.ID || meta.ExitID != sel.Exit.ID || meta.ProfileID != sel.Control.ID || meta.ExitNodeID != sel.Exit.NodeProofID ||
		meta.EntryMode != sel.EntryMode || meta.ExitMode != sel.ExitMode {
		return nil, errors.New("Linux imported policy substituted a captured node identity")
	}
	physicalCapture, err := policy.Capture()
	if err != nil {
		return nil, err
	}
	physical, err := captureDesktopLinuxRunningPath(physicalCapture.PhysicalRoots, physicalCapture.IPv6Mode)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	launch = &desktopNodeLaunch{root: linuxOwnedControllerRoot, endpoint: sel.Native.endpoint, profileID: sel.Exit.ID,
		policyProfileID: sel.Control.ID, mode: sel.ExitMode, config: []byte(policy.Config()), metadata: metadata,
		configSHA256: meta.ConfigSHA256, mtuSession: sessionID, importedEntry: true}
	h := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: capture.parent, operation: operation, imported: policy, launch: launch,
		source: []byte(sel.Native.importedInput), network: capture.network, revision: desktopOwnedNodeProfileToken(sel.Control),
		options: capture.sources.appliedOptions, savedOptions: capture.sources.appliedOptions, physical: physical, monitor: &atomic.Pointer[desktopLinuxNodeMonitor]{},
		selection: linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}}
	owner := &desktopLinuxImportedConnection{capture: capture, host: h, selection: sel}
	launch.importedPlatform = owner
	if err := h.current(ctx); err != nil {
		return launch, err
	}
	p := capture.parent.parent
	select {
	case <-ctx.Done():
		return launch, ctx.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		return launch, err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[h] = struct{}{}
	p.gate <- struct{}{}
	h.gate <- struct{}{}
	registered = true
	owner.registered = true
	owner.session, err = captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return launch, err
	}
	if err := h.CheckLegacyTransition(ctx); err != nil {
		return launch, err
	}
	return launch, h.current(ctx)
}

func (h *desktopLinuxNodeHost) currentImported(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil || h.closing || h.closed || h.operation == nil || h.parent == nil ||
		h.imported == nil || h.imported.Validate() != nil || h.policy != nil || h.external != nil || h.launch == nil {
		return errors.New("Linux imported host lost its typed original policy")
	}
	owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || owner == nil || owner.host != h || owner.capture == nil || owner.capture.parent != h.parent || owner.selection.Native == nil ||
		owner.selection.Native.importedPlatform != owner.capture || owner.selection.Native.validate(owner.selection) != nil {
		return errors.New("Linux imported host changed its original capture")
	}
	if err := owner.capture.current(ctx); err != nil {
		return err
	}
	meta := h.imported.Metadata()
	wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if h.selection != wanted || meta.TargetOS != "linux" || h.launch.root != linuxOwnedControllerRoot || h.launch.mode != meta.ExitMode ||
		h.launch.profileID != meta.ExitID || h.launch.policyProfileID != meta.ProfileID || h.launch.mtuSession != meta.SessionID ||
		h.launch.configSHA256 != meta.ConfigSHA256 || !bytes.Equal(h.launch.config, []byte(h.imported.Config())) ||
		string(h.source) != owner.selection.Native.importedInput || meta.OriginalSourceSHA256 != owner.selection.Native.importedOriginalSource {
		return errors.New("Linux imported host changed its sealed command or constructor")
	}
	if h.activation == nil {
		if h.operation.Err() != nil {
			return errConnectionOperationCancelled
		}
	} else if err := h.activation.matches(h); err != nil {
		return err
	}
	a := h.parent.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if err := owner.capture.sources.currentLocked(a, h.importedProjected); err != nil {
		return err
	}
	if h.activation == nil {
		if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
			return errConnectionOperationCancelled
		}
	} else if h.process == nil || a.cmd != h.process.command || a.state.RouterID != meta.ExitID || a.state.RuntimeMode != meta.ExitMode {
		return errors.New("Linux imported activation belongs to a replaced connection")
	}
	return nil
}

func newDesktopLinuxImportedTransaction(ctx context.Context, h *desktopLinuxNodeHost, journal *desktopLinuxNodeJournal, predecessor *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if h == nil || h.imported == nil || h.process == nil || !h.process.Started() || journal == nil || !sameDesktopLinuxParentCapture(h.parent, journal.parent) {
		return nil, errors.New("Linux imported transaction lost its original process and journal")
	}
	if err := h.current(ctx); err != nil {
		return nil, err
	}
	owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
	if !ok || owner.host != h {
		return nil, errors.New("Linux imported transaction lost its retained host")
	}
	t := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: h.parent, journal: journal, process: h.process,
		imported: h.imported, importedSources: owner.capture.sources, mode: h.launch.mode, operation: h.operation, startup: ctx, selection: h.selection,
		profileID: h.launch.profileID, revision: h.revision, network: h.network, options: h.options, savedOptions: h.savedOptions, predecessor: predecessor}
	return finishDesktopLinuxNodeTransaction(t)
}
