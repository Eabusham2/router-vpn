//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// A restore retains sealed constructor input, not a process, native admission
// or historical proof. The original session supplies its latest joined trial
// predecessor when the fresh host starts. Clearing this copy cannot erase the
// new host's independently owned private source.
type desktopLinuxNodeRestore struct {
	mu           sync.Mutex
	path         *desktopLinuxNodePath
	parent       *desktopLinuxNodeParentCapture
	session      *desktopLinuxNodeSession
	journal      *desktopLinuxNodeJournal
	source       []byte
	digest       [32]byte
	sourceSHA256 string
	mode         string
	endpoint     string
	network      string
	revision     string
	options      [3]bool
	savedOptions [3]bool
	mtu          int
	entered      bool
	cleared      bool
	restored     *desktopLinuxNodeHost
}

func captureDesktopLinuxNodeRestore(ctx context.Context, a *app, path *desktopLinuxNodePath, profile common.RouterProfile) (*desktopLinuxNodeRestore, error) {
	return captureDesktopLinuxNodeRestoreWith(ctx, a, path, profile, readDesktopLinuxNodePathReady)
}

// Tests model only the native readiness observation. The sealed parser,
// profile/options, retained owners and gate ordering remain the shipping path.
func captureDesktopLinuxNodeRestoreWith(ctx context.Context, a *app, path *desktopLinuxNodePath, profile common.RouterProfile,
	readReady func(context.Context, *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error)) (*desktopLinuxNodeRestore, error) {
	if ctx == nil || ctx.Err() != nil || path == nil || path.app != a || path.session == nil || path.host == nil {
		return nil, errors.New("Linux restore has no original proved path")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := path.session.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { path.session.gate <- struct{}{} }()
	if err := path.host.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { path.host.gate <- struct{}{} }()
	_, live, err := path.currentLockedWith(ctx, readReady)
	if err != nil {
		return nil, err
	}
	h := path.host
	if h.launch.mode != "shadowsocks" || profile.ID != h.launch.profileID || profile.External != nil ||
		profile.NodeKind != "" && profile.NodeKind != "router-vpn" ||
		desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		h.mtu != nil || live.Active || live.MTU < 1280 || live.MTU > 9000 {
		return nil, errors.New("Linux restore changed its supported graph, saved policy or idle live MTU")
	}
	if _, err := h.capturedProofProfile(); err != nil {
		return nil, err
	}
	saved := &desktopLinuxNodeRestore{path: path, parent: path.sessionParent, session: path.session, journal: path.journal,
		source: append([]byte(nil), h.source...), mode: h.launch.mode, endpoint: h.launch.endpoint,
		network: h.network, revision: h.revision, options: h.options, savedOptions: h.savedOptions, mtu: live.MTU}
	saved.digest = sha256.Sum256(saved.source)
	saved.sourceSHA256 = h.policy.OriginalProfile().SourceSHA256()
	if _, _, err := saved.compiled(profile); err != nil {
		clear(saved.source)
		return nil, err
	}
	if err := path.selectedLocked(ctx); err != nil {
		clear(saved.source)
		return nil, err
	}
	return saved, nil
}

// The caller holds saved.mu, or owns the unpublished capture. This parses only
// the sealed in-memory input; generated files and current DNS bootstrap are
// deliberately not consulted during restoration.
func (saved *desktopLinuxNodeRestore) compiled(profile common.RouterProfile) (*mobilemultihop.NodeProfile, common.RouterProfile, error) {
	var empty common.RouterProfile
	if saved == nil || saved.cleared || len(saved.source) == 0 || len(saved.source) > mobilemultihop.NodeLaunchInputLimit ||
		sha256.Sum256(saved.source) != saved.digest || saved.mode != "shadowsocks" ||
		desktopOwnedNodeProfileToken(profile) != saved.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != saved.savedOptions ||
		saved.mtu < 1280 || saved.mtu > 9000 {
		return nil, empty, errors.New("Linux restore lost its exact sealed source, profile or measured MTU")
	}
	profile = cloneRouterProfile(profile)
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = saved.options[0], saved.options[1], saved.options[2]
	original, err := mobilemultihop.ParseNodeLaunchInput(string(saved.source))
	if err != nil || original == nil || original.SourceSHA256() != saved.sourceSHA256 ||
		validateDesktopOwnedNodeSourceProfile(profile, saved.endpoint, string(saved.source)) != nil {
		return nil, empty, errors.Join(err, errors.New("Linux restore substituted another private graph"))
	}
	// This is validation only. Fresh construction allocates its own new session.
	if _, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, "00000000000000000000000000000000", "linux", saved.mtu); err != nil {
		return nil, empty, err
	}
	return original, profile, nil
}

func clearDesktopLinuxNodeRestore(saved *desktopLinuxNodeRestore) {
	if saved == nil {
		return
	}
	saved.mu.Lock()
	defer saved.mu.Unlock()
	clear(saved.source)
	saved.source, saved.cleared = nil, true
}

// Parent native Current and session selection are checked separately by the
// restart caller. This final app-lock comparison may not change a replacement
// command, selected profile, request or separately selected runtime option.
func (saved *desktopLinuxNodeRestore) restartAppCurrent(a *app, operation context.Context, profile common.RouterProfile) error {
	if saved == nil || saved.parent == nil || saved.parent.app != a || a == nil || operation == nil ||
		operation.Err() != nil || saved.network == "" || physicalNetworkIdentity() != saved.network {
		return errors.New("Linux restore lost its original application, request or network")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	actual, exists := a.profileByIDLocked(profile.ID)
	_, duplicate := desktopNodeOwners.Load(a)
	if saved.parent.currentAppLocked(false) != nil || a.checkCapturedConnectionOperationLocked(operation) != nil ||
		a.connectionCancelIntent == operation || a.cmd != nil || a.state.Connected || duplicate || !exists ||
		a.profiles.SelectedID != profile.ID || desktopOwnedNodeProfileToken(actual) != saved.revision ||
		[3]bool{actual.DAITAEnabled, actual.JumboTUN, actual.SocksEnabled} != saved.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != saved.options {
		return errors.New("Linux restore cannot replace a changed request, private policy or runtime")
	}
	return nil
}

// The temporary-test or SMART caller retains operationMu for this entire
// transition. It selects the current request before entering here; neither a
// saved path nor a later callback may acquire another request's restore slot.
func (a *app) restartCapturedDesktopLinuxNode(plan speedLabRestorePlan, scope string) (failure error) {
	if scope != "speed-lab:restore" && scope != "smart:restore" {
		return errors.New("Linux restore has no recognized operation")
	}
	saved := plan.linux
	if saved == nil || plan.native != nil || plan.external != nil || plan.tor != nil || plan.multihop != nil ||
		plan.request.Topology != "router" || plan.request.NodeID != plan.profile.ID ||
		plan.request.Mode != saved.mode || plan.request.Execution != "local" {
		return errors.New("Linux restore has no single captured proved local execution")
	}
	saved.mu.Lock()
	defer saved.mu.Unlock()
	if saved.entered || saved.cleared || saved.parent == nil || saved.session == nil || saved.journal == nil {
		return errors.New("Linux restore cannot replay an entered or retired capture")
	}
	operation := a.connectionOperationContextOrBackground()
	// Individual startup/proof operations keep their own bounds. This ceiling
	// also accommodates the existing maximum 300-second Router proof setting;
	// Speed Lab's original shorter restore context remains authoritative.
	ctx, cancel := context.WithTimeout(operation, 7*time.Minute)
	defer cancel()
	original, profile, err := saved.compiled(plan.profile)
	if err != nil {
		return err
	}
	if err := saved.restartAppCurrent(a, operation, profile); err != nil {
		return err
	}
	s := saved.session
	if err := s.enter(ctx); err != nil {
		return err
	}
	err = s.currentLocked(ctx)
	if err == nil && (s.parent != saved.parent || s.journal != saved.journal || s.active != nil || s.journalErr != nil) {
		err = errors.New("Linux restore lost its original session and joined journal")
	}
	s.gate <- struct{}{}
	if err != nil {
		return err
	}
	if err := saved.restartAppCurrent(a, operation, profile); err != nil {
		return err
	}
	// Native cover activation remains a separate unfinished capability. A
	// restored graph must not silently replace requested cover with ambient UDP.
	if saved.options[0] {
		return errors.New("Linux restore requires native activation for the captured cover policy")
	}
	saved.entered = true
	h, err := newDesktopLinuxNodeHostWithSource(ctx, saved.parent, operation, profile, saved.mode,
		original, saved.endpoint, saved.network, saved.savedOptions, saved.mtu)
	saved.restored = h
	if h != nil {
		defer func() {
			if failure == nil {
				return
			}
			cleanup, finish := context.WithTimeout(context.Background(), 20*time.Second)
			defer finish()
			failure = errors.Join(failure, retireDesktopLinuxNodeRestore(cleanup, s, h), a.speedLabCheckLaunchedRuntime())
		}()
	}
	if err != nil {
		return err
	}
	if err := h.CheckLegacyTransition(ctx); err != nil {
		return err
	}
	if err := h.Stage(ctx); err != nil {
		return err
	}
	err = s.Start(ctx, h)
	if h.launch.command != nil && a.ownsConnectionRuntime(h.launch.command) {
		err = errors.Join(err, a.speedLabOwnRuntime(h.launch.command))
	}
	if err != nil {
		return err
	}
	sessionTrackerFor(a).declareRequest(scope+":"+saved.mode, plan.request.Base)
	if _, err := h.WaitReady(ctx); err != nil {
		return err
	}
	if _, err := h.Prove(ctx); err != nil {
		return err
	}
	if err := h.Activate(ctx); err != nil {
		return err
	}
	if err := s.Monitor(ctx, h); err != nil {
		return err
	}
	return currentDesktopLinuxRestoredHost(ctx, a, s, saved.journal, h)
}

// Retire only the fresh host created by this restore. The original session
// retains failed cleanup for ordinary Stop; a replacement is never selected.
func retireDesktopLinuxNodeRestore(ctx context.Context, s *desktopLinuxNodeSession, h *desktopLinuxNodeHost) error {
	if s == nil || h == nil {
		return errors.New("Linux restore cleanup lost its created owner")
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	selected := s.active == h
	s.gate <- struct{}{}
	if selected {
		return s.Retire(ctx, h, false)
	}
	return h.Close(ctx)
}

func currentRestoredDesktopLinuxNode(ctx context.Context, a *app, saved *desktopLinuxNodeRestore) error {
	if saved == nil {
		return errors.New("Linux restore has no captured result")
	}
	saved.mu.Lock()
	h, s, journal := saved.restored, saved.session, saved.journal
	saved.mu.Unlock()
	return currentDesktopLinuxRestoredHost(ctx, a, s, journal, h)
}

func currentDesktopLinuxRestoredHost(ctx context.Context, a *app, s *desktopLinuxNodeSession, journal *desktopLinuxNodeJournal, h *desktopLinuxNodeHost) error {
	if h == nil || h.parent == nil || h.parent.app != a || h.launch == nil || h.launch.command == nil {
		return errors.New("Linux restore has no newly proved original host")
	}
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, h.launch.command)
	if err != nil || !handled || path == nil || path.host != h || path.session != s || path.journal != journal {
		return errors.Join(err, errors.New("Linux restore lost its newly proved retained session"))
	}
	return nil
}

func (a *app) captureSmartDesktopLinuxNode(ctx context.Context, profile common.RouterProfile) (*desktopSmartNodeCapture, bool, error) {
	a.mu.Lock()
	previous, command := a.state, a.cmd
	a.mu.Unlock()
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, command)
	if err != nil || !handled {
		return nil, handled, err
	}
	if path == nil || !previous.Connected || path.host.operation != ctx || a.checkCapturedConnectionOperation(ctx) != nil {
		return nil, true, errors.New("SMART Linux predecessor belongs to another original proved operation")
	}
	saved, err := captureDesktopLinuxNodeRestore(ctx, a, path, profile)
	if err != nil {
		return nil, true, err
	}
	return &desktopSmartNodeCapture{operation: ctx, state: previous,
		plan: speedLabRestorePlan{profile: cloneRouterProfile(profile), linux: saved,
			request: speedLabRequest{Topology: "router", NodeID: profile.ID, Mode: path.launch.mode, Base: previous.Base, Execution: "local"}}}, true, nil
}

func (a *app) retainSmartDesktopLinuxNode(saved *desktopSmartNodeCapture) error {
	if saved == nil || saved.plan.linux == nil || a.checkCapturedConnectionOperation(saved.operation) != nil {
		return errors.New("SMART Linux predecessor lost its original operation")
	}
	restore := saved.plan.linux
	restore.mu.Lock()
	defer restore.mu.Unlock()
	path := restore.path
	if restore.cleared || restore.entered || path == nil || path.app != a || path.host.operation != saved.operation {
		return errors.New("SMART Linux predecessor cannot retain another capture")
	}
	ctx, cancel := context.WithTimeout(saved.operation, 4*time.Second)
	defer cancel()
	if err := path.session.enter(ctx); err != nil {
		return err
	}
	defer func() { path.session.gate <- struct{}{} }()
	if err := path.host.enter(ctx); err != nil {
		return err
	}
	defer func() { path.host.gate <- struct{}{} }()
	if _, _, err := path.currentLocked(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.checkCapturedConnectionOperationLocked(saved.operation) != nil || a.connectionCancelIntent == saved.operation ||
		path.host.parent.currentAppLocked(false) != nil || a.cmd != path.command || !a.state.Connected ||
		a.state.RouterID != saved.state.RouterID || a.state.RuntimeMode != saved.state.RuntimeMode ||
		!bytes.Equal(path.host.source, restore.source) {
		return errors.New("SMART Linux predecessor changed before its presentation could be retained")
	}
	a.state.Mode, a.state.LogicalMode, a.state.Base = saved.state.Mode, saved.state.LogicalMode, saved.state.Base
	a.state.Phase, a.state.LastError = "connected", ""
	return nil
}
