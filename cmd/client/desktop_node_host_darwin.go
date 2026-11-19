//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"sync/atomic"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// One retained original parent owns the sealed Router source, actual child,
// PF baseline, selected DNS/TUN receipt and independently routed private proof.
// No saved receipt can construct or replace this lifetime.
type desktopMacOSPairedNodeHost struct {
	measurementEpoch                                                   atomic.Uint64
	measurementRetired                                                 atomic.Bool
	reader                                                             *desktopNodeMTURecord
	mtu                                                                *desktopMacOSPairedNodeMTUOwner
	mtuObservation                                                     desktopMacOSPairedNodeMTUObservationSlot
	parent                                                             *desktopMacOSSessionCapture
	launch                                                             *desktopNodeLaunch
	policy                                                             *mobilemultihop.DesktopNodePolicy
	selection                                                          desktopMacOSNodeSelection
	operation                                                          context.Context
	profile                                                            common.RouterProfile
	source, policyInput                                                []byte
	network, revision                                                  string
	options, savedOptions                                              [3]bool
	beforeCommand                                                      *exec.Cmd
	beforeState                                                        state
	beforeSelected                                                     string
	gate                                                               chan struct{}
	process                                                            *desktopMacOSProcess
	baseline                                                           *desktopMacOSNodeReceipt
	ready                                                              *mobilemultihop.DesktopNodeReadyRecord
	transfer                                                           string
	started                                                            time.Time
	proved                                                             bool
	entered, staged, published, activated, baselineEntered             bool
	retiring, nativeRetired, baselineRetired, workspaceRetired, closed bool
	stageDirectory                                                     string
	monitorCancel                                                      context.CancelFunc
	monitorDone                                                        chan struct{}
	verify                                                             func(context.Context, string) (string, error)
	baselineRun                                                        desktopMacOSNodeBaselineRunner
}

func prepareDesktopMacOSPairedNodeHost(ctx context.Context, a *app, profile common.RouterProfile, mode string, restoredMTU int) (*desktopMacOSPairedNodeHost, error) {
	return prepareDesktopMacOSPairedNodeHostWith(ctx, a, profile, mode, restoredMTU, verifyBundledNativeContext, func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	})
}

// Only package verification and the original bounded lookup have test seams.
// Neither may replace the installed parent, original profile or native child.
func prepareDesktopMacOSPairedNodeHostWith(operation context.Context, a *app, profile common.RouterProfile, mode string, restoredMTU int, verify func(context.Context, string) (string, error), lookup applexray.Lookup) (*desktopMacOSPairedNodeHost, error) {
	if operation == nil || a == nil || verify == nil || lookup == nil || !mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode, profile.StartLayer) || profile.External != nil || profile.NodeKind != "" && profile.NodeKind != "router-vpn" {
		return nil, errors.New("macOS paired Node requires its supported original private graph")
	}
	ctx, cancel := context.WithTimeout(operation, 30*time.Second)
	defer cancel()
	parent, err := captureDesktopMacOSSession(ctx, a)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(parent.parent.ctx, cancel)
	defer stop()
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	saved, exists := a.profileByIDLocked(profile.ID)
	beforeCommand, beforeState, beforeSelected := a.cmd, a.state, a.profiles.SelectedID
	savedOptions := [3]bool{saved.DAITAEnabled, saved.JumboTUN, saved.SocksEnabled}
	options := [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}
	selectedOptions := [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks}
	a.mu.Unlock()
	revision := desktopOwnedNodeProfileToken(profile)
	if !exists || desktopOwnedNodeProfileToken(saved) != revision || options != selectedOptions {
		return nil, errors.New("macOS Node preparation changed its saved source or runtime options")
	}
	current := func() error {
		if err := parent.Current(ctx); err != nil {
			return err
		}
		actual, e := physicalNetworkIdentityContext(ctx)
		if e != nil {
			return e
		}
		if actual != network || network == "" {
			return errors.New("macOS Node preparation changed its original physical network")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		actualProfile, ok := a.profileByIDLocked(profile.ID)
		if !ok || a.checkCapturedConnectionOperationLocked(operation) != nil || a.connectionCancelIntent == operation || desktopOwnedNodeProfileToken(actualProfile) != revision || [3]bool{actualProfile.DAITAEnabled, actualProfile.JumboTUN, actualProfile.SocksEnabled} != savedOptions || [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != options {
			return errors.New("macOS Node preparation lost its original request and saved source")
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return nil, err
	}
	image, err := verify(ctx, macOSOwnedControllerRoot)
	if err != nil || image != macosprocess.EnginePath {
		return nil, errors.Join(err, errors.New("macOS Node verified another installed image"))
	}
	files, err := readDesktopNodeAssets(macOSOwnedControllerRoot, profile.ID, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	start, err := readDesktopNodeStartAssets(macOSOwnedControllerRoot, profile, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range start {
			clear(body)
		}
	}()
	original, endpoint, err := compileDesktopNode(ctx, profile, mode, files, start, func(call context.Context, name string) ([]netip.Addr, error) {
		if err := current(); err != nil {
			return nil, err
		}
		values, err := lookup(call, name)
		if err != nil {
			return nil, err
		}
		if err := current(); err != nil {
			return nil, err
		}
		return values, nil
	})
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	h, err := newDesktopMacOSPairedNodeHost(ctx, parent, operation, profile, mode, original, endpoint, network, savedOptions, restoredMTU)
	if h != nil {
		h.beforeCommand, h.beforeState, h.beforeSelected = beforeCommand, beforeState, beforeSelected
		h.verify = verify
	}
	return h, err
}

func newDesktopMacOSPairedNodeHost(ctx context.Context, parent *desktopMacOSSessionCapture, operation context.Context, profile common.RouterProfile, mode string, original *mobilemultihop.NodeProfile, endpoint, network string, savedOptions [3]bool, restoredMTU int) (*desktopMacOSPairedNodeHost, error) {
	if ctx == nil || parent == nil || operation == nil || original == nil || !mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode, profile.StartLayer) {
		return nil, errors.New("macOS Node source requires its exact original parent and graph")
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	revision, fixed, err := desktopDeviceFixedInput(operation)
	if err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.NewDesktopNodePolicyWithDevicePreference(original, session, "darwin", restoredMTU, revision, fixed)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	source, err := original.LaunchInput()
	if err != nil || validateDesktopOwnedNodeSourceProfile(profile, endpoint, source) != nil || meta.ProfileID != profile.ID || meta.Mode != mode || meta.TargetOS != "darwin" {
		return nil, errors.Join(err, errors.New("macOS Node source changed its original paired profile"))
	}
	policyInput, err := macosprocess.MarshalNodePolicyPreference(restoredMTU, revision, fixed)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	layer := profile.StartLayer
	if layer == "" {
		layer = "off"
	}
	h := &desktopMacOSPairedNodeHost{parent: parent, policy: policy, operation: operation, profile: cloneRouterProfile(profile), source: []byte(source), policyInput: policyInput, network: network,
		revision: desktopOwnedNodeProfileToken(profile), options: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, savedOptions: savedOptions, gate: make(chan struct{}, 1), verify: verifyBundledNativeContext, baselineRun: runDesktopMacOSNodeBaseline,
		selection: desktopMacOSNodeSelection{Schema: 1, Family: macosprocess.NodeFamily, ProfileID: profile.ID, NodeID: meta.NodeID, Mode: mode, StartLayer: layer, Session: session, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy},
		launch:    &desktopNodeLaunch{root: macOSOwnedControllerRoot, endpoint: endpoint, profileID: profile.ID, policyProfileID: profile.ID, mode: mode, config: []byte(policy.Config()), metadata: metadata, configSHA256: meta.ConfigSHA256, mtuSession: session}}
	h.launch.pairedNode = h
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, false); err != nil {
		return nil, err
	}
	if err := parent.session.Retain(ctx, h); err != nil {
		return nil, err
	}
	return h, h.current(ctx, false)
}

func (h *desktopMacOSPairedNodeHost) enter(ctx context.Context) error {
	if h == nil || ctx == nil || h.gate == nil {
		return errors.New("macOS paired Node lost its bounded owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.gate:
	}
	if err := ctx.Err(); err != nil {
		h.gate <- struct{}{}
		return err
	}
	return nil
}
func (h *desktopMacOSPairedNodeHost) current(ctx context.Context, running bool) error {
	if h == nil || h.parent == nil || h.launch == nil || h.launch.pairedNode != h || h.policy == nil || h.policy.Validate() != nil || h.operation == nil || h.baselineRun == nil || !h.selection.valid() || h.retiring || h.closed || h.launch.root != macOSOwnedControllerRoot || h.launch.configSHA256 != h.selection.Config || !bytes.Equal(h.launch.config, []byte(h.policy.Config())) {
		return errors.New("macOS paired Node lost its original sealed lifetime")
	}
	source, err := h.policy.OriginalProfile().LaunchInput()
	if err != nil || source != string(h.source) {
		return errors.New("macOS paired Node original source was replaced")
	}
	if err := h.parent.Current(ctx); err != nil {
		return err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil {
		return err
	}
	if network == "" || network != h.network {
		return errors.New("macOS paired Node physical network changed")
	}
	a := h.parent.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	profile, exists := a.profileByIDLocked(h.launch.profileID)
	valid := exists && !a.closing && desktopOwnedNodeProfileToken(profile) == h.revision && [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == h.savedOptions && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == h.options
	if !h.activated {
		valid = valid && h.operation.Err() == nil && a.checkCapturedConnectionOperationLocked(h.operation) == nil && a.connectionCancelIntent != h.operation
	}
	if h.published {
		value, ok := desktopNodeOwners.Load(a)
		valid = valid && ok && value == h.launch && a.cmd == h.launch.command && a.state.RouterID == h.launch.profileID && a.state.RuntimeMode == h.launch.mode
	}
	a.mu.Unlock()
	if !valid {
		return errors.New("macOS paired Node request, saved source or command was replaced")
	}
	if h.published {
		p := h.parent.parent
		if err := p.enter(ctx); err != nil {
			return err
		}
		same := p.originalSession == h.parent.session && h.parent.session.pairedNode == h && h.parent.session.external == nil && h.parent.session.nodeChain == nil && h.parent.session.candidatePrefix == nil
		p.gate <- struct{}{}
		if !same {
			return errors.New("macOS paired Node lost its exclusive original session")
		}
	}
	if running {
		if !h.published || h.process == nil || h.process.command != h.launch.command || h.baseline == nil || h.baseline.Phase != "active" {
			return errors.New("macOS paired Node has no actual admitted child")
		}
		if err := h.process.Current(ctx); err != nil {
			return err
		}
		if _, err := h.baselineRun(ctx, h.parent, h.selection, "current", h.baseline, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (h *desktopMacOSPairedNodeHost) Stage(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, false); err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	same := a.cmd == h.beforeCommand && a.profiles.SelectedID == h.beforeSelected && a.state.Mode == h.beforeState.Mode &&
		a.state.RuntimeMode == h.beforeState.RuntimeMode && a.state.RouterID == h.beforeState.RouterID && a.state.Connected == h.beforeState.Connected
	a.mu.Unlock()
	if !same || h.staged || h.entered || h.launch.directory != "" {
		return errors.New("macOS paired Node staging cannot replace its prior captured connection")
	}
	directory, err := newPrivateRuntimeDir(macOSOwnedControllerRoot, "native-node")
	if err != nil {
		return err
	}
	h.stageDirectory = directory
	if err = captureDesktopRuntimeDirectory(h.launch, directory); err != nil {
		return err
	}
	for _, input := range []struct {
		name string
		body []byte
	}{{"node-source.json", h.source}, {"node-policy.json", h.policyInput}, {"sing-box.json", h.launch.config}} {
		if err := writeDesktopRuntimeFile(h.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	h.staged = true
	return h.current(ctx, false)
}

func (h *desktopMacOSPairedNodeHost) Start(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, false); err != nil {
		return err
	}
	if !h.staged || h.entered || h.process != nil {
		return errors.New("macOS paired Node start requires its unused private stage")
	}
	p := h.parent.parent
	a := h.parent.app
	a.mu.Lock()
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	if p.currentLocked(ctx, true) != nil || h.parent.session.external != nil || h.parent.session.nodeChain != nil || h.parent.session.candidatePrefix != nil || h.parent.session.pairedNode != nil {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS paired Node predecessor has not retired")
	}
	_, legacy := desktopNodeOwners.Load(a)
	_, retained := desktopExternalRetainedLaunches.Load(a)
	if a.cmd != nil || a.state.Connected || legacy || retained || a.checkCapturedConnectionOperationLocked(h.operation) != nil {
		a.mu.Unlock()
		p.gate <- struct{}{}
		return errors.New("macOS paired Node start cannot replace an unjoined original runtime")
	}
	h.entered, h.published = true, true
	h.parent.session.pairedNode = h
	desktopNodeOwners.Store(a, h.launch)
	a.state.Mode, a.state.RuntimeMode, a.state.RouterID = h.launch.mode, h.launch.mode, h.launch.policyProfileID
	a.state.Connected, a.state.Phase = false, "starting"
	a.mu.Unlock()
	p.gate <- struct{}{}
	var err error
	h.baseline, err = h.baselineRun(ctx, h.parent, h.selection, "apply", nil, func() { h.baselineEntered = true })
	if err != nil {
		return err
	}
	scope := macosprocess.Scope{Family: macosprocess.NodeFamily, Session: h.selection.Session, Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
	h.started = time.Now()
	h.process, err = startDesktopMacOSProcessWithVerifier(ctx, h.parent, scope, h.verify)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.cmd != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil {
		a.mu.Unlock()
		return errors.New("macOS paired Node created child lost its original application")
	}
	h.launch.command = h.process.command
	a.cmd = h.launch.command
	a.mu.Unlock()
	return h.current(ctx, true)
}
