//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"router-vpn/internal/mobilemtu"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// This host retains the actual original controller/session, sealed graph,
// private workspace, native child and durable PF baseline as one operation.
// A registry entry is an observation handle, never replacement authority.
type desktopMacOSExternalHost struct {
	entryRevision                                                      string
	entryOptions                                                       [3]bool
	parent                                                             *desktopMacOSSessionCapture
	launch                                                             *desktopNodeLaunch
	policy                                                             *mobilemultihop.DesktopExternalPolicy
	selection                                                          desktopMacOSExternalSelection
	operation                                                          context.Context
	revision, persistedRevision                                        string
	options, savedOptions                                              [3]bool
	beforeCommand                                                      *exec.Cmd
	beforeState                                                        state
	beforeSelected                                                     string
	gate                                                               chan struct{}
	process                                                            *desktopMacOSProcess
	baseline                                                           *desktopMacOSExternalReceipt
	entered, staged, published, activated, baselineEntered             bool
	retiring, nativeRetired, baselineRetired, workspaceRetired, closed bool
	stageDirectory                                                     string
	proof                                                              *mobilemultihop.ExternalProofResult
	monitorCancel                                                      context.CancelFunc
	monitorDone                                                        chan struct{}
	verify                                                             func(context.Context, string) (string, error)
	baselineRun                                                        desktopMacOSBaselineRunner
}

func desktopMacOSExternalEligible(launch *desktopNodeLaunch) bool {
	if launch != nil && launch.ownedNode == nil && launch.tor == nil && desktopExternalRetainedEntryOwner(launch.external) {
		return launch.profileID == launch.external.entry.ID && launch.policyProfileID == launch.external.profile.ID
	}
	if !desktopWindowsExternalEligible(launch) {
		return false
	}
	switch launch.external.profile.External.Protocol {
	case "socks5", "shadowsocks", "http-connect", "https-connect", "hysteria2", "wireguard", "amneziawg", "openvpn":
		return true
	}
	return false
}

func prepareDesktopRetainedExternal(a *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	if a == nil || !desktopMacOSExternalEligible(launch) {
		return nil, nil
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil, nil
	}
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return nil, err
	}
	parent, err := captureDesktopMacOSSession(operation, a)
	if err != nil {
		return nil, err
	}
	if launch.root != macOSOwnedControllerRoot || launch.external.retained != nil || launch.command != nil || launch.directory != "" {
		return nil, errors.New("macOS external preparation requires its unused installed graph")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
		return nil, errors.Join(err, errors.New("macOS external graph lacks its retained physical policy"))
	}
	policy := launch.external.physical
	meta := policy.Metadata()
	launch.configSHA256 = meta.ConfigSHA256
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(launch.policyProfileID)
	entry := common.RouterProfile{}
	if !launch.external.direct {
		entry, _ = a.profileByIDLocked(launch.profileID)
	}
	h := &desktopMacOSExternalHost{parent: parent, launch: launch, policy: policy, operation: operation,
		revision: desktopOwnedNodeProfileToken(profile), entryRevision: desktopOwnedNodeProfileToken(entry),
		entryOptions: [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}, options: [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks},
		savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, beforeCommand: a.cmd,
		beforeState: a.state, beforeSelected: a.profiles.SelectedID, gate: make(chan struct{}, 1), verify: verifyBundledNativeContext, baselineRun: runDesktopMacOSExternalBaseline,
		selection: desktopMacOSExternalSelection{Schema: 1, ProfileID: launch.profileID, Protocol: meta.Protocol, Session: meta.SessionID,
			Source: meta.SourceSHA256, Config: meta.ConfigSHA256, HomeLAN: meta.HomeLANAccess, Policy: meta.KillSwitchPolicy}}
	a.mu.Unlock()
	if !exists || validateDesktopMacOSExternalSources(profile, entry, launch) != nil || !h.selection.valid() {
		return nil, errors.New("macOS external preparation changed its saved source")
	}
	persisted := cloneRouterProfile(profile)
	persisted.MultihopEnabled, persisted.MultihopEntryID, persisted.MultihopExitID = false, "", ""
	persisted.MultihopExecution, persisted.MultihopEntryMode = "local", ""
	if !launch.external.direct {
		persisted.MultihopEnabled, persisted.MultihopEntryID, persisted.MultihopExitID = true, entry.ID, profile.ID
	}
	h.persistedRevision = desktopOwnedNodeProfileToken(persisted)
	launch.external.retained = h
	h.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(operation, 45*time.Second)
	stop := context.AfterFunc(parent.parent.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := h.current(ctx, false); err != nil {
		launch.external.retained = nil
		return nil, err
	}
	image, err := h.verify(ctx, macOSOwnedControllerRoot)
	if err == nil && image != macosprocess.EnginePath {
		err = errors.New("macOS external preflight selected another installed image")
	}
	if err == nil {
		err = preflightDesktopExternalLaunch(ctx, image, launch, runDesktopExternalPreflightCommand)
	}
	if err == nil {
		err = parent.session.Retain(ctx, h)
	}
	if err != nil {
		launch.external.retained = nil
		return nil, err
	}
	return h, h.current(ctx, false)
}

func (h *desktopMacOSExternalHost) enter(ctx context.Context) error {
	if h == nil || ctx == nil || h.gate == nil {
		return errors.New("macOS external host has no bounded original owner")
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

// Called under the host gate once published; preparation is single-threaded.
func (h *desktopMacOSExternalHost) current(ctx context.Context, running bool) error {
	if h == nil || h.parent == nil || h.launch == nil || h.policy == nil || h.policy.Validate() != nil || h.operation == nil || h.baselineRun == nil ||
		h.retiring || h.closed || h.launch.external == nil || h.launch.external.retained != h || h.launch.external.physical != h.policy ||
		h.launch.root != macOSOwnedControllerRoot || h.launch.configSHA256 != h.selection.Config || !bytes.Equal(h.launch.config, []byte(h.policy.Config())) ||
		h.launch.external.network == "" {
		return errors.New("macOS external host lost its original sealed operation")
	}
	network, err := h.launch.external.currentNetworkIdentityContext(ctx)
	if err != nil {
		return err
	}
	if network != h.launch.external.network {
		return errors.New("macOS external physical network changed")
	}
	if err := h.parent.Current(ctx); err != nil {
		return err
	}
	a := h.parent.app
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	profile, exists := a.profileByIDLocked(h.launch.policyProfileID)
	entry := common.RouterProfile{}
	if !h.launch.external.direct {
		entry, _ = a.profileByIDLocked(h.launch.profileID)
	}
	revision := desktopOwnedNodeProfileToken(profile)
	valid := exists && !a.closing && (revision == h.revision || h.activated && revision == h.persistedRevision) &&
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == h.savedOptions &&
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == h.options && validateDesktopMacOSExternalSources(profile, entry, h.launch) == nil &&
		desktopOwnedNodeProfileToken(entry) == h.entryRevision &&
		[3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled} == h.entryOptions
	if !h.activated {
		valid = valid && h.operation.Err() == nil && a.checkCapturedConnectionOperationLocked(h.operation) == nil && a.connectionCancelIntent != h.operation
	}
	if h.published {
		valid = valid && a.cmd == h.launch.command && a.state.RouterID == h.launch.policyProfileID && a.state.RuntimeMode == h.launch.mode
	}
	a.mu.Unlock()
	if !valid {
		return errors.New("macOS external request, private profile or runtime was replaced")
	}
	if h.published {
		if value, ok := desktopExternalRetainedLaunches.Load(a); !ok || value != h.launch {
			return errors.New("macOS external host lost its original registry")
		}
		p := h.parent.parent
		if err := p.enter(ctx); err != nil {
			return err
		}
		selected := p.originalSession == h.parent.session && h.parent.session.external == h
		p.gate <- struct{}{}
		if !selected {
			return errors.New("macOS external host belongs to another active session")
		}
	}
	if running {
		if !h.published || h.process == nil || h.baseline == nil || h.baseline.Phase != "active" || h.process.command != h.launch.command {
			return errors.New("macOS external host lacks its actual admitted child")
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

func (h *desktopMacOSExternalHost) Stage(ctx context.Context) error {
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
		return errors.New("macOS external staging cannot replace its prior captured connection")
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
	}{{"sing-box.json", h.launch.config}, {"source.json", h.launch.external.source}, {"capture.json", h.launch.external.capture}} {
		if err := writeDesktopRuntimeFile(h.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	h.staged = true
	return h.current(ctx, false)
}

func (h *desktopMacOSExternalHost) Start(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, false); err != nil {
		return err
	}
	if !h.staged || h.entered || h.process != nil {
		return errors.New("macOS external start requires its unused private stage")
	}
	p := h.parent.parent
	a := h.parent.app
	a.mu.Lock()
	if err := p.enter(ctx); err != nil {
		a.mu.Unlock()
		return err
	}
	if p.currentLocked(ctx, true) != nil || h.parent.session.external != nil || h.parent.session.nodeChain != nil {
		p.gate <- struct{}{}
		a.mu.Unlock()
		return errors.New("macOS external predecessor has not retired")
	}
	_, legacy := desktopNodeOwners.Load(a)
	_, retained := desktopExternalRetainedLaunches.Load(a)
	if a.cmd != nil || a.state.Connected || legacy || retained || a.checkCapturedConnectionOperationLocked(h.operation) != nil {
		a.mu.Unlock()
		p.gate <- struct{}{}
		return errors.New("macOS external start cannot replace an unjoined original runtime")
	}
	h.entered, h.published = true, true
	h.parent.session.external = h
	desktopExternalRetainedLaunches.Store(a, h.launch)
	a.state.Mode, a.state.RuntimeMode, a.state.RouterID = "external-node", h.launch.mode, h.launch.policyProfileID
	a.state.Connected, a.state.Phase = false, "starting"
	a.mu.Unlock()
	p.gate <- struct{}{}
	var err error
	h.baseline, err = h.baselineRun(ctx, h.parent, h.selection, "apply", nil, func() { h.baselineEntered = true })
	if err != nil {
		return err
	}
	scope := macosprocess.Scope{Session: h.selection.Session, Source: h.selection.Source, Config: h.selection.Config, Workspace: h.launch.directory}
	h.launch.external.mu.Lock()
	h.launch.external.started = time.Now()
	h.launch.external.mu.Unlock()
	h.process, err = startDesktopMacOSProcessWithVerifier(ctx, h.parent, scope, h.verify)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.cmd != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil {
		a.mu.Unlock()
		return errors.New("macOS external created child lost its original application")
	}
	h.launch.command = h.process.command
	a.cmd = h.launch.command
	a.mu.Unlock()
	return h.current(ctx, true)
}

func (h *desktopMacOSExternalHost) ProcessDone() <-chan struct{} {
	// The process pointer is published before launch.command; callers observe
	// this only through that exact command in the retained runtime registry.
	if h == nil || h.process == nil {
		return nil
	}
	return h.process.joined
}

func (h *desktopMacOSExternalHost) proofCurrent(ctx context.Context, proof desktopExternalProof) error {
	if err := h.current(ctx, true); err != nil {
		return err
	}
	meta := h.policy.Metadata()
	expected := h.launch.external.expected
	if !proof.Healthy || !proof.DNSProven || proof.EntryProven != expected.EntryProven || proof.EntryID != expected.EntryID || proof.EntryNodeID != expected.EntryNodeID || proof.ExitID != expected.ExitID || proof.Execution != "local" ||
		proof.SessionID != meta.SessionID || proof.SourceSHA256 != meta.OriginalSourceSHA256 || proof.ConfigSHA256 != meta.OriginalConfigSHA256 ||
		h.proof != nil && *h.proof != proof.ExternalProofResult {
		return errors.New("macOS external proof changed its original DNS or exit path")
	}
	if err := desktopExternalPhysicalReceiptContext(ctx, h.launch.external, proof.Physical); err != nil {
		return err
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil || receipt.TargetOS != "darwin" || receipt.MTU < 1280 || !strings.HasPrefix(receipt.Name, "utun") {
		return errors.New("macOS external proof lacks its actual native TUN")
	}
	link, _, err := desktopnetwork.InterfaceContext(ctx, int(receipt.Index))
	if err != nil || link.Name != receipt.Name || link.MTU != receipt.MTU || link.Flags&net.FlagUp == 0 {
		return errors.New("macOS external TUN changed after native proof")
	}
	return h.process.Current(ctx)
}
func (h *desktopMacOSExternalHost) CurrentProof(ctx context.Context, proof desktopExternalProof) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	return h.proofCurrent(ctx, proof)
}
func (h *desktopMacOSExternalHost) Activate(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.activated || h.proof != nil {
		return errors.New("macOS external activation already consumed its original proof")
	}
	proof, err := h.parent.app.readDesktopExternalProofRecord(h.launch)
	if err != nil {
		return err
	}
	if err = h.proofCurrent(ctx, proof); err != nil {
		return err
	}
	a := h.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || h.operation.Err() != nil || a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.cmd != h.launch.command || a.closing {
		return errors.New("macOS external activation lost its original request")
	}
	h.proof = &proof.ExternalProofResult
	h.activated = true
	return nil
}

func (h *desktopMacOSExternalHost) Monitor(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx, true); err != nil {
		return err
	}
	if !h.activated || h.monitorDone != nil {
		return errors.New("macOS external monitor has no unused original activation")
	}
	watch, cancel := context.WithCancel(h.parent.parent.ctx)
	done := make(chan struct{})
	h.monitorCancel, h.monitorDone = cancel, done
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		var once sync.Once
		end := func() { once.Do(func() { ticker.Stop(); cancel(); close(done) }) }
		defer end()
		a, launch := h.parent.app, h.launch
		for {
			select {
			case <-watch.Done():
				return
			case <-ticker.C:
			}
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				continue
			}
			release, current := a.claimRuntimeMonitorOperation(launch.command)
			if !current {
				return
			}
			if release == nil {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				release()
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				release()
				continue
			}
			end()
			invalidateDesktopMacOSExternalMeasurements(a, launch)
			err := a.stopModeWithIntent(true)
			message := "captured macOS external path retired; original protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			if a.cmd == launch.command || a.cmd == nil && a.state.RouterID == launch.policyProfileID {
				a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			}
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			release()
			return
		}
	}()
	return nil
}

func (h *desktopMacOSExternalHost) ProcessDoneContext(ctx context.Context) (<-chan struct{}, error) {
	if ctx == nil {
		return nil, errors.New("process observation requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return h.ProcessDone(), ctx.Err()
}
