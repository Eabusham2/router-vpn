//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

type desktopLinuxPrivateInput struct {
	name string
	body []byte
}

func (h *desktopLinuxNodeHost) privateInputs() []desktopLinuxPrivateInput {
	if h.external != nil && h.launch != nil && h.launch.external != nil {
		return []desktopLinuxPrivateInput{{"sing-box.json", h.launch.config},
			{"source.json", h.launch.external.source}, {"capture.json", h.launch.external.capture}}
	}
	return []desktopLinuxPrivateInput{{"sing-box.json", h.launch.config}, {"capture.json", h.launch.metadata}, {"node-source.json", h.source}}
}

// The external command has the same inherited parent layout and bounded
// public digests, but remains a different CLI and sealed policy family.
func validateDesktopLinuxProtectedArguments(arguments []string, directory string) ([]string, error) {
	if len(arguments) == 11 && arguments[0] == "routervpn-external" {
		copied := append([]string(nil), arguments...)
		copied[0] = "routervpn-node"
		validated, err := validateDesktopNodeProcessArguments(copied, directory)
		if err != nil {
			return nil, err
		}
		validated[0] = "routervpn-external"
		return validated, nil
	}
	return validateDesktopNodeProcessArguments(arguments, directory)
}

func desktopLinuxExternalEligible(launch *desktopNodeLaunch) bool {
	if launch == nil || launch.external == nil || launch.tor != nil || !launch.external.direct || launch.external.predecessor != "" ||
		launch.external.selection != "local" || launch.external.profile.External == nil ||
		desktopOwnedNodeProtectionPolicy(launch.external.profile) == "off" {
		return false
	}
	switch launch.external.profile.External.Protocol {
	case "shadowsocks", "http-connect", "https-connect", "hysteria2", "wireguard", "amneziawg", "openvpn":
		return true
	}
	return false
}

// Compare the literal launch copy against the saved original by applying only
// the captured Direct/Local selection and its one frozen outer endpoint. All
// credentials, selected DNS, MTU and device policy remain in the comparison.
func validateDesktopLinuxExternalSource(profile common.RouterProfile, launch *desktopNodeLaunch) error {
	if !desktopLinuxExternalEligible(launch) || launch.profileID != profile.ID || launch.policyProfileID != profile.ID {
		return errors.New("Linux external source lost its exact direct saved profile")
	}
	owner := launch.external
	selected, err := externalRuntimePolicy(profile)
	if err != nil {
		return err
	}
	selected, err = externalDNSPolicyForPath(selected, common.RouterProfile{}, true)
	if err != nil {
		return err
	}
	selected.MultihopEnabled, selected.MultihopEntryID, selected.MultihopExitID = false, "", ""
	selected.MultihopExecution, selected.MultihopEntryMode = "local", ""
	selected, err = freezeDesktopExternalProfile(selected, launch.endpoint)
	if err != nil || desktopOwnedNodeProfileToken(selected) != desktopOwnedNodeProfileToken(owner.profile) ||
		[3]bool{selected.DAITAEnabled, selected.JumboTUN, selected.SocksEnabled} != [3]bool{owner.profile.DAITAEnabled, owner.profile.JumboTUN, owner.profile.SocksEnabled} {
		return errors.Join(err, errors.New("Linux external source substituted private policy or credentials"))
	}
	original, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil || owner.physical == nil || owner.physical.Validate() != nil ||
		original.SourceSHA256() != owner.physical.OriginalPolicy().SourceSHA256() || original.Config() != owner.physical.OriginalPolicy().Config() ||
		original.Metadata() != owner.physical.OriginalPolicy().Metadata() {
		return errors.Join(err, errors.New("Linux external source lost its independently sealed original graph"))
	}
	var captured struct {
		Profile common.RouterProfile `json:"profile"`
	}
	if json.Unmarshal(owner.capture, &captured) != nil || desktopOwnedNodeProfileToken(captured.Profile) != desktopOwnedNodeProfileToken(owner.profile) {
		return errors.New("Linux external source changed its captured original profile")
	}
	return nil
}

func (h *desktopLinuxNodeHost) currentExternal(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil || h.operation == nil || h.closing || h.closed || h.parent == nil ||
		h.policy != nil || h.external == nil || h.external.Validate() != nil || h.launch == nil || h.launch.external == nil ||
		h.launch.external.physical != h.external || h.network == "" || physicalNetworkIdentity() != h.network {
		return errors.New("Linux external host lost its original captured operation and policy")
	}
	if h.activation == nil {
		if h.operation.Err() != nil {
			return errConnectionOperationCancelled
		}
	} else if err := h.activation.matches(h); err != nil {
		return err
	}
	if err := h.parent.Current(ctx); err != nil {
		return err
	}
	meta := h.external.Metadata()
	owner := h.launch.external
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if meta.TargetOS != "linux" || h.selection != selection || h.launch.root != linuxOwnedControllerRoot ||
		h.launch.profileID != owner.profile.ID || h.launch.mode != "external-"+meta.Protocol ||
		h.launch.configSHA256 != meta.ConfigSHA256 || owner.session != meta.SessionID || h.launch.mtuSession != "" ||
		!bytes.Equal(h.launch.config, []byte(h.external.Config())) || owner.network != h.network ||
		!bytes.Equal(h.source, owner.source) || owner.retained == nil {
		return errors.New("Linux external host changed its original sealed command")
	}
	a := h.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(h.launch.profileID)
	revision := desktopOwnedNodeProfileToken(profile)
	if !exists || (revision != h.revision && (h.activation == nil || revision != h.externalPersistedRevision)) ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options || validateDesktopLinuxExternalSource(profile, h.launch) != nil {
		return errors.New("Linux external host belongs to a replaced private profile or selected options")
	}
	if h.activation == nil {
		if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
			return errConnectionOperationCancelled
		}
	} else if h.process == nil || a.cmd != h.process.command || a.state.RouterID != h.launch.profileID || a.state.RuntimeMode != h.launch.mode {
		return errors.New("Linux external activation belongs to another connection")
	}
	return nil
}

func prepareDesktopRetainedExternal(a *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	return prepareDesktopRetainedExternalWith(a, launch, verifyBundledNativeContext)
}

// The verifier seam models package metadata only. Source capture, original
// parent, private staging, inherited descriptors and native proof are real.
func prepareDesktopRetainedExternalWith(a *app, launch *desktopNodeLaunch,
	verify func(context.Context, string) (string, error)) (desktopExternalRetainedRuntime, error) {
	if a == nil || !desktopLinuxExternalEligible(launch) {
		return nil, nil
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil, nil // The legacy guard still decides whether that distinct path may start.
	}
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return nil, err
	}
	if err := a.resumeDesktopLinuxEmptyRecovery(operation); err != nil {
		return nil, err
	}
	a.mu.Lock()
	before := &desktopLinuxNodeConnectPreflight{app: a, operation: operation, controller: controller, command: a.cmd, state: a.state,
		selected: a.profiles.SelectedID}
	a.mu.Unlock()
	var err error
	before.prior, err = a.captureDesktopNodeStop()
	if err != nil {
		return nil, err
	}
	h, err := prepareDesktopLinuxExternalHost(operation, a, launch, verify)
	if h == nil {
		return nil, err
	}
	adapter, _ := launch.external.retained.(*desktopLinuxExternalConnection)
	if adapter == nil || adapter.host != h {
		return nil, errors.Join(err, errors.New("Linux external preparation lost its original adapter"))
	}
	adapter.preflight = before
	before.host = h
	if err == nil {
		adapter.session, err = captureDesktopLinuxNodeSession(operation, a)
		before.session = adapter.session
	}
	if err == nil {
		err = before.current(operation)
	}
	return adapter, err
}

func prepareDesktopLinuxExternalHost(operation context.Context, a *app, launch *desktopNodeLaunch,
	verify func(context.Context, string) (string, error)) (*desktopLinuxNodeHost, error) {
	if operation == nil || operation.Err() != nil || a == nil || verify == nil || !desktopLinuxExternalEligible(launch) ||
		launch.command != nil || launch.directory != "" || launch.root != linuxOwnedControllerRoot || launch.external.retained != nil {
		return nil, errors.New("Linux external preparation requires its unused installed protected graph")
	}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(operation, 45*time.Second)
	stop := context.AfterFunc(parent.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil || launch.external.physical == nil {
		return nil, errors.Join(err, errors.New("Linux external graph has no exact retained physical policy"))
	}
	policy := launch.external.physical
	capture, err := policy.Capture()
	if err != nil {
		return nil, err
	}
	physical, err := captureDesktopLinuxRunningPath(capture.PhysicalRoots, capture.IPv6Mode)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(launch.profileID)
	options := [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks}
	a.mu.Unlock()
	if !exists || validateDesktopLinuxExternalSource(profile, launch) != nil {
		return nil, errors.New("Linux external preparation changed its original saved profile")
	}
	meta := policy.Metadata()
	launch.configSHA256 = meta.ConfigSHA256
	h := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: parent, operation: operation, external: policy, launch: launch,
		source: append([]byte(nil), launch.external.source...), network: launch.external.network,
		revision: desktopOwnedNodeProfileToken(profile), options: options,
		savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, physical: physical,
		selection: linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
			ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess},
		monitor: &atomic.Pointer[desktopLinuxNodeMonitor]{}}
	// Successful interactive Connect persists exactly this already captured
	// Direct/Local choice. Its accepted source revision remains in the journal.
	persisted := cloneRouterProfile(profile)
	persisted.MultihopEnabled, persisted.MultihopEntryID, persisted.MultihopExitID = false, "", ""
	persisted.MultihopExecution, persisted.MultihopEntryMode = "local", ""
	h.externalPersistedRevision = desktopOwnedNodeProfileToken(persisted)
	adapter := &desktopLinuxExternalConnection{host: h, verify: verify}
	launch.external.retained = adapter
	if err := h.current(ctx); err != nil {
		clear(h.source)
		launch.external.retained = nil
		return nil, err
	}
	image, err := verify(ctx, linuxOwnedControllerRoot)
	if err != nil || filepath.Clean(image) != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		clear(h.source)
		launch.external.retained = nil
		return nil, errors.Join(err, errors.New("Linux external preparation verified another installed image"))
	}
	if err := preflightDesktopExternalLaunch(ctx, image, launch, runDesktopExternalPreflightCommand); err != nil {
		clear(h.source)
		launch.external.retained = nil
		return nil, err
	}
	p := parent.parent
	select {
	case <-ctx.Done():
		clear(h.source)
		launch.external.retained = nil
		return nil, ctx.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		clear(h.source)
		launch.external.retained = nil
		return nil, err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[h] = struct{}{}
	p.gate <- struct{}{}
	h.gate <- struct{}{}
	return h, h.current(ctx)
}

func newDesktopLinuxExternalTransaction(h *desktopLinuxNodeHost, journal *desktopLinuxNodeJournal,
	predecessor *desktopLinuxNodeTransaction) (*desktopLinuxNodeTransaction, error) {
	if h == nil || h.current(h.operation) != nil || h.policy != nil || h.external == nil || h.process == nil || !h.process.Started() ||
		journal == nil || !sameDesktopLinuxParentCapture(h.parent, journal.parent) || !sameDesktopLinuxParentCapture(h.parent, h.process.parent) {
		return nil, errors.New("Linux external transaction lost its original typed source and process")
	}
	t := &desktopLinuxNodeTransaction{gate: make(chan struct{}, 1), parent: h.parent, journal: journal, process: h.process,
		external: h.external, mode: h.launch.mode, operation: h.operation, selection: h.selection, profileID: h.launch.profileID,
		revision: h.revision, network: h.network, options: h.options, savedOptions: h.savedOptions, predecessor: predecessor}
	return finishDesktopLinuxNodeTransaction(t)
}

func (t *desktopLinuxNodeTransaction) validatePolicy() error {
	if t.policy != nil && t.external == nil {
		return t.policy.Validate()
	}
	if t.external != nil && t.policy == nil && t.external.Validate() == nil {
		meta := t.external.Metadata()
		wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
			ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
		if meta.TargetOS == "linux" && t.selection == wanted && t.mode == "external-"+meta.Protocol {
			return nil
		}
	}
	return errors.New("Linux transaction lost its unique original typed policy")
}

func (t *desktopLinuxNodeTransaction) runtimeMode() string {
	if t.policy != nil && t.external == nil {
		return t.policy.Metadata().Mode
	}
	return t.mode
}
