package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The captured host is retained across temporary paths. Only the latest joined
// protection predecessor changes during restoration; package, controller and
// original private policy are never selected again from mutable app settings.
type desktopWindowsExternalHost struct {
	app     *app
	host    desktopNodeConnectionHost
	capture desktopOwnedNodePreparation
}

func (host *desktopWindowsExternalHost) current() error {
	if host == nil || host.app == nil || host.capture.lifetime == nil || host.capture.current == nil ||
		host.host.startExternal == nil || host.host.verify == nil || host.host.externalPreflight == nil ||
		!filepath.IsAbs(host.capture.packageRoot) || !filepath.IsAbs(host.capture.dataRoot) {
		return errors.New("native external connection lost its captured Windows host")
	}
	if err := host.capture.lifetime.Err(); err != nil {
		return err
	}
	return host.capture.current()
}

func (host *desktopWindowsExternalHost) currentContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native external observation requires its caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if host == nil || host.app == nil || host.capture.lifetime == nil || host.capture.currentContext == nil || host.host.startExternal == nil || host.host.verify == nil || host.host.externalPreflight == nil || !filepath.IsAbs(host.capture.packageRoot) || !filepath.IsAbs(host.capture.dataRoot) {
		return errors.New("native external observation lost its explicit captured Windows host")
	}
	if err := host.capture.lifetime.Err(); err != nil {
		return err
	}
	return errors.Join(host.capture.currentContext(ctx), ctx.Err())
}

func (host *desktopWindowsExternalHost) protectionSlot() (*desktopNodeProtectionSlot, error) {
	if err := host.current(); err != nil {
		return nil, err
	}
	a := host.app
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot != nil {
		return slot, host.current()
	}
	// Explicit On-connect release can remove an empty slot. Recreate its
	// backend from the original controller capability, never a fresh global
	// selection after a temporary path or package change.
	if host.capture.protectionBackend == nil {
		return nil, errors.New("native external protection lost its captured controller backend")
	}
	backend, err := host.capture.protectionBackend()
	if err != nil {
		return nil, err
	}
	if err := host.current(); err != nil {
		return nil, err
	}
	candidate := &desktopNodeProtectionSlot{backend: backend}
	a.mu.Lock()
	if a.nodeProtection != nil || a.controllerClosingLocked() {
		a.mu.Unlock()
		return nil, errors.New("native external protection cannot replace another application slot")
	}
	a.nodeProtection = candidate
	a.mu.Unlock()
	return candidate, host.current()
}

type desktopWindowsExternalRuntime struct {
	app                                            *app
	launch                                         *desktopNodeLaunch
	host                                           *desktopWindowsExternalHost
	policy                                         *mobilemultihop.DesktopExternalPolicy
	operation                                      context.Context
	profileToken, persistedToken, entryToken       string
	options, savedOptions                          [3]bool
	beforeCommand                                  *exec.Cmd
	beforeState                                    state
	beforeSelected                                 string
	stageDirectory                                 string
	gate                                           chan struct{}
	mu                                             sync.Mutex
	slot                                           *desktopNodeProtectionSlot
	attempt                                        *desktopNodeProtectionAttempt
	process                                        desktopNodeProcess
	done                                           chan struct{}
	waitErr                                        error
	startEntered                                   bool
	staged, published                              bool
	activated, retiring, retired, closed, finished bool
	proof                                          *mobilemultihop.ExternalProofResult
	monitorCancel                                  context.CancelFunc
	monitorDone                                    chan struct{}
}

// An unstarted private workspace still has an owner if its checked removal
// fails. It is retried before a later preparation and during shutdown; it can
// never replace the active external registry or consume a protection target.
var desktopWindowsExternalPreparations sync.Map // *desktopWindowsExternalRuntime -> *app

// Selection names only the supported shape. Full original credentials and
// paired layer identity are compiled before a prior owner can be retired.
func desktopExternalStartLayerSupported(protocol, layer string) bool {
	return layer == "" || layer == common.StartLayerOff || protocol == "hysteria2" &&
		(layer == common.StartLayerAES256GCM || layer == common.StartLayerAES256GCMXOR)
}

func desktopWindowsExternalProfileEligible(profile common.RouterProfile, direct bool, restored string) bool {
	if (!direct && !desktopWindowsExternalSSEntryFinalProfile(profile)) || profile.NodeKind != "external" || profile.External == nil ||
		!desktopExternalStartLayerSupported(profile.External.Protocol, profile.StartLayer) ||
		profile.MultihopExecution != "" && profile.MultihopExecution != "local" || restored != "" && restored != "local" {
		return false
	}
	policy := desktopOwnedNodeProtectionPolicy(profile)
	if policy != "on-connect" && policy != "always" {
		return false
	}
	switch profile.External.Protocol {
	case "shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5", "wireguard", "amneziawg", "openvpn":
		return true
	}
	return false
}

func desktopWindowsExternalEligible(launch *desktopNodeLaunch) bool {
	return launch != nil && launch.ownedNode == nil && launch.tor == nil && launch.external != nil &&
		launch.external.predecessor == "" && launch.external.selection == "local" &&
		launch.policyProfileID == launch.external.profile.ID &&
		(launch.external.direct && launch.profileID == launch.policyProfileID || !launch.external.direct && launch.profileID == launch.external.entry.ID) &&
		desktopWindowsExternalGraphEligible(launch.external.profile, launch.external.entry, launch.external.direct, "")
}

func captureDesktopWindowsExternalHost(a *app, supplied *desktopNodeConnectionHost) (*desktopWindowsExternalHost, error) {
	if a == nil || supplied == nil || supplied.capture == nil || supplied.verify == nil || supplied.lookup == nil ||
		supplied.startExternal == nil || supplied.externalPreflight == nil {
		return nil, errors.New("native external preparation has no complete Windows host")
	}
	host := *supplied
	capture, err := host.capture(a)
	if err != nil {
		return nil, err
	}
	owner := &desktopWindowsExternalHost{app: a, host: host, capture: capture}
	return owner, owner.current()
}

func prepareDesktopWindowsExternalLaunch(a *app, host *desktopNodeConnectionHost, profile, entry common.RouterProfile,
	exit standardExit, direct bool, restored string) (*desktopNodeLaunch, error) {
	if !desktopWindowsExternalGraphEligible(profile, entry, direct, restored) {
		return nil, errors.New("native external preparation requires its captured Local Windows graph")
	}
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return nil, err
	}
	captured, err := captureDesktopWindowsExternalHost(a, host)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(operation, 30*time.Second)
	stop := context.AfterFunc(captured.capture.lifetime, cancel)
	defer func() { stop(); cancel() }()
	network := physicalNetworkIdentity()
	if network == "" {
		return nil, errors.New("native external preparation has no captured physical network")
	}
	binary, err := captured.host.verify(ctx, captured.capture.packageRoot)
	if err != nil || !sameDesktopNodeProcessPath(binary, filepath.Join(captured.capture.packageRoot, "runtime", "native", nativeBinaryName())) {
		return nil, errors.Join(err, errors.New("native external verification selected another captured package"))
	}
	launch, err := compileDesktopExternalCaptured(ctx, profile, entry, exit, direct, restored, nil, nil, captured.host.lookup)
	if err != nil {
		return nil, err
	}
	launch.root, launch.external.network, launch.external.windowsHost = captured.capture.dataRoot, network, captured
	if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil || launch.external.physical == nil {
		return nil, errors.Join(err, errors.New("native external preparation has no exact physical policy"))
	}
	launch.configSHA256 = launch.external.physical.Metadata().ConfigSHA256
	if err := captured.current(); err != nil {
		return nil, err
	}
	if err := preflightDesktopExternalLaunch(ctx, binary, launch, captured.host.externalPreflight); err != nil {
		return nil, err
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil || ctx.Err() != nil || physicalNetworkIdentity() != network {
		return nil, errors.Join(err, ctx.Err(), errors.New("native external preparation changed its request or physical network"))
	}
	return launch, captured.current()
}

// This comparison permits only the explicit Direct/Local projection and its
// already frozen endpoint. Credentials, trust, DNS, device policy and complete
// imported source remain tied to the same saved external node.
func validateDesktopWindowsExternalSource(profile common.RouterProfile, launch *desktopNodeLaunch) error {
	if !desktopWindowsExternalEligible(launch) || profile.ID != launch.policyProfileID {
		return errors.New("native external source lost its exact saved node")
	}
	owner := launch.external
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return validateDesktopWindowsExternalSourceLocked(profile, launch)
}
func validateDesktopWindowsExternalSourceContext(ctx context.Context, profile common.RouterProfile, launch *desktopNodeLaunch) error {
	if ctx == nil {
		return errors.New("native external source observation omitted caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !desktopWindowsExternalEligible(launch) || profile.ID != launch.policyProfileID {
		return errors.New("native external source lost its exact saved node")
	}
	if err := mobilemtu.LockContext(ctx, &launch.external.mu); err != nil {
		return err
	}
	defer launch.external.mu.Unlock()
	return errors.Join(validateDesktopWindowsExternalSourceLocked(profile, launch), ctx.Err())
}
func validateDesktopWindowsExternalSourceLocked(profile common.RouterProfile, launch *desktopNodeLaunch) error {
	if !desktopWindowsExternalEligible(launch) || profile.ID != launch.policyProfileID {
		return errors.New("native external source lost its exact saved node")
	}
	owner := launch.external
	if !owner.direct {
		return validateDesktopRetainedExternalSourcesLocked(profile, owner.entry, launch)
	}
	selected, err := externalRuntimePolicy(profile)
	if err == nil {
		selected, err = externalDNSPolicyForPath(selected, common.RouterProfile{}, true)
	}
	if err != nil {
		return err
	}
	selected.MultihopEnabled, selected.MultihopEntryID, selected.MultihopExitID = false, "", ""
	selected.MultihopExecution, selected.MultihopEntryMode = "local", ""
	selected, err = freezeDesktopExternalProfile(selected, launch.endpoint)
	if err != nil || desktopOwnedNodeProfileToken(selected) != desktopOwnedNodeProfileToken(owner.profile) ||
		[3]bool{selected.DAITAEnabled, selected.JumboTUN, selected.SocksEnabled} != [3]bool{owner.profile.DAITAEnabled, owner.profile.JumboTUN, owner.profile.SocksEnabled} {
		return errors.Join(err, errors.New("native external source substituted private settings or credentials"))
	}
	original, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil || owner.physical == nil || owner.physical.Validate() != nil ||
		original.SourceSHA256() != owner.physical.OriginalPolicy().SourceSHA256() || original.Config() != owner.physical.OriginalPolicy().Config() ||
		original.Metadata() != owner.physical.OriginalPolicy().Metadata() {
		return errors.Join(err, errors.New("native external source lost its independently sealed original policy"))
	}
	var captured struct {
		Profile common.RouterProfile `json:"profile"`
	}
	if json.Unmarshal(owner.capture, &captured) != nil || desktopOwnedNodeProfileToken(captured.Profile) != desktopOwnedNodeProfileToken(owner.profile) {
		return errors.New("native external source changed its captured private profile")
	}
	return nil
}

func prepareDesktopRetainedExternalForLaunch(a *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	if launch != nil && launch.external != nil && launch.external.windowsHost != nil {
		return prepareDesktopWindowsRetainedExternal(a, launch)
	}
	return prepareDesktopRetainedExternal(a, launch)
}

func preflightDesktopWindowsExternalRestore(a *app, launch *desktopNodeLaunch) error {
	if a == nil || launch == nil || launch.external == nil || launch.external.windowsHost == nil || launch.external.physical == nil {
		return errors.New("native external restore has no original Windows package capture")
	}
	host := launch.external.windowsHost
	if host.app != a || host.current() != nil || launch.root != host.capture.dataRoot || launch.external.network != physicalNetworkIdentity() {
		return errors.New("native external restore changed its original controller or physical path")
	}
	operation := a.connectionOperationContextOrBackground()
	ctx, cancel := context.WithTimeout(operation, 30*time.Second)
	stop := context.AfterFunc(host.capture.lifetime, cancel)
	defer func() { stop(); cancel() }()
	binary, err := host.host.verify(ctx, host.capture.packageRoot)
	if err != nil || !sameDesktopNodeProcessPath(binary, filepath.Join(host.capture.packageRoot, "runtime", "native", nativeBinaryName())) {
		return errors.Join(err, errors.New("native external restore selected another package"))
	}
	if err := preflightDesktopExternalLaunch(ctx, binary, launch, host.host.externalPreflight); err != nil {
		return err
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return err
	}
	return errors.Join(ctx.Err(), host.current())
}

func prepareDesktopWindowsRetainedExternal(a *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
	if a == nil || !desktopWindowsExternalEligible(launch) || launch.external.windowsHost == nil || launch.external.windows != nil {
		return nil, errors.New("native external launch lost its original prepared Windows host")
	}
	if err := a.retryDesktopWindowsExternalPreparations(); err != nil {
		return nil, err
	}
	host := launch.external.windowsHost
	if host.app != a || host.current() != nil || launch.root != host.capture.dataRoot {
		return nil, errors.New("native external launch changed its original controller or Data root")
	}
	if launch.external.physical == nil {
		if err := prepareDesktopExternalPhysical(launch, "windows"); err != nil {
			return nil, err
		}
	}
	policy := launch.external.physical
	if _, err := desktopProtectionSelectionFor(nil, policy); err != nil {
		return nil, err
	}
	operation := a.connectionOperationContextOrBackground()
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(launch.policyProfileID)
	owner := &desktopWindowsExternalRuntime{app: a, launch: launch, host: host, policy: policy, operation: operation,
		profileToken: desktopOwnedNodeProfileToken(profile), options: [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks},
		savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, beforeCommand: a.cmd,
		beforeState: a.state, beforeSelected: a.profiles.SelectedID, gate: make(chan struct{}, 1)}
	entry, entryExists := a.profileByIDLocked(launch.external.entry.ID)
	if !launch.external.direct && entryExists {
		owner.entryToken = desktopOwnedNodeProfileToken(entry)
	}
	a.mu.Unlock()
	if !exists || !launch.external.direct && !entryExists || validateDesktopWindowsExternalSource(profile, launch) != nil {
		return nil, errors.New("native external launch changed its captured saved source")
	}
	persisted := cloneRouterProfile(profile)
	persisted.MultihopEnabled, persisted.MultihopEntryID, persisted.MultihopExitID = !launch.external.direct, launch.external.entry.ID, ""
	if !launch.external.direct {
		persisted.MultihopExitID = profile.ID
	}
	persisted.MultihopExecution, persisted.MultihopEntryMode = "local", ""
	owner.persistedToken = desktopOwnedNodeProfileToken(persisted)
	owner.gate <- struct{}{}
	launch.configSHA256 = policy.Metadata().ConfigSHA256
	launch.external.windows, launch.external.retained = owner, owner
	if err := owner.current(false); err != nil {
		launch.external.windows, launch.external.retained = nil, nil
		return nil, err
	}
	desktopWindowsExternalPreparations.Store(owner, a)
	return owner, nil
}

func (owner *desktopWindowsExternalRuntime) enter(ctx context.Context) error {
	if owner == nil || ctx == nil || owner.gate == nil {
		return errors.New("native external operation has no captured lifecycle owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.gate:
		return nil
	}
}

// This guard deliberately never locks the protection slot. Its journal invokes
// it while holding that slot; proof adoption separately checks the exact active
// attempt. A zero process/observer is never accepted as positive liveness.
func (owner *desktopWindowsExternalRuntime) current(processRequired bool) error {
	if owner == nil || owner.app == nil || owner.launch == nil || owner.host == nil || owner.host.app != owner.app ||
		owner.policy == nil || owner.policy.Validate() != nil || owner.operation == nil || owner.launch.ownedNode != nil ||
		owner.launch.external == nil || owner.launch.external.windows != owner || owner.launch.external.retained != owner ||
		owner.launch.external.windowsHost != owner.host || owner.launch.external.physical != owner.policy {
		return errors.New("native external owner changed its captured policy family")
	}
	if err := owner.host.current(); err != nil {
		return err
	}
	l, a := owner.launch, owner.app
	if l.root != owner.host.capture.dataRoot || l.policyProfileID != l.external.profile.ID || l.mode != "external-"+owner.policy.Metadata().Protocol ||
		l.external.network == "" || l.external.network != l.external.currentNetworkIdentity() || l.configSHA256 != owner.policy.Metadata().ConfigSHA256 {
		return errors.New("native external owner changed its captured runtime or network")
	}
	owner.mu.Lock()
	activated, published, retiring, retired, closed := owner.activated, owner.published, owner.retiring, owner.retired, owner.closed
	process, done, slot := owner.process, owner.done, owner.slot
	owner.mu.Unlock()
	if retiring || retired || closed {
		return errors.New("native external owner is retired")
	}
	// Always acquire the source before app state. A bounded source observer
	// must not retain app.mu while waiting for another proof reader.
	l.external.mu.Lock()
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(l.policyProfileID)
	revision := desktopOwnedNodeProfileToken(profile)
	valid := exists && !a.closing && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == owner.options &&
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == owner.savedOptions &&
		(revision == owner.profileToken || activated && revision == owner.persistedToken) && owner.sourcesCurrentLocked(profile) == nil
	if !activated {
		valid = valid && a.checkCapturedConnectionOperationLocked(owner.operation) == nil && a.connectionCancelIntent != owner.operation
	}
	if published {
		valid = valid && slot != nil && a.nodeProtection == slot && a.cmd == l.command && a.state.RouterID == l.policyProfileID && a.state.RuntimeMode == l.mode
	}
	a.mu.Unlock()
	l.external.mu.Unlock()
	if !valid {
		return errors.New("native external owner belongs to a replaced request, private source or runtime")
	}
	if published {
		if current, ok := desktopExternalRetainedLaunches.Load(a); !ok || current != l {
			return errors.New("native external owner lost its exact retained registry entry")
		}
		if _, legacy := desktopNodeOwners.Load(a); legacy {
			return errors.New("native external owner cannot share a legacy runtime registry")
		}
	}
	if processRequired {
		if !published || process == nil || !process.Started() || done == nil {
			return errors.New("native external owner has no actual retained child and exit observer")
		}
		select {
		case <-done:
			return errors.New("native external owner's exact child exited")
		default:
		}
		return process.Alive()
	}
	return nil
}

func (owner *desktopWindowsExternalRuntime) currentContext(ctx context.Context, processRequired bool) error {
	if ctx == nil {
		return errors.New("native external owner observation omitted original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if owner == nil || owner.app == nil || owner.launch == nil || owner.host == nil || owner.host.app != owner.app ||
		owner.policy == nil || owner.policy.Validate() != nil || owner.operation == nil || owner.launch.ownedNode != nil ||
		owner.launch.external == nil || owner.launch.external.windows != owner || owner.launch.external.retained != owner ||
		owner.launch.external.windowsHost != owner.host || owner.launch.external.physical != owner.policy {
		return errors.New("native external owner changed its captured policy family")
	}
	if err := owner.host.currentContext(ctx); err != nil {
		return err
	}
	l, a := owner.launch, owner.app
	network, err := l.external.currentNetworkIdentityContext(ctx)
	if err != nil {
		return err
	}
	if l.root != owner.host.capture.dataRoot || l.policyProfileID != l.external.profile.ID || l.mode != "external-"+owner.policy.Metadata().Protocol ||
		l.external.network == "" || l.external.network != network || l.configSHA256 != owner.policy.Metadata().ConfigSHA256 {
		return errors.New("native external owner changed its captured runtime or network")
	}
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	activated, published, retiring, retired, closed := owner.activated, owner.published, owner.retiring, owner.retired, owner.closed
	process, done, slot := owner.process, owner.done, owner.slot
	owner.mu.Unlock()
	if retiring || retired || closed {
		return errors.New("native external owner is retired")
	}
	// Match the source-before-app order used by legacy and DNS observations,
	// but never poll one mutex while retaining the other. A legacy reader can
	// block on either mutex and must remain able to finish while we wait.
	for {
		if err := mobilemtu.LockContext(ctx, &l.external.mu); err != nil {
			return err
		}
		if a.mu.TryLock() {
			break
		}
		l.external.mu.Unlock()
		if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
			return err
		}
		a.mu.Unlock()
	}
	profile, exists := a.profileByIDLocked(l.policyProfileID)
	revision := desktopOwnedNodeProfileToken(profile)
	sourceErr := owner.sourcesCurrentLocked(profile)
	valid := exists && !a.closing && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == owner.options &&
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} == owner.savedOptions &&
		(revision == owner.profileToken || activated && revision == owner.persistedToken)
	if !activated {
		valid = valid && a.checkCapturedConnectionOperationLocked(owner.operation) == nil && a.connectionCancelIntent != owner.operation
	}
	if published {
		valid = valid && slot != nil && a.nodeProtection == slot && a.cmd == l.command && a.state.RouterID == l.policyProfileID && a.state.RuntimeMode == l.mode
	}
	a.mu.Unlock()
	l.external.mu.Unlock()
	if sourceErr != nil {
		return errors.Join(sourceErr, ctx.Err())
	}
	if !valid {
		return errors.Join(errors.New("native external owner belongs to a replaced request, private source or runtime"), ctx.Err())
	}
	if published {
		if current, ok := desktopExternalRetainedLaunches.Load(a); !ok || current != l {
			return errors.New("native external owner lost its exact retained registry entry")
		}
		if _, legacy := desktopNodeOwners.Load(a); legacy {
			return errors.New("native external owner cannot share a legacy runtime registry")
		}
	}
	if processRequired {
		if !published || process == nil || done == nil {
			return errors.New("native external owner has no actual retained child and exit observer")
		}
		select {
		case <-done:
			return errors.New("native external owner's exact child exited")
		default:
		}
		observer, ok := process.(interface{ AliveContext(context.Context) error })
		if !ok {
			return errors.New("native external process omitted explicit bounded observation")
		}
		return errors.Join(observer.AliveContext(ctx), ctx.Err())
	}
	return ctx.Err()
}

func (owner *desktopWindowsExternalRuntime) ProcessDone() <-chan struct{} {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.done
}

func (owner *desktopWindowsExternalRuntime) ProcessDoneContext(ctx context.Context) (<-chan struct{}, error) {
	if ctx == nil || owner == nil {
		return nil, errors.New("native external exit observation omitted caller or owner")
	}
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return nil, err
	}
	defer owner.mu.Unlock()
	if owner.done == nil {
		return nil, errors.New("native external owner has no original exit observer")
	}
	return owner.done, ctx.Err()
}

func desktopWindowsExternalProcess(launch *desktopNodeLaunch) desktopNodeProcess {
	if launch == nil || launch.ownedNode != nil || launch.external == nil || launch.external.windows == nil {
		return nil
	}
	owner := launch.external.windows
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.process
}

func (owner *desktopWindowsExternalRuntime) CurrentProof(ctx context.Context, proof desktopExternalProof) error {
	if err := owner.currentContext(ctx, true); err != nil {
		return err
	}
	if err := desktopExternalPhysicalReceiptContext(ctx, owner.launch.external, proof.Physical); err != nil {
		return err
	}
	if !proof.Healthy || !proof.DNSProven ||
		proof.EntryProven != !owner.launch.external.direct || proof.EntryID != owner.launch.external.entry.ID || proof.EntryNodeID != "" || proof.Execution != "local" {
		return errors.New("native external proof lost its actual process or distinct final exit policy")
	}
	meta := owner.policy.Metadata()
	if proof.SourceSHA256 != meta.OriginalSourceSHA256 || proof.ConfigSHA256 != meta.OriginalConfigSHA256 || proof.SessionID != meta.SessionID {
		return errors.New("native external proof substituted physical identity for its original exit proof")
	}
	network, err := desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil || network.TargetOS != "windows" || network.MTU < 1280 {
		return errors.Join(err, errors.New("native external proof has no complete Windows TUN receipt"))
	}
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	slot, attempt, captured := owner.slot, owner.attempt, owner.proof
	owner.mu.Unlock()
	if slot == nil || attempt == nil || attempt.external != owner.policy || attempt.policy != nil {
		return errors.New("native external proof lost its typed protection attempt")
	}
	if err := mobilemtu.LockContext(ctx, &slot.mu); err != nil {
		return err
	}
	valid := slot.active == attempt && attempt.prepared != nil && attempt.prepared.Capture.SessionID == meta.SessionID &&
		attempt.prepared.Capture.SourceSHA256 == meta.SourceSHA256 && attempt.prepared.Policy == meta.KillSwitchPolicy
	slot.mu.Unlock()
	if !valid || captured != nil && *captured != proof.ExternalProofResult {
		return errors.New("native external proof lost its original admitted protection or proved path")
	}
	return errors.Join(ctx.Err(), owner.currentContext(ctx, true))
}

func (owner *desktopWindowsExternalRuntime) Activate(ctx context.Context) error {
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	proof, err := owner.app.readDesktopExternalProof(owner.launch)
	if err != nil {
		return err
	}
	if err := owner.current(true); err != nil {
		return err
	}
	a := owner.app
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(owner.launch.policyProfileID)
	if ctx.Err() != nil || a.checkCapturedConnectionOperationLocked(owner.operation) != nil || a.connectionCancelIntent == owner.operation ||
		!exists || desktopOwnedNodeProfileToken(profile) != owner.profileToken || a.cmd != owner.launch.command || a.closing ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != owner.options ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != owner.savedOptions || owner.host.capture.lifetime.Err() != nil {
		return errors.New("native external activation belongs to a replaced request, source or controller")
	}
	if !owner.entryCurrentLocked() {
		return errors.New("native external activation replaced its original entry source")
	}
	owner.mu.Lock()
	if owner.activated || owner.proof != nil || owner.retired || owner.closed {
		owner.mu.Unlock()
		return errors.New("native external activation has no unused original proof")
	}
	owner.proof = &proof.ExternalProofResult
	owner.activated = true
	owner.mu.Unlock()
	return nil
}

func (owner *desktopWindowsExternalRuntime) capturedFilesCurrent() error {
	for _, value := range []struct {
		name string
		body []byte
	}{{"sing-box.json", []byte(owner.policy.Config())}, {"source.json", owner.launch.external.source}, {"capture.json", owner.launch.external.capture}} {
		actual, err := readDesktopRuntimeFile(owner.launch, value.name, 8<<20)
		same := err == nil && bytes.Equal(actual, value.body)
		clear(actual)
		if !same {
			return errors.Join(err, errors.New("native external workspace changed its captured private input"))
		}
	}
	return nil
}

func (owner *desktopWindowsExternalRuntime) Stage(ctx context.Context) error {
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	if err := owner.current(false); err != nil {
		return err
	}
	if err := owner.app.guardDesktopOwnedNodeTransition(owner.launch); err != nil {
		return err
	}
	a := owner.app
	a.mu.Lock()
	unchanged := a.cmd == owner.beforeCommand && a.profiles.SelectedID == owner.beforeSelected &&
		a.state.Mode == owner.beforeState.Mode && a.state.RuntimeMode == owner.beforeState.RuntimeMode &&
		a.state.RouterID == owner.beforeState.RouterID && a.state.Connected == owner.beforeState.Connected
	a.mu.Unlock()
	if !unchanged {
		return errors.New("native external staging cannot replace a changed prior connection")
	}
	owner.mu.Lock()
	unused := !owner.staged && owner.attempt == nil && owner.process == nil && owner.launch.directory == ""
	owner.mu.Unlock()
	if !unused {
		return errors.New("native external private workspace was already staged")
	}
	directory, err := newPrivateRuntimeDir(owner.host.capture.dataRoot, "native-node")
	if err != nil {
		return err
	}
	owner.stageDirectory = directory
	if err := captureDesktopRuntimeDirectory(owner.launch, directory); err != nil {
		return err
	}
	for _, input := range []struct {
		name string
		body []byte
	}{{"sing-box.json", []byte(owner.policy.Config())}, {"source.json", owner.launch.external.source}, {"capture.json", owner.launch.external.capture}} {
		if err := writeDesktopRuntimeFile(owner.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	if err := owner.capturedFilesCurrent(); err != nil {
		return err
	}
	owner.mu.Lock()
	owner.staged = true
	owner.mu.Unlock()
	return errors.Join(ctx.Err(), owner.current(false))
}

func desktopWindowsExternalArguments(launch *desktopNodeLaunch) ([]string, error) {
	if launch == nil || launch.external == nil || launch.external.windows == nil || launch.ownedNode != nil {
		return nil, errors.New("native external command has no typed Windows owner")
	}
	owner := launch.external.windows
	owner.mu.Lock()
	attempt := owner.attempt
	owner.mu.Unlock()
	if attempt == nil || attempt.launch != launch || attempt.external != owner.policy || attempt.policy != nil {
		return nil, errors.New("native external command lost its exact protection transfer")
	}
	meta := owner.policy.Metadata()
	return validateDesktopExternalProcessArguments([]string{"routervpn-external", "--runtime-dir", launch.directory,
		"--session", meta.SessionID, "--config-sha256", meta.ConfigSHA256,
		"--physical-source-sha256", meta.SourceSHA256, "--physical-transfer-sha256", attempt.digest}, launch.directory)
}

func (owner *desktopWindowsExternalRuntime) Start(ctx context.Context) error {
	if err := owner.enter(ctx); err != nil {
		return err
	}
	defer func() { owner.gate <- struct{}{} }()
	if err := owner.current(false); err != nil {
		return err
	}
	owner.mu.Lock()
	unused := owner.staged && owner.process == nil && owner.attempt == nil && !owner.published && !owner.activated
	owner.mu.Unlock()
	if !unused || ctx != owner.operation || owner.app.checkCapturedConnectionOperation(ctx) != nil {
		return errors.New("native external start lost its unused staged operation")
	}
	a, launch := owner.app, owner.launch
	a.mu.Lock()
	empty := a.cmd == nil && !a.state.Connected
	a.mu.Unlock()
	if _, exists := lookupDesktopNativeLaunch(a); !empty || exists {
		return errors.New("native external start cannot replace an unjoined runtime")
	}
	if err := owner.capturedFilesCurrent(); err != nil {
		return err
	}
	slot, err := owner.host.protectionSlot()
	if err == nil {
		err = a.ensureDesktopNodeRecovery(ctx, slot)
	}
	if err == nil {
		err = a.ensureDesktopNodeJournalForStart(ctx, slot)
	}
	if err != nil {
		return err
	}
	attempt, err := slot.beginExternal(ctx, launch, owner.policy, owner.profileToken)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	owner.slot, owner.attempt = slot, attempt
	owner.mu.Unlock()
	raw, err := json.Marshal(attempt.transfer)
	if err == nil {
		err = writeDesktopRuntimeFile(launch, "external-protection-transfer.json", raw, false)
	}
	if err != nil {
		return err
	}
	args, err := desktopWindowsExternalArguments(launch)
	if err != nil {
		return err
	}
	environment := desktopNativeEnvironmentForPackage(os.Environ(), launch.root, launch.profileID, "", owner.host.capture.packageRoot)
	for i, value := range environment {
		if strings.HasPrefix(value, "HOMEVPN_POLICY_PROFILE_ID=") {
			environment[i] = "HOMEVPN_POLICY_PROFILE_ID=" + launch.policyProfileID
		}
	}
	environment, err = desktopExternalPhysicalEnvironment(environment, launch.external)
	if err != nil {
		return err
	}
	command := exec.Command(filepath.Join(owner.host.capture.packageRoot, "runtime", "native", nativeBinaryName()), args...)
	command.Dir, command.Env = launch.directory, environment
	launch.command = command // Descriptor only; the host creates and retains the actual child/Job.
	a.mu.Lock()
	if a.cmd != nil || a.state.Connected || a.nodeProtection != slot || a.checkCapturedConnectionOperationLocked(ctx) != nil {
		a.mu.Unlock()
		return errors.New("native external publication lost its empty current application slot")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		a.mu.Unlock()
		return errors.New("native external publication cannot share a legacy owner")
	}
	if prior, exists := desktopExternalRetainedLaunches.LoadOrStore(a, launch); exists && prior != launch {
		a.mu.Unlock()
		return errors.New("native external publication cannot replace another retained owner")
	}
	a.cmd = command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "starting", ""
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "external-node", "external-node", launch.mode
	a.state.RouterID, a.state.Base = launch.policyProfileID, "external"
	a.mu.Unlock()
	owner.mu.Lock()
	owner.published = true
	owner.startEntered = true
	owner.mu.Unlock()
	launch.external.mu.Lock()
	launch.external.started = time.Now()
	launch.external.mu.Unlock()
	process, startErr := owner.host.host.startExternal(ctx, a, launch, args, environment, launch.directory)
	owner.mu.Lock()
	owner.process = process // Partial creation remains owned on every failed return.
	if process != nil && process.Started() {
		owner.done = make(chan struct{})
		done := owner.done
		go func() {
			_, waitErr := process.Wait(context.Background())
			owner.mu.Lock()
			owner.waitErr = waitErr
			owner.mu.Unlock()
			close(done)
		}()
	}
	owner.mu.Unlock()
	if err := owner.current(true); startErr != nil || err != nil {
		return errors.Join(startErr, err)
	}
	admission, ok := process.(desktopNodeJournalAdmission)
	if !ok {
		return errors.New("native external start omitted its actual inherited journal channel")
	}
	if err := admission.AdmitProtection(ctx); err != nil {
		return err
	}
	return errors.Join(a.checkCapturedConnectionOperation(ctx), owner.current(true))
}
