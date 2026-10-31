package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// A temporary test owns one complete connection transaction, including the
// reconnect. HTTP cancellation retires only the test child; explicit Disconnect
// cancels intent as well and therefore must never reconnect the previous VPN.
type speedLabTemporaryOwner struct {
	intent       context.Context
	cancelIntent context.CancelFunc
	test         context.Context
	cancelTest   context.CancelFunc
	current      context.Context // protected by app.mu
	runtime      *exec.Cmd       // protected by app.mu
	mutated      bool            // protected by app.mu
	restored     bool            // protected by app.mu
	network      string
}

var speedLabTemporaryOwners sync.Map // map[*app]*speedLabTemporaryOwner

type speedLabRestorePlan struct {
	profile  common.RouterProfile
	request  speedLabRequest
	native   *desktopNodeLaunch
	external *speedLabExternalRestore
	tor      *speedLabTorRestore
	multihop *multihopSelection
}

// Tor restoration retains the proved policy identity, not an old isolation
// secret, process or session. The normal Tor launcher creates fresh private
// inputs and requires a new native Tor/DNS/interface proof before adoption.
type speedLabTorRestore struct {
	profileToken string
	policyToken  string
	network      string
	mtu          int
	automaticMTU bool
	selection    *desktopTorSelection
}

func (saved *speedLabTorRestore) execution() string {
	if saved == nil || saved.selection == nil {
		return ""
	}
	return desktopTorExecution(saved.selection.policy.MultihopExecution)
}

func speedLabTorPolicy(profile common.RouterProfile) (common.RouterProfile, error) {
	if profile.NodeKind != "external" || profile.External == nil || !desktopTorProtocol(profile.External.Protocol) {
		return common.RouterProfile{}, errors.New("previous Tor connection has no captured external node")
	}
	policy, err := externalRuntimePolicy(profile)
	if err != nil {
		return common.RouterProfile{}, err
	}
	return externalDNSPolicyForPath(policy, common.RouterProfile{}, true)
}

func captureSpeedLabTorRestore(profile common.RouterProfile, identity speedLabPathIdentity) (*speedLabTorRestore, error) {
	launch := identity.Tor
	if launch == nil || launch.tor == nil || launch.external != nil || launch.profileID != profile.ID || identity.Execution == "" || identity.Execution != desktopTorExecution(launch.tor.expected.Execution) || identity.TorSession != launch.tor.expected.SessionID || liveMeasurementProfileToken(profile) != identity.ProfileToken {
		return nil, errors.New("previous Tor connection has another captured owner")
	}
	mtu, err := captureDesktopMTURestore(launch)
	if err != nil {
		return nil, err
	}
	automatic := false
	if owner := desktopMeasurementMTUSession(launch); owner != nil {
		owner.mu.Lock()
		automatic = owner.automatic
		owner.mu.Unlock()
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return nil, err
	}
	const name = "tor-profile.json"
	input, known := launch.tor.inputs[name]
	before, err := launch.directoryRoot.Lstat(name)
	if !known || err != nil || !os.SameFile(input.info, before) || !before.Mode().IsRegular() {
		return nil, errors.New("previous Tor private source was replaced")
	}
	raw, err := readDesktopRuntimeSnapshot(launch.directoryRoot, name, 4<<20)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	after, err := launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(input.info, after) || desktopTorDigest(raw) != input.digest || desktopTorDigest(raw) != launch.tor.digests.ProfileSHA256 {
		return nil, errors.New("previous Tor private source differs from its captured bytes")
	}
	// The active runtime may have explicitly overridden a saved Direct/entry
	// preference. Reconstruct its validated private capture, not that preference
	// or a fresh hostname/bootstrap selection after the old owner is stopped.
	capture, err := readDesktopRuntimeSnapshot(launch.directoryRoot, "tor-capture.json", desktopTorInputLimit("tor-capture.json"))
	defer clear(capture)
	if err != nil {
		return nil, err
	}
	decoded, err := mobiletor.DecodeDesktopBridgeCapture(string(raw), string(capture), launch.directory)
	if err != nil || decoded.Digests() != launch.tor.digests || decoded.Policy().Metadata() != launch.tor.expected || identity.TorEntry != launch.tor.predecessor {
		return nil, errors.New("previous Tor restore lost its exact native source and Router entry capture")
	}
	type runtimeWire common.RouterProfile
	var captured runtimeWire
	if json.Unmarshal(raw, &captured) != nil || captured.ID != profile.ID || captured.External == nil || !desktopTorProtocol(captured.External.Protocol) || launch.tor.sourceIdentityToken() != desktopTorSourceIdentityToken(profile) {
		return nil, errors.New("previous Tor policy differs from its captured private source")
	}
	selection := &desktopTorSelection{profile: cloneRouterProfile(profile), policy: cloneRouterProfile(common.RouterProfile(captured)), profileToken: launch.tor.sourceIdentityToken(), predecessor: launch.tor.predecessor}
	return &speedLabTorRestore{profileToken: identity.ProfileToken, policyToken: desktopTorSourceIdentityToken(selection.policy), network: identity.Network, mtu: mtu, automaticMTU: automatic, selection: selection}, nil
}

func (a *app) speedLabTorRestoreProfile(plan speedLabRestorePlan) (common.RouterProfile, error) {
	saved := plan.tor
	if saved == nil || plan.external != nil || plan.native != nil || plan.multihop != nil || plan.request.Topology != "external" || plan.request.NodeID != plan.profile.ID || saved.execution() == "" || plan.request.Execution != saved.execution() || saved.profileToken == "" || liveMeasurementProfileToken(plan.profile) != saved.profileToken {
		return common.RouterProfile{}, errors.New("previous Tor restore selection is not the captured proved execution")
	}
	if saved.network == "" || physicalNetworkIdentity() != saved.network {
		return common.RouterProfile{}, errors.New("previous Tor restore belongs to a changed physical network")
	}
	a.mu.Lock()
	current, exists := a.profileByIDLocked(plan.profile.ID)
	current = cloneRouterProfile(current)
	a.mu.Unlock()
	if !exists || liveMeasurementProfileToken(current) != saved.profileToken {
		return common.RouterProfile{}, errors.New("previous Tor restore node policy or credentials changed")
	}
	if _, err := saved.selectionFor(a, plan.profile, plan.request); err != nil {
		return common.RouterProfile{}, err
	}
	return cloneRouterProfile(plan.profile), nil
}

func (saved *speedLabTorRestore) selectionFor(a *app, profile common.RouterProfile, request speedLabRequest) (*desktopTorSelection, error) {
	if saved == nil || saved.selection == nil || saved.profileToken != liveMeasurementProfileToken(profile) || saved.selection.profileToken != desktopTorSourceIdentityToken(profile) || saved.policyToken == "" || desktopTorSourceIdentityToken(saved.selection.policy) != saved.policyToken || request.Topology != "external" || saved.execution() == "" || request.Execution != saved.execution() || request.Base != "" || request.Mode != "" || request.ExitMode != "" || request.ExitID != "" || request.NodeID != profile.ID {
		return nil, errors.New("previous Tor restore would substitute its proved source, device or DNS policy")
	}
	entryID, mode := "", ""
	if entry := saved.selection.predecessor; entry != nil {
		entryID, mode = entry.entry.ID, entry.mode
	}
	if request.EntryID != entryID || request.EntryMode != mode || saved.network == "" || physicalNetworkIdentity() != saved.network {
		return nil, errors.New("previous Tor restore would select a different entry, mode or physical path")
	}
	if err := saved.selection.current(a); err != nil {
		return nil, err
	}
	selection := *saved.selection
	selection.profile, selection.policy = cloneRouterProfile(selection.profile), cloneRouterProfile(selection.policy)
	return &selection, nil
}

func (a *app) restoreSpeedLabTorMTU(plan speedLabRestorePlan) error {
	saved := plan.tor
	raw, exists := desktopNodeOwners.Load(a)
	launch, ok := raw.(*desktopNodeLaunch)
	if saved == nil || saved.mtu < 1280 || saved.mtu > 9000 || !exists || !ok || launch == nil || launch.tor == nil || launch.profileID != plan.profile.ID || launch.tor.network != saved.network {
		return errors.New("restored Tor MTU lost its captured node or physical path")
	}
	if err := a.desktopTorCurrent(launch); err != nil {
		return err
	}
	selection, err := saved.selectionFor(a, plan.profile, plan.request)
	if err != nil || launch.tor.predecessor != selection.predecessor {
		return errors.New("restored Tor MTU belongs to a different captured entry path")
	}
	owner := desktopMeasurementMTUSession(launch)
	if owner == nil {
		return errors.New("restored Tor connection has no captured MTU owner")
	}
	owner.mu.Lock()
	owner.restoreMTU, owner.automatic = saved.mtu, saved.automaticMTU
	owner.mu.Unlock()
	return a.restoreDesktopCapturedMTU(a.connectionOperationContextOrBackground(), launch)
}

type speedLabExternalRestore struct {
	mtu         int
	source      []byte
	predecessor string
	profile     common.RouterProfile
	entry       common.RouterProfile
	direct      bool
	execution   string
	root        string
	network     string
}

func (a *app) beginSpeedLabTemporaryOperation() (context.Context, speedLabTemporarySnapshot, func(), error) {
	return a.beginSpeedLabTemporaryOperationExpected(nil)
}

func (a *app) beginSpeedLabTemporaryOperationExpected(request *speedLabRequest) (context.Context, speedLabTemporarySnapshot, func(), error) {
	if !a.operationMu.TryLock() {
		return nil, speedLabTemporarySnapshot{}, nil, errors.New("another Router VPN connection or settings transaction is already in progress")
	}
	ok := false
	defer func() {
		if !ok {
			a.operationMu.Unlock()
		}
	}()
	if err := guardViaEntryDecision(a); err != nil {
		return nil, speedLabTemporarySnapshot{}, nil, err
	}
	a.mu.Lock()
	st := a.state
	busy := a.closing || st.Connected && st.Phase != "connected" || !st.Connected && profileSettingsBusy(st.Connected, st.Phase) || a.connectionContext != nil
	var expectedErr error
	if request != nil {
		expectedErr = a.validateSpeedLabExpectedProfilesLocked(*request, nil)
	}
	a.mu.Unlock()
	if expectedErr != nil {
		return nil, speedLabTemporarySnapshot{}, nil, expectedErr
	}
	if busy {
		return nil, speedLabTemporarySnapshot{}, nil, errors.New("wait for the current VPN transition before a temporary Speed Lab test")
	}
	if err := preflightPrivateConnectionRuntime(); err != nil {
		return nil, speedLabTemporarySnapshot{}, nil, err
	}
	snapshot, err := a.speedLabSnapshotTemporary()
	if err != nil {
		return nil, speedLabTemporarySnapshot{}, nil, err
	}
	intent, cancelIntent := context.WithCancel(context.Background())
	test, cancelTest := context.WithCancel(intent)
	owner := &speedLabTemporaryOwner{intent: intent, cancelIntent: cancelIntent, test: test, cancelTest: cancelTest, current: test, runtime: snapshot.Runtime, network: physicalNetworkIdentity()}
	if owner.network == "" {
		cancelTest()
		cancelIntent()
		return nil, speedLabTemporarySnapshot{}, nil, errors.New("temporary Speed Lab could not capture the physical network")
	}
	a.mu.Lock()
	if request != nil {
		expectedErr = a.validateSpeedLabExpectedProfilesLocked(*request, nil)
	}
	if expectedErr != nil {
		a.mu.Unlock()
		cancelTest()
		cancelIntent()
		clearSpeedLabRestorePlan(snapshot.Plan)
		return nil, speedLabTemporarySnapshot{}, nil, expectedErr
	}
	if a.closing || a.state != snapshot.State || a.cmd != snapshot.Runtime || !reflect.DeepEqual(a.profiles, snapshot.Profiles) || a.connectionContext != nil {
		a.mu.Unlock()
		cancelTest()
		cancelIntent()
		return nil, speedLabTemporarySnapshot{}, nil, errors.New("VPN state changed while capturing the temporary Speed Lab restore point")
	}
	if _, exists := speedLabTemporaryOwners.LoadOrStore(a, owner); exists {
		a.mu.Unlock()
		cancelTest()
		cancelIntent()
		return nil, speedLabTemporarySnapshot{}, nil, errors.New("another temporary Speed Lab restore point is still owned")
	}
	a.connectionContext, a.connectionCancel = test, cancelIntent
	a.mu.Unlock()
	snapshot.Owner = owner
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancelTest()
			cancelIntent()
			a.mu.Lock()
			if current, exists := speedLabTemporaryOwners.Load(a); exists && current == owner && a.connectionContext == owner.current {
				a.connectionContext, a.connectionCancel = nil, nil
			}
			a.mu.Unlock()
			speedLabTemporaryOwners.CompareAndDelete(a, owner)
			clearSpeedLabRestorePlan(snapshot.Plan)
			a.operationMu.Unlock()
		})
	}
	ok = true
	return test, snapshot, finish, nil
}

func clearSpeedLabRestorePlan(plan speedLabRestorePlan) {
	if launch := plan.native; launch != nil {
		launch.workspaceMu.Lock()
		owner := launch.ownedNode
		// Once staging acquires a protection attempt, the runtime owns these
		// buffers even if startup or cleanup is still pending. A finished test
		// plan must not erase a restored connection's future restore source.
		if owner == nil || owner.retired || owner.attempt == nil && owner.process == nil {
			clear(launch.config)
			clear(launch.metadata)
			if owner != nil {
				clear(owner.source)
			}
		}
		launch.workspaceMu.Unlock()
	}
	if plan.external != nil {
		clear(plan.external.source)
	}
}

func compileSpeedLabExternalRestore(saved *speedLabExternalRestore, exit standardExit) (*desktopNodeLaunch, error) {
	if saved == nil || saved.execution != "local" && saved.execution != "server" || saved.profile.ID != exit.ID || saved.profile.External == nil || saved.profile.External.Protocol != exit.Protocol {
		return nil, errors.New("previous external connection has no exact proved restore selection")
	}
	var err error
	exit, err = standardExitFromExternalProfile(saved.profile)
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if len(saved.source) == 0 || len(saved.source) > 4<<20 || json.Unmarshal(saved.source, &graph) != nil || graph == nil {
		return nil, errors.New("saved external source is invalid")
	}
	// Rebuild from the owned source, not generated files or mutable selection.
	// Keep the saved AUTO preference while retaining its proved winner only.
	retained := saved.execution
	if saved.profile.MultihopExecution == "" || saved.profile.MultihopExecution == "local" {
		if saved.execution != "local" {
			return nil, errors.New("previous local external profile cannot restore a server execution")
		}
		// Ordinary Local (including direct/anonymous proxy paths) has no relay
		// proposal to restore. Supplying a fake retained proposal would require
		// a Router entry and server credentials that this path never used.
		retained = ""
	}
	launch, err := compileDesktopExternalGraphWithPredecessor(graph, saved.profile, saved.entry, exit, saved.direct, retained, saved.predecessor)
	if err != nil {
		return nil, err
	}
	launch.root, launch.external.network, launch.external.selection = saved.root, saved.network, saved.execution
	if saved.mtu != 0 {
		launch.external.mtu = &desktopMTUSession{restoreMTU: saved.mtu}
	}
	return launch, nil
}

func (a *app) speedLabOwnerCurrentLocked(owner *speedLabTemporaryOwner) bool {
	current, exists := speedLabTemporaryOwners.Load(a)
	return owner != nil && exists && current == owner && a.connectionContext == owner.current
}

func (a *app) speedLabCheckOwner(owner *speedLabTemporaryOwner) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.speedLabOwnerCurrentLocked(owner) || a.cmd != owner.runtime {
		return errors.New("temporary Speed Lab owner or runtime changed; refusing to alter the replacement connection")
	}
	return nil
}

// Called immediately after a Speed Lab launcher records its own process. A
// late proof cannot subsequently claim whichever process happens to be active.
func (a *app) speedLabOwnRuntime(command *exec.Cmd) error {
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return nil // These path helpers are also exercised independently.
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	a.mu.Lock()
	defer a.mu.Unlock()
	if !ok || !a.speedLabOwnerCurrentLocked(owner) || a.cmd != command {
		return errors.New("temporary Speed Lab runtime changed before ownership capture")
	}
	owner.runtime = command
	return nil
}

// A launcher may finish by successfully retiring its own failed candidate. Only
// an empty runtime can be reconciled here; a different non-nil process must have
// been captured explicitly at launch and must never be adopted after the fact.
func (a *app) speedLabCheckLaunchedRuntime() error {
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return nil
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	if !ok {
		return errors.New("temporary Speed Lab owner is invalid")
	}
	a.mu.Lock()
	if a.speedLabOwnerCurrentLocked(owner) && a.cmd == nil {
		owner.runtime = nil
	}
	a.mu.Unlock()
	return a.speedLabCheckOwner(owner)
}

func (a *app) speedLabStopRuntime(hold bool) error {
	raw, exists := speedLabTemporaryOwners.Load(a)
	if !exists {
		return a.stopModeWithIntent(hold)
	}
	owner, ok := raw.(*speedLabTemporaryOwner)
	if !ok {
		return errors.New("temporary Speed Lab owner is invalid")
	}
	if err := a.speedLabCheckOwner(owner); err != nil {
		return err
	}
	err := a.stopModeWithIntent(hold)
	a.mu.Lock()
	if a.speedLabOwnerCurrentLocked(owner) && a.cmd == nil {
		owner.runtime = nil
	}
	a.mu.Unlock()
	return err
}

func (a *app) speedLabSuspendPrevious(snapshot speedLabTemporarySnapshot, systemDirect bool) error {
	if err := a.speedLabCheckOwner(snapshot.Owner); err != nil {
		return err
	}
	if err := snapshot.Owner.test.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	snapshot.Owner.mutated = true
	a.mu.Unlock()
	// Choosing a system-direct test explicitly permits its temporary unprotected
	// Internet path. Other temporary VPN transitions retain fail-closed policy.
	return a.speedLabStopRuntime(!systemDirect)
}

func (a *app) speedLabCaptureRestorePlan(snapshot speedLabTemporarySnapshot) (speedLabRestorePlan, error) {
	if !snapshot.State.Connected {
		if snapshot.Runtime != nil || snapshot.State.Mode != "" && snapshot.State.Mode != "off" {
			return speedLabRestorePlan{}, errors.New("a retired runtime still needs cleanup before a temporary Speed Lab test")
		}
		return speedLabRestorePlan{}, nil
	}
	if snapshot.State.Phase != "connected" || snapshot.Runtime == nil {
		return speedLabRestorePlan{}, errors.New("temporary Speed Lab requires a stable owned connection to restore")
	}
	identity, _, err := captureSpeedLabIdentity(a)
	if err != nil {
		return speedLabRestorePlan{}, err
	}
	profile, ok := profileByID(snapshot.Profiles.Profiles, snapshot.State.RouterID)
	if !ok {
		return speedLabRestorePlan{}, errors.New("previous Speed Lab connection node is no longer linked")
	}
	plan := speedLabRestorePlan{profile: cloneRouterProfile(profile)}
	st := snapshot.State
	plan.request = speedLabRequest{Topology: "router", NodeID: st.RouterID, Mode: st.RuntimeMode, Base: st.Base}
	if plan.request.Mode == "" {
		plan.request.Mode = st.Mode
	}
	if st.Mode == "multihop" {
		graph := identity.Graph
		if !identity.GraphOK || graph.Execution != "local" && graph.Execution != "server" {
			return plan, errors.New("previous multihop connection has no proved execution choice")
		}
		control, ok := profileByID(snapshot.Profiles.Profiles, snapshot.Profiles.SelectedID)
		if !ok {
			return plan, errors.New("previous multihop control profile disappeared")
		}
		plan.request = speedLabRequest{Topology: "multihop", EntryID: graph.EntryID, ExitID: graph.ExitID, EntryMode: graph.EntryMode, Base: graph.Base, ExitMode: graph.ExitMode, Execution: graph.Execution}
		request := plan.request
		if request.Base == "native" {
			// native is a derived runtime base, never a new legacy base request.
			// The exact retained raw mode reconstructs it during validation.
			request.Base = ""
		}
		selection, err := a.resolveSpeedLabMultihop(request, control, snapshot.Profiles.Profiles)
		if err != nil {
			return plan, err
		}
		selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
		if retainedNativeMultihopSelected() {
			selection, err = captureNativeMultihopRestore(a, snapshot.Runtime, graph, selection.Control, selection.Entry, selection.Exit)
			if err != nil {
				return plan, err
			}
		}
		plan.multihop = &selection
	} else if st.Mode == "external-node" {
		if profile.External == nil {
			return plan, errors.New("previous external connection has no private node capture")
		}
		plan.request.Topology = "external"
		plan.request.Mode, plan.request.Base = "", ""
		plan.request.Execution = "local"
		if profile.MultihopEnabled {
			plan.request.EntryID = profile.MultihopEntryID
		}
		if raw, exists := desktopNodeOwners.Load(a); exists {
			launch, ok := raw.(*desktopNodeLaunch)
			if !ok || launch == nil || launch.command != snapshot.Runtime || launch.profileID != st.RouterID {
				return plan, errors.New("previous external connection has another native owner")
			}
			if launch.tor != nil {
				if launch != identity.Tor {
					return plan, errors.New("previous Tor connection changed during restore capture")
				}
				plan.tor, err = captureSpeedLabTorRestore(profile, identity)
				if err != nil {
					return plan, err
				}
				plan.request.EntryID, plan.request.EntryMode, plan.request.Execution = "", "", plan.tor.execution()
				if entry := plan.tor.selection.predecessor; entry != nil {
					plan.request.EntryID, plan.request.EntryMode = entry.entry.ID, entry.mode
				}
			} else {
				if launch.external == nil {
					return plan, errors.New("previous external connection has no captured native graph")
				}
				proof, err := a.readDesktopExternalProof(launch)
				if err != nil {
					return plan, err
				}
				captured := launch.external
				captured.mu.Lock()
				plan.external = &speedLabExternalRestore{source: append([]byte(nil), captured.source...), predecessor: captured.predecessor, profile: cloneRouterProfile(captured.profile), entry: cloneRouterProfile(captured.entry), direct: captured.direct, execution: proof.Execution, root: launch.root, network: captured.network}
				captured.mu.Unlock()
				plan.external.mtu, err = captureDesktopMTURestore(launch)
				if err != nil {
					return plan, err
				}
				plan.request.EntryID, plan.request.Execution = "", plan.external.execution
				plan.request.EntryMode = ""
				if !plan.external.direct {
					plan.request.EntryID = plan.external.entry.ID
					if plan.external.entry.NodeKind == "" || plan.external.entry.NodeKind == "router-vpn" {
						plan.request.EntryMode = plan.external.profile.MultihopEntryMode
					}
				}
			}
		} else if profile.MultihopExecution != "" && profile.MultihopExecution != "local" {
			return plan, errors.New("previous external execution cannot be restored without its native proof receipt")
		}
	} else if raw, exists := desktopNodeOwners.Load(a); exists {
		launch, ok := raw.(*desktopNodeLaunch)
		if !ok || launch == nil || launch.external != nil || launch.tor != nil || launch.command != snapshot.Runtime || launch.profileID != st.RouterID || launch.mode != plan.request.Mode {
			return plan, errors.New("previous native connection has another captured owner")
		}
		if launch.ownedNode != nil {
			plan.native, err = a.captureDesktopOwnedNodeRestore(launch, profile)
			if err != nil {
				return plan, err
			}
			if err := validateSpeedLabIdentity(a, identity); err != nil {
				clearSpeedLabRestorePlan(plan)
				return speedLabRestorePlan{}, err
			}
			return plan, nil
		}
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			return plan, err
		}
		config, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
		if err != nil {
			return plan, err
		}
		metadata, err := readDesktopRuntimeFile(launch, "capture.json", 1<<20)
		if err != nil {
			clear(config)
			return plan, err
		}
		var receipt struct {
			Schema    int    `json:"schema"`
			ProfileID string `json:"profile_id"`
			Mode      string `json:"mode"`
			ConfigSHA string `json:"config_sha256"`
		}
		sum := sha256.Sum256(config)
		if json.Unmarshal(metadata, &receipt) != nil || receipt.Schema != 1 || receipt.ProfileID != st.RouterID || receipt.Mode != plan.request.Mode || launch.configSHA256 == "" || receipt.ConfigSHA != launch.configSHA256 || receipt.ConfigSHA != hex.EncodeToString(sum[:]) {
			clear(config)
			clear(metadata)
			return plan, errors.New("previous native configuration differs from its captured identity")
		}
		restoredConfig, restoredMetadata, err := capturedDesktopNodeRestoreGraph(launch, config, metadata)
		clear(config)
		clear(metadata)
		if err != nil {
			return plan, err
		}
		plan.native = &desktopNodeLaunch{root: launch.root, endpoint: launch.endpoint, profileID: launch.profileID, mode: launch.mode, config: restoredConfig, metadata: restoredMetadata,
			nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), launch.nodePhysicalEgress...)}
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		clearSpeedLabRestorePlan(plan)
		return speedLabRestorePlan{}, err
	}
	return plan, nil
}

// Runtime boundaries are explicit so ownership, cancellation, state and durable
// restoration execute unchanged in tests without installing a host VPN.
type speedLabRestoreActions struct {
	stop    func(bool) error
	restart func(speedLabRestorePlan) error
	persist func(common.RouterProfileStore) error
	network func() string
}

func (a *app) speedLabRestoreWith(snapshot speedLabTemporarySnapshot, actions speedLabRestoreActions) error {
	owner := snapshot.Owner
	if err := a.speedLabCheckOwner(owner); err != nil {
		return err
	}
	a.mu.Lock()
	if owner.restored {
		a.mu.Unlock()
		return nil
	}
	mutated := owner.mutated
	a.mu.Unlock()
	if !mutated {
		// An invalid request or preflight failure never disturbed the old VPN.
		return nil
	}
	owner.cancelTest()
	if err := actions.stop(snapshot.State.Connected && owner.intent.Err() == nil); err != nil {
		if ownerErr := a.speedLabCheckOwner(owner); ownerErr != nil {
			return errors.Join(err, ownerErr)
		}
		return errors.Join(err, actions.persist(snapshot.Profiles))
	}
	a.mu.Lock()
	if !a.speedLabOwnerCurrentLocked(owner) || a.cmd != nil {
		a.mu.Unlock()
		return errors.New("temporary Speed Lab teardown lost ownership; prior state was not installed over the replacement")
	}
	owner.runtime = nil
	a.rollbackProfilesLocked(snapshot.Profiles)
	st := snapshot.State
	if st.Connected {
		st.Connected, st.Mode, st.LogicalMode, st.RuntimeMode, st.Base, st.Phase, st.LastError = false, "off", "", "", "", "off", ""
	}
	a.state = st
	a.mu.Unlock()
	if err := actions.persist(snapshot.Profiles); err != nil {
		return a.speedLabRestoreFailed(owner, "previous private profile state could not be restored", err)
	}
	if !snapshot.State.Connected || owner.intent.Err() != nil {
		a.mu.Lock()
		if a.speedLabOwnerCurrentLocked(owner) && a.cmd == nil {
			owner.restored = true
		}
		a.mu.Unlock()
		return nil
	}
	if owner.network == "" || actions.network() != owner.network {
		return a.speedLabRestoreFailed(owner, "previous VPN belongs to a changed physical network", errors.New("captured network changed"))
	}
	// This context survives a test timeout/client cancellation but is cancelled
	// immediately by Disconnect. No unrelated operation can replace this owner.
	restoreCtx, cancelRestore := context.WithTimeout(owner.intent, 180*time.Second)
	defer cancelRestore()
	a.mu.Lock()
	if !a.speedLabOwnerCurrentLocked(owner) || a.cmd != nil {
		a.mu.Unlock()
		return errors.New("temporary Speed Lab restoration owner changed")
	}
	owner.current = restoreCtx
	a.connectionContext = restoreCtx
	a.profiles.SelectedID = snapshot.State.RouterID
	a.mu.Unlock()
	err := actions.restart(snapshot.Plan)
	if err == nil {
		err = restoreCtx.Err()
	}
	if err == nil && actions.network() != owner.network {
		err = errors.New("physical network changed during prior-connection proof")
	}
	if err == nil {
		err = a.speedLabCheckOwner(owner)
	}
	a.mu.Lock()
	if err == nil && (!a.state.Connected || a.state.Phase != "connected" || a.state.RouterID != snapshot.State.RouterID || a.cmd == nil) {
		err = errors.New("prior connection did not complete a new owned path proof")
	}
	owned := a.speedLabOwnerCurrentLocked(owner) && a.cmd == owner.runtime
	if owned {
		a.rollbackProfilesLocked(snapshot.Profiles)
		if err == nil {
			// Only logical UI metadata and user options are restored here. The
			// connected bit is earned above by the new runtime's actual proof.
			a.state.Mode, a.state.LogicalMode = snapshot.State.Mode, snapshot.State.LogicalMode
			a.state.RuntimeMode, a.state.Base = snapshot.State.RuntimeMode, snapshot.State.Base
			a.state.DAITA, a.state.Jumbo, a.state.Socks = snapshot.State.DAITA, snapshot.State.Jumbo, snapshot.State.Socks
			a.state.LastError = ""
		}
	}
	a.mu.Unlock()
	if !owned {
		return errors.Join(err, errors.New("Speed Lab restore completion belongs to a retired owner"))
	}
	if persistErr := actions.persist(snapshot.Profiles); persistErr != nil {
		err = errors.Join(err, persistErr)
	}
	if err != nil {
		// Cleanup is still bound to this owner's runtime. A failed proof must
		// leave neither an unproved tunnel nor a fabricated Connected state.
		if check := a.speedLabCheckOwner(owner); check != nil {
			return errors.Join(err, check)
		}
		cleanupErr := actions.stop(owner.intent.Err() == nil)
		return a.speedLabRestoreFailed(owner, "previous VPN could not be restored", errors.Join(err, cleanupErr))
	}
	a.mu.Lock()
	if a.speedLabOwnerCurrentLocked(owner) && a.cmd == owner.runtime {
		owner.restored = true
	}
	a.mu.Unlock()
	return nil
}

func (a *app) speedLabRestoreFailed(owner *speedLabTemporaryOwner, message string, cause error) error {
	err := errors.New(message + ": " + cause.Error())
	a.mu.Lock()
	if a.speedLabOwnerCurrentLocked(owner) && a.cmd == owner.runtime {
		a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", err.Error()
	}
	a.mu.Unlock()
	return err
}

func (a *app) speedLabRestartPlan(plan speedLabRestorePlan) error {
	return a.speedLabRestartPlanWithTorRuntime(plan, desktopTorConnectRuntime{})
}

func (a *app) speedLabRestartPlanWithTorRuntime(plan speedLabRestorePlan, torDriver desktopTorConnectRuntime) error {
	var err error
	switch {
	case plan.tor != nil:
		err = a.startSpeedLabTorRestoreWithRuntime(plan, torDriver)
	case plan.external != nil:
		_, err = a.startSpeedLabExternalPathCaptured(plan.request, plan.external)
	case plan.native != nil:
		err = a.speedLabRestartNative(plan)
	case plan.multihop != nil:
		_, err = a.startSpeedLabMultihopSelection(*plan.multihop, plan.request)
	case plan.request.Topology == "external":
		_, err = a.startSpeedLabExternalPath(plan.request)
	default:
		// AUTO/SMART/CUSTOM are presentation choices; the captured runtime is
		// the already-proved path. Re-running those strategies could select a
		// different node, mode or graph while claiming to have restored it.
		mode := strings.TrimSpace(plan.request.Mode)
		if mode == "" || mode == "off" || mode == "auto" || mode == "smart-auto" || mode == "custom" {
			return errors.New("previous connection has no concrete runtime to restore")
		}
		sessionTrackerFor(a).declareRequest("speed-lab:restore:"+mode, plan.request.Base)
		err = a.startModeAttempt(mode, true)
		err = errors.Join(err, a.speedLabCheckLaunchedRuntime())
	}
	if err == nil {
		var identity speedLabPathIdentity
		identity, err = waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond)
		if err == nil {
			err = verifySpeedLabPath(a.connectionOperationContextOrBackground(), a, identity)
		}
	}
	return err
}

func (a *app) speedLabRestartNative(plan speedLabRestorePlan) error {
	return a.restartCapturedDesktopNode(plan, "speed-lab:restore")
}

func (a *app) restartCapturedDesktopNode(plan speedLabRestorePlan, scope string) (resultErr error) {
	if scope != "speed-lab:restore" && scope != "smart:restore" {
		return errors.New("captured native restore has no recognized operation")
	}
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return err
	}
	launch := plan.native
	if launch == nil || launch.external != nil {
		return errors.New("previous native node capture is unavailable")
	}
	if launch.ownedNode != nil {
		launch.workspaceMu.Lock()
		prior := launch.ownedNode.operation
		if prior == nil || prior == operation {
			launch.ownedNode.operation = operation
		}
		launch.workspaceMu.Unlock()
		if prior != nil && prior != operation {
			return errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
		}
	}
	stopRestore := func() error {
		if launch.ownedNode != nil {
			_, err := a.stopDesktopNodeForOperationWithIntent(operation, true)
			return err
		}
		if !a.sameConnectionOperation(operation) {
			return errors.Join(errConnectionOperationCancelled, errDesktopNodeOperationReplaced)
		}
		return a.stopModeWithIntent(true)
	}
	if err := stageDesktopNodeLaunch(a, launch); err != nil {
		return err
	}
	started := false
	defer func() {
		if started {
			return
		}
		if raw, exists := activeDNSRuntimeIdentities.Load(a); exists {
			if identity, ok := raw.(activeDNSRuntimeIdentity); ok && identity.Config == filepath.Join(launch.directory, "sing-box.json") {
				activeDNSRuntimeIdentities.CompareAndDelete(a, identity)
			}
		}
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		if launch.ownedNode != nil {
			resultErr = errors.Join(resultErr, a.discardDesktopOwnedNodeUnstarted(launch))
		} else {
			resultErr = errors.Join(resultErr, cleanupDesktopNodeLaunch(launch))
		}
	}()
	if err := registerActiveDNSRuntimeConfig(a, launch.profileID, launch.mode, filepath.Join(launch.directory, "sing-box.json")); err != nil {
		return err
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return err
	}
	if launch.ownedNode != nil {
		if err := a.publishDesktopOwnedNodeStartFor(launch, scope+":proving-node", plan.request.Base, operation); err != nil {
			return err
		}
		started = true
		if err := a.speedLabOwnRuntime(launch.command); err != nil {
			return errors.Join(err, stopRestore())
		}
		if err := startDesktopNodeLaunch(a, launch); err != nil {
			return errors.Join(err, stopRestore())
		}
	} else {
		if err := launch.command.Start(); err != nil {
			return err
		}
	}
	if err := a.publishStartedDesktopNode(operation, launch, launch.command, launch.profileID, launch.mode, scope+":proving-node", plan.request.Base); err != nil {
		if launch.ownedNode != nil {
			return errors.Join(err, stopRestore())
		}
		if a.ownsConnectionRuntime(launch.command) {
			started = true
			return errors.Join(err, a.speedLabOwnRuntime(launch.command), stopRestore())
		}
		return errors.Join(err, joinUnpublishedDesktopCommand(launch.command))
	}
	started = true
	sessionTrackerFor(a).declareRequest(scope+":"+launch.mode, plan.request.Base)
	if err := a.speedLabOwnRuntime(launch.command); err != nil {
		return err
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if err := a.checkCapturedConnectionOperation(operation); err != nil {
			return err
		}
		if !a.ownsConnectionRuntime(launch.command) {
			return errors.New("restored native runtime changed during startup")
		}
		var proofErr error
		if launch.ownedNode != nil {
			_, proofErr = a.testDesktopOwnedNodeHealth(operation, plan.profile, launch)
		} else {
			_, proofErr = a.testHealth(plan.profile)
		}
		if proofErr == nil {
			break
		} else if !time.Now().Before(deadline) {
			return proofErr
		}
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-operation.Done():
			timer.Stop()
			return errConnectionOperationCancelled
		case <-timer.C:
		}
	}
	if err := a.checkCapturedConnectionOperation(operation); err != nil || !a.ownsConnectionRuntime(launch.command) {
		return errors.Join(err, errors.New("restored native proof completed for a retired runtime"))
	}
	if launch.ownedNode != nil {
		if _, err := a.readDesktopOwnedNodeReady(launch, false); err != nil {
			return err
		}
	}
	a.mu.Lock()
	if err := a.checkDesktopNodeStartupOwnerLocked(operation, launch, launch.command); err != nil {
		a.mu.Unlock()
		return errors.Join(err, errors.New("restored proof belongs to a replaced operation or runtime"))
	}
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	daita := a.state.DAITA
	a.mu.Unlock()
	if daita {
		a.startCoverTraffic(plan.profile)
	}
	if launch.ownedNode != nil {
		a.monitorDesktopOwnedNodeRuntime(launch)
	}
	return nil
}
