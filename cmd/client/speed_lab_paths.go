package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/routechoice"
)

type speedLabRequest struct {
	preparedExternal   *speedLabExternalPreparation
	Scope              string   `json:"scope,omitempty"`
	Topology           string   `json:"topology,omitempty"`
	NodeID             string   `json:"node_id,omitempty"`
	EntryID            string   `json:"entry_id,omitempty"`
	EntryMode          string   `json:"entry_mode,omitempty"`
	ExitID             string   `json:"exit_id,omitempty"`
	Mode               string   `json:"mode,omitempty"`
	Base               string   `json:"base,omitempty"`
	ExitMode           string   `json:"exit_mode,omitempty"`
	Execution          string   `json:"execution,omitempty"`
	CustomLayers       []string `json:"custom_layers,omitempty"`
	DurationMode       string   `json:"duration_mode,omitempty"`
	MinSeconds         float64  `json:"min_seconds,omitempty"`
	MaxSeconds         float64  `json:"max_seconds,omitempty"`
	DAITA              *bool    `json:"daita,omitempty"`
	Jumbo              *bool    `json:"jumbo,omitempty"`
	RequireEncrypted   *bool    `json:"require_encrypted,omitempty"`
	RequireObfuscation *bool    `json:"require_obfuscation,omitempty"`
}

type speedLabPath struct {
	Scope            string    `json:"scope"`
	Topology         string    `json:"topology"`
	Temporary        bool      `json:"temporary"`
	NodeID           string    `json:"node_id,omitempty"`
	NodeName         string    `json:"node_name,omitempty"`
	EntryID          string    `json:"entry_id,omitempty"`
	EntryName        string    `json:"entry_name,omitempty"`
	EntryMode        string    `json:"entry_mode,omitempty"`
	ExitID           string    `json:"exit_id,omitempty"`
	ExitName         string    `json:"exit_name,omitempty"`
	RequestedMode    string    `json:"requested_mode,omitempty"`
	RuntimeMode      string    `json:"runtime_mode,omitempty"`
	LogicalMode      string    `json:"logical_mode,omitempty"`
	Base             string    `json:"base,omitempty"`
	ExitMode         string    `json:"exit_mode,omitempty"`
	Execution        string    `json:"execution,omitempty"`
	ExternalProtocol string    `json:"external_protocol,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	Description      string    `json:"description"`
}

type speedLabPathIdentity struct {
	SessionID       string
	StateToken      string
	RouterID        string
	Graph           activeMultihopGraph
	GraphOK         bool
	Command         *exec.Cmd
	Network         string
	ProfileToken    string
	EntryToken      string
	External        *desktopNodeLaunch
	ExternalSession string
	Execution       string
	Options         [3]bool
}

type speedLabTemporarySnapshot struct {
	Profiles common.RouterProfileStore
	State    state
	Runtime  *exec.Cmd
	Plan     speedLabRestorePlan
	Owner    *speedLabTemporaryOwner
}

func captureSpeedLabIdentity(a *app) (speedLabPathIdentity, speedLabPath, error) {
	a.mu.Lock()
	st, command := a.state, a.cmd
	profile, profileOK := a.profileByIDLocked(strings.TrimSpace(st.RouterID))
	profile = cloneRouterProfile(profile)
	a.mu.Unlock()
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("Speed Lab current-path test requires a stable connected VPN; choose system-direct or a temporary test path while disconnected")
	}
	session, err := captureAsyncMeasurementSession(a)
	if err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, err
	}
	if strings.TrimSpace(st.RouterID) == "" || session.RouterID != st.RouterID {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("active Speed Lab path identity is unavailable or disagrees with the session tracker")
	}
	if !profileOK {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("active Speed Lab node disappeared")
	}
	graph, graphOK := getActiveMultihopGraph(a)
	if st.Mode == "multihop" && !graphOK {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("active multihop graph identity is unavailable")
	}
	identity := speedLabPathIdentity{SessionID: session.ID, StateToken: mtuStateSnapshotToken(st), RouterID: st.RouterID, Graph: graph, GraphOK: graphOK && st.Mode == "multihop", Command: command, Network: physicalNetworkIdentity(), ProfileToken: liveMeasurementProfileToken(profile), Options: [3]bool{st.DAITA, st.Jumbo, st.Socks}}
	if identity.Network == "" {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("Speed Lab cannot capture the current physical network")
	}
	path := speedLabPath{Scope: "current", Topology: "router", NodeID: profile.ID, NodeName: profile.Name, RuntimeMode: st.RuntimeMode, LogicalMode: st.LogicalMode, Base: st.Base, Description: "actual currently connected Router VPN path; mutable selection is not used as path proof"}
	if strings.EqualFold(profile.NodeKind, "external") || profile.External != nil {
		path.Topology = "external"
		if profile.External != nil {
			path.ExternalProtocol = profile.External.Protocol
		}
	}
	if st.Mode == "multihop" {
		path.Topology = "multihop"
		path.EntryID, path.ExitID = graph.EntryID, graph.ExitID
		path.EntryMode = graph.EntryMode
		path.Base, path.ExitMode, path.StartedAt, path.Execution = graph.Base, graph.ExitMode, graph.Started, graph.Execution
		a.mu.Lock()
		entry, entryOK := a.profileByIDLocked(graph.EntryID)
		if entryOK {
			path.EntryName = entry.Name
			identity.EntryToken = liveMeasurementProfileToken(entry)
		}
		if exit, ok := a.profileByIDLocked(graph.ExitID); ok {
			path.ExitName = exit.Name
		}
		a.mu.Unlock()
		if !entryOK {
			return speedLabPathIdentity{}, speedLabPath{}, errors.New("active Speed Lab entry disappeared")
		}
	} else if st.Mode == "external-node" {
		if raw, exists := desktopNodeOwners.Load(a); exists {
			launch, ok := raw.(*desktopNodeLaunch)
			if !ok || launch == nil || launch.external == nil || launch.command != command {
				return speedLabPathIdentity{}, speedLabPath{}, errors.New("active external Speed Lab runtime owner changed")
			}
			proof, err := a.readDesktopExternalProof(launch)
			if err != nil {
				return speedLabPathIdentity{}, speedLabPath{}, err
			}
			identity.External, identity.ExternalSession, identity.Execution = launch, proof.SessionID, proof.Execution
			path.Execution, path.ExitID, path.ExitName = proof.Execution, profile.ID, profile.Name
			path.StartedAt = launch.external.started
			if !launch.external.direct {
				path.EntryID, path.EntryName = launch.external.entry.ID, launch.external.entry.Name
				path.EntryMode = launch.external.profile.MultihopEntryMode
				a.mu.Lock()
				entry, ok := a.profileByIDLocked(path.EntryID)
				a.mu.Unlock()
				if !ok {
					return speedLabPathIdentity{}, speedLabPath{}, errors.New("active external Speed Lab entry disappeared")
				}
				identity.EntryToken = liveMeasurementProfileToken(entry)
			}
		}
	}
	if err := validateSpeedLabIdentity(a, identity); err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, err
	}
	return identity, path, nil
}

func validateSpeedLabIdentity(a *app, identity speedLabPathIdentity) error {
	session := sessionTrackerFor(a).snapshot(0)
	if identity.SessionID == "" || session.ID != identity.SessionID || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.RouterID != identity.RouterID {
		return errors.New("Speed Lab result became stale because the VPN session/path changed")
	}
	a.mu.Lock()
	st, command := a.state, a.cmd
	profile, profileOK := a.profileByIDLocked(identity.RouterID)
	profileToken := liveMeasurementProfileToken(profile)
	entryID := identity.Graph.EntryID
	if identity.External != nil {
		entryID = identity.External.external.entry.ID
	}
	entry, entryOK := a.profileByIDLocked(entryID)
	entryToken := liveMeasurementProfileToken(entry)
	a.mu.Unlock()
	if !st.Connected || st.RouterID != identity.RouterID || mtuStateSnapshotToken(st) != identity.StateToken || command != identity.Command || [3]bool{st.DAITA, st.Jumbo, st.Socks} != identity.Options {
		return errors.New("Speed Lab result became stale because the active node/mode/base changed")
	}
	if !profileOK || profileToken != identity.ProfileToken || identity.EntryToken != "" && (!entryOK || entryToken != identity.EntryToken) {
		return errors.New("Speed Lab result became stale because the captured node policy or credentials changed")
	}
	if identity.Network == "" || physicalNetworkIdentity() != identity.Network {
		return errors.New("Speed Lab result became stale because the physical network changed")
	}
	if identity.GraphOK {
		current, ok := getActiveMultihopGraph(a)
		if !ok || current != identity.Graph {
			return errors.New("Speed Lab result became stale because the launched multihop graph changed")
		}
	}
	if identity.External != nil {
		current, exists := desktopNodeOwners.Load(a)
		if !exists || current != identity.External {
			return errors.New("Speed Lab result became stale because the native external owner changed")
		}
		proof, err := a.readDesktopExternalProof(identity.External)
		if err != nil {
			return err
		}
		if proof.SessionID != identity.ExternalSession || proof.Execution != identity.Execution {
			return errors.New("Speed Lab result belongs to a different external execution")
		}
	}
	return nil
}

func (a *app) speedLabSnapshotTemporary() (speedLabTemporarySnapshot, error) {
	a.mu.Lock()
	snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(a.profiles), State: a.state, Runtime: a.cmd}
	a.mu.Unlock()
	plan, err := a.speedLabCaptureRestorePlan(snapshot)
	if err != nil {
		return speedLabTemporarySnapshot{}, err
	}
	snapshot.Plan = plan
	return snapshot, nil
}

func (a *app) speedLabWriteStore(store common.RouterProfileStore) error {
	body, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return atomicWritePrivate(a.cfg.ProfilesFile, append(body, '\n'))
}

func (a *app) speedLabRestoreTemporary(snapshot speedLabTemporarySnapshot) error {
	return a.speedLabRestoreWith(snapshot, speedLabRestoreActions{stop: a.speedLabStopRuntime, restart: a.speedLabRestartPlan, persist: a.speedLabWriteStore, network: physicalNetworkIdentity})
}

func speedLabProfileOverrides(profile common.RouterProfile, q speedLabRequest) common.RouterProfile {
	p := cloneRouterProfile(profile)
	if base := normalizeBase(q.Base); base == "wg" || base == "awg" {
		p.BaseTunnel = base
	}
	if q.RequireEncrypted != nil {
		p.AutoRequireEncrypted = *q.RequireEncrypted
	}
	if q.RequireObfuscation != nil {
		p.AutoRequireObfuscation = *q.RequireObfuscation
	}
	if q.DAITA != nil {
		p.DAITAEnabled = *q.DAITA
	}
	if q.Jumbo != nil {
		p.JumboTUN = *q.Jumbo
	}
	return p
}

func (a *app) previewSpeedLabTemporaryProfile(nodeID string, q speedLabRequest) (common.RouterProfile, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validProfileID(nodeID) {
		return common.RouterProfile{}, errors.New("temporary Speed Lab path requires a valid linked node id")
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(nodeID)
	profile = cloneRouterProfile(profile)
	a.mu.Unlock()
	if !ok {
		return common.RouterProfile{}, errors.New("temporary Speed Lab node is not linked")
	}
	return speedLabProfileOverrides(profile, q), nil
}

func (a *app) applySpeedLabTemporaryProfile(nodeID string, q speedLabRequest) (common.RouterProfile, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !validProfileID(nodeID) {
		return common.RouterProfile{}, errors.New("temporary Speed Lab path requires a valid linked node id")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != nodeID {
			continue
		}
		a.profiles.Profiles[i] = speedLabProfileOverrides(a.profiles.Profiles[i], q)
		a.profiles.SelectedID = nodeID
		if q.DAITA != nil {
			a.state.DAITA = *q.DAITA
		}
		if q.Jumbo != nil {
			a.state.Jumbo = *q.Jumbo
		}
		a.state.RouterID = nodeID
		return cloneRouterProfile(a.profiles.Profiles[i]), nil
	}
	return common.RouterProfile{}, errors.New("temporary Speed Lab node is not linked")
}

func waitForSpeedLabConnectedIdentity(a *app, timeout time.Duration) (speedLabPathIdentity, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		identity, _, err := captureSpeedLabIdentity(a)
		if err == nil {
			return identity, nil
		}
		if opErr := a.checkConnectionOperation(); opErr != nil {
			return speedLabPathIdentity{}, opErr
		}
		time.Sleep(50 * time.Millisecond)
	}
	return speedLabPathIdentity{}, errors.New("temporary Speed Lab path connected but typed path proof did not become current")
}

func (a *app) startSpeedLabRouterPath(q speedLabRequest) (path speedLabPath, resultErr error) {
	defer func() { resultErr = errors.Join(resultErr, a.speedLabCheckLaunchedRuntime()) }()
	profile, err := a.applySpeedLabTemporaryProfile(q.NodeID, q)
	if err != nil {
		return speedLabPath{}, err
	}
	if strings.EqualFold(profile.NodeKind, "external") || profile.External != nil {
		return speedLabPath{}, errors.New("choose topology=external for an external custom node")
	}
	mode := strings.ToLower(strings.TrimSpace(q.Mode))
	if mode == "" {
		mode = "smart-auto"
	}
	base := normalizeBase(q.Base)
	if base == "auto" {
		base = ""
	}
	var runtimeID, actualBase, logical string
	switch mode {
	case "smart-auto":
		result, runErr := a.runSmartStrategy()
		if runErr != nil {
			return speedLabPath{}, runErr
		}
		runtimeID, logical = result.RuntimeMode, "smart-auto"
		a.mu.Lock()
		actualBase = a.state.Base
		a.mu.Unlock()
	case "auto":
		result, runErr := a.runAutoStrategy("auto")
		if runErr != nil {
			return speedLabPath{}, runErr
		}
		runtimeID, logical = result.RuntimeMode, "auto"
		a.mu.Lock()
		actualBase = a.state.Base
		a.mu.Unlock()
	case "custom":
		result, runErr := a.runCustomStrategy(q.CustomLayers)
		if runErr != nil {
			return speedLabPath{}, runErr
		}
		runtimeID, logical = result.RuntimeMode, "custom"
		a.mu.Lock()
		actualBase = a.state.Base
		a.mu.Unlock()
	default:
		sessionTrackerFor(a).declareRequest("speed-lab:"+mode, base)
		used, runErr := a.startLogicalMode(mode, base)
		if runErr != nil {
			return speedLabPath{}, runErr
		}
		runtimeID, actualBase, logical = used.RuntimeID, used.Base, mode
		a.mu.Lock()
		a.state.LogicalMode = logical
		a.state.RuntimeMode = runtimeID
		if actualBase != "native" && actualBase != "auto" {
			a.state.Base = actualBase
		}
		a.state.RouterID = profile.ID
		a.state.Connected = true
		a.state.Phase = "connected"
		a.mu.Unlock()
	}
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return speedLabPath{}, err
	}
	return speedLabPath{Scope: "temporary", Topology: "router", Temporary: true, NodeID: profile.ID, NodeName: profile.Name, RequestedMode: mode, RuntimeMode: runtimeID, LogicalMode: logical, Base: actualBase, Description: "temporary Router VPN path; linked-node selection and profile settings are restored after the test"}, nil
}

func (a *app) resolveSpeedLabMultihop(q speedLabRequest, control common.RouterProfile, profiles []common.RouterProfile) (multihopSelection, error) {
	request := multihopConnectRequest{EntryID: q.EntryID, ExitID: q.ExitID, Base: q.Base, ExitMode: q.ExitMode, Execution: q.Execution}
	if runtime.GOOS == "linux" {
		return resolveMultihopSelection(control, profiles, request)
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return resolveNativeMultihopSelection(control, profiles, request)
	}
	return multihopSelection{}, errors.New("temporary desktop multihop Speed Lab is unavailable on this platform")
}

func (a *app) startSpeedLabMultihopPath(q speedLabRequest) (speedLabPath, error) {
	entryProfile, err := a.applySpeedLabTemporaryProfile(q.EntryID, q)
	if err != nil {
		return speedLabPath{}, err
	}
	if strings.EqualFold(entryProfile.NodeKind, "external") || entryProfile.External != nil {
		return speedLabPath{}, errors.New("Router VPN node-to-node multihop requires a Router VPN entry; use topology=external for an external entry/exit graph")
	}
	a.mu.Lock()
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	a.mu.Unlock()
	sel, err := a.resolveSpeedLabMultihop(q, entryProfile, profiles)
	if err != nil {
		return speedLabPath{}, err
	}
	return a.startSpeedLabMultihopSelection(sel, q)
}

func (a *app) startSpeedLabMultihopSelection(sel multihopSelection, q speedLabRequest) (speedLabPath, error) {
	execution, err := routeExecution(multihopConnectRequest{Execution: q.Execution})
	if err != nil {
		return speedLabPath{}, err
	}
	modes := []string{sel.ExitMode}
	if q.ExitMode == "auto" && execution == "auto" {
		modes = []string{"shadowsocks", "hysteria2"}
	}
	if runtime.GOOS != "linux" && sel.Native == nil {
		sel, err = captureNativeMultihopForApp(a, sel, modes)
		if err != nil {
			return speedLabPath{}, err
		}
	}
	network := physicalNetworkIdentity()
	if network == "" {
		return speedLabPath{}, errors.New("temporary multihop cannot capture its physical network")
	}
	sessionTrackerFor(a).declareRequest("speed-lab:multihop", sel.Base)
	if err := a.speedLabStopRuntime(true); err != nil {
		return speedLabPath{}, err
	}
	ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), 180*time.Second)
	defer cancel()
	driver := &desktopExecutionDriver{a: a, selection: sel, network: network}
	var active routechoice.Session
	var winner *routechoice.Candidate
	if execution == "auto" {
		var candidates []routechoice.Candidate
		for _, mode := range modes {
			for _, kind := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
				candidates = append(candidates, routechoice.Candidate{Execution: kind, Transport: mode, EntryID: sel.Entry.ID, ExitID: sel.Exit.ID})
			}
		}
		var result routechoice.Result
		result, active, err = routechoice.Compare(ctx, candidates, driver, routechoice.Options{Targets: comparisonTargets, StartupTimeout: 25 * time.Second, ProbeTimeout: 2500 * time.Millisecond, CleanupTimeout: 15 * time.Second, Preferred: routechoice.Local})
		winner = result.Winner
	} else {
		candidate := routechoice.Candidate{Execution: execution, Transport: sel.ExitMode, EntryID: sel.Entry.ID, ExitID: sel.Exit.ID}
		start, stop := context.WithTimeout(ctx, 25*time.Second)
		active, err = driver.Open(start, candidate)
		stop()
		if err == nil {
			verify, stop := context.WithTimeout(ctx, 5*time.Second)
			err = active.Verify(verify)
			stop()
		}
		if err == nil {
			winner = &candidate
		}
	}
	// Capture the concrete session returned by the driver, never whichever
	// process is currently selected after an asynchronous proof completes.
	real, ok := active.(*desktopExecutionSession)
	if ok && real.command != nil && a.ownsConnectionRuntime(real.command) {
		err = errors.Join(err, a.speedLabOwnRuntime(real.command))
	} else {
		err = errors.Join(err, a.speedLabCheckLaunchedRuntime())
	}
	if err == nil {
		err = a.checkConnectionOperation()
	}
	if err == nil && (!ok || winner == nil || real.Identity() == "") {
		err = errors.New("temporary multihop result lost its captured path before adoption")
	}
	if err != nil {
		if active != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			err = errors.Join(err, active.Close(cleanup))
			stop()
			err = errors.Join(err, a.speedLabCheckLaunchedRuntime())
		}
		return speedLabPath{}, err
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	a.mu.Unlock()
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return speedLabPath{}, err
	}
	graph, _ := getActiveMultihopGraph(a)
	return speedLabPath{Scope: "temporary", Topology: "multihop", Temporary: true, EntryID: sel.Entry.ID, EntryName: sel.Entry.Name, ExitID: sel.Exit.ID, ExitName: sel.Exit.Name, RuntimeMode: winner.Transport, LogicalMode: "multihop", Base: sel.Base, ExitMode: winner.Transport, Execution: string(winner.Execution), StartedAt: graph.Started, Description: "temporary proven multihop graph; entry/exit/base/exit transport and execution are not saved"}, nil
}

func speedLabExternalEntry(profiles []common.RouterProfile, external common.RouterProfile, q speedLabRequest) (common.RouterProfile, string, bool, error) {
	entryID := strings.TrimSpace(q.EntryID)
	if entryID == "" {
		if q.EntryMode != "" {
			return common.RouterProfile{}, "", false, errors.New("an external Speed Lab entry mode requires its captured Router entry")
		}
		return common.RouterProfile{}, "", true, nil
	}
	if entryID == external.ID {
		return common.RouterProfile{}, "", false, errors.New("temporary external entry and exit must be different")
	}
	entry, ok := profileByID(profiles, entryID)
	if !ok {
		return common.RouterProfile{}, "", false, errors.New("temporary external entry is not linked")
	}
	kind := strings.TrimSpace(entry.NodeKind)
	if kind == "" {
		kind = "router-vpn"
	}
	switch kind {
	case "router-vpn":
		if _, err := desktopExternalEntryMode(external, entry, q.EntryMode, q.Base); err != nil {
			return common.RouterProfile{}, "", false, err
		}
		if strings.TrimSpace(entry.Endpoint) == "" {
			return common.RouterProfile{}, "", false, errors.New("Router VPN external-entry hop has no public endpoint")
		}
	case "external":
		if q.EntryMode != "" {
			return common.RouterProfile{}, "", false, errors.New("an external Speed Lab entry mode requires its captured Router entry")
		}
		_, err := standardExitFromExternalProfile(entry)
		if err != nil {
			return common.RouterProfile{}, "", false, err
		}
	default:
		return common.RouterProfile{}, "", false, errors.New("unsupported temporary external entry kind")
	}
	return entry, kind, false, nil
}

func (a *app) startSpeedLabExternalPath(q speedLabRequest) (speedLabPath, error) {
	return a.startSpeedLabExternalPathCaptured(q, nil)
}

type speedLabExternalPreparation struct {
	profile, policy, entry common.RouterProfile
	exit                   standardExit
	entryKind              string
	direct                 bool
	native                 *desktopNodeLaunch
}

func (prepared *speedLabExternalPreparation) releaseUnused() {
	if prepared == nil || prepared.native == nil || prepared.native.command != nil && prepared.native.command.Process != nil {
		return
	}
	clear(prepared.native.config)
	clear(prepared.native.metadata)
	clear(prepared.native.external.source)
	clear(prepared.native.external.capture)
}

func (a *app) prepareSpeedLabExternalPath(q speedLabRequest, restored *speedLabExternalRestore) (*speedLabExternalPreparation, error) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, errors.New("temporary external Speed Lab path requires the desktop external-node runtime on this platform")
	}
	external, err := a.previewSpeedLabTemporaryProfile(q.NodeID, q)
	if err != nil {
		return nil, err
	}
	if external.NodeKind != "external" || external.External == nil {
		return nil, errors.New("temporary external Speed Lab path requires an external custom node")
	}
	if external.External.Protocol == "tor-bridge" {
		if q.EntryID != "" || q.EntryMode != "" || q.Execution != "" && q.Execution != "local" {
			return nil, errors.New("external Tor Speed Lab requires its direct owned Tor runtime")
		}
		if _, _, _, _, err := torBridgeProfile(external); err != nil {
			return nil, err
		}
		if capability := torBridgeRuntimeCapability(); !capability.Supported {
			return nil, errors.New(capability.Reason)
		}
		policy, err := externalRuntimePolicy(external)
		if err != nil {
			return nil, err
		}
		policy, err = externalDNSPolicyForPath(policy, common.RouterProfile{}, true)
		if err != nil {
			return nil, err
		}
		return &speedLabExternalPreparation{profile: external, policy: policy, direct: true}, nil
	}
	policy, err := externalRuntimePolicy(external)
	if err != nil {
		return nil, err
	}
	exit, err := standardExitFromExternalProfile(external)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	a.mu.Unlock()
	entry, entryKind, direct, err := speedLabExternalEntry(profiles, external, q)
	if err != nil {
		return nil, err
	}
	if !direct && entryKind == "router-vpn" {
		policy.MultihopEntryMode, err = desktopExternalEntryMode(policy, entry, q.EntryMode, q.Base)
		if err != nil {
			return nil, err
		}
	} else {
		if q.EntryMode != "" {
			return nil, errors.New("an external Speed Lab entry mode requires its captured Router entry")
		}
		policy.MultihopEntryMode = ""
	}
	policy, err = externalDNSPolicyForPath(policy, entry, direct)
	if err != nil {
		return nil, err
	}
	execution, err := externalExecutionChoice(external, q.Execution, direct)
	if err != nil {
		return nil, err
	}
	policy.MultihopExecution = execution
	var native *desktopNodeLaunch
	if restored != nil {
		if restored.profile.ID != external.ID || restored.profile.External == nil || restored.profile.External.Protocol != exit.Protocol || restored.execution != q.Execution || restored.direct != direct || !direct && restored.entry.ID != entry.ID || restored.network == "" || restored.network != physicalNetworkIdentity() {
			return nil, errors.New("saved external Speed Lab restore receipt differs from the captured path")
		}
		native, err = compileSpeedLabExternalRestore(restored, exit)
		if err == nil {
			var binary string
			binary, err = verifyBundledNative(desktopAmneziaPackageRoot())
			if err == nil {
				err = preflightDesktopExternalLaunch(a.connectionOperationContextOrBackground(), binary, native, runDesktopExternalPreflightCommand)
			}
		}
	} else if desktopExternalNativeProtocol(exit.Protocol) {
		native, err = prepareDesktopExternalLaunch(a, policy, entry, exit, direct, "")
	} else if execution != "local" {
		err = errors.New("this external Speed Lab protocol requires a paired server credential adapter for Server/Compare")
	}
	if err != nil {
		return nil, err
	}
	if exit.Protocol == "openvpn" && native == nil {
		capability := openVPNRuntimeCapability()
		if runtime.GOOS == "windows" {
			capability = windowsOpenVPNRuntimeCapability()
		}
		if !capability.Supported {
			return nil, errors.New(capability.Reason)
		}
		if !direct && !openVPNProtocolIsTCP(exit.Method) {
			return nil, errors.New("hopped OpenVPN Speed Lab tests require TCP OpenVPN; UDP remains fail-closed")
		}
	}
	return &speedLabExternalPreparation{profile: external, policy: policy, entry: entry, exit: exit, entryKind: entryKind, direct: direct, native: native}, nil
}

func (a *app) startSpeedLabExternalPathCaptured(q speedLabRequest, restored *speedLabExternalRestore) (speedLabPath, error) {
	prepared := q.preparedExternal
	var err error
	if prepared == nil || restored != nil {
		prepared, err = a.prepareSpeedLabExternalPath(q, restored)
	}
	if err != nil {
		return speedLabPath{}, err
	}
	defer prepared.releaseUnused()
	external, err := a.applySpeedLabTemporaryProfile(q.NodeID, q)
	if err != nil {
		return speedLabPath{}, err
	}
	if liveMeasurementProfileToken(external) != liveMeasurementProfileToken(prepared.profile) {
		return speedLabPath{}, errors.New("temporary external profile changed after native preflight")
	}
	if external.External.Protocol == "tor-bridge" {
		return a.startSpeedLabTorPath(q, external)
	}
	policy, entry, exit, entryKind, direct, native := prepared.policy, prepared.entry, prepared.exit, prepared.entryKind, prepared.direct, prepared.native
	if !direct {
		a.mu.Lock()
		current, exists := a.profileByIDLocked(entry.ID)
		a.mu.Unlock()
		if !exists || liveMeasurementProfileToken(current) != liveMeasurementProfileToken(entry) {
			return speedLabPath{}, errors.New("temporary external entry changed after native preflight")
		}
	}
	sessionBase := "external"
	if !direct && entryKind == "router-vpn" {
		sessionBase = desktopExternalEntryBase(policy.MultihopEntryMode)
	}
	sessionTrackerFor(a).declareRequest("speed-lab:external", sessionBase)
	if err := a.speedLabStopRuntime(true); err != nil {
		return speedLabPath{}, err
	}
	var cmd *exec.Cmd
	if native != nil {
		err = stageDesktopNodeLaunch(a, native)
		cmd = native.command
	} else if exit.Protocol == "openvpn" {
		if runtime.GOOS == "windows" {
			cmd, err = windowsOpenVPNStandardExitCommand(a, policy, entry, exit, direct)
		} else {
			cmd, err = openVPNStandardExitCommand(a, policy, entry, exit, direct)
		}
	} else if !direct && entryKind == "external" {
		cmd, err = nativeExternalEntryStandardExitCommand(a, policy, entry, exit)
	} else {
		cmd, err = nativeStandardExitCommand(a, policy, entry, exit, direct)
	}
	if err != nil {
		return speedLabPath{}, err
	}
	started := false
	defer func() {
		if native != nil && !started {
			clear(native.config)
			clear(native.metadata)
			clear(native.external.source)
			clear(native.external.capture)
			if native.directory != "" {
				_ = cleanupDesktopNodeLaunch(native)
			}
		}
	}()
	if err := a.checkConnectionOperation(); err != nil {
		return speedLabPath{}, err
	}
	if err := cmd.Start(); err != nil {
		return speedLabPath{}, err
	}
	started = true
	if native != nil {
		native.external.started = time.Now()
		desktopNodeOwners.Store(a, native)
	}
	a.mu.Lock()
	a.cmd = cmd
	a.state.Mode = "external-node"
	a.state.LogicalMode = "external-node"
	a.state.RuntimeMode = "external-" + exit.Protocol
	a.state.Base = sessionBase
	a.state.RouterID = external.ID
	a.state.Connected = false
	a.state.Phase = "speed-lab:external:proving-exit"
	a.state.LastError = ""
	a.mu.Unlock()
	if err := a.speedLabOwnRuntime(cmd); err != nil {
		return speedLabPath{}, err
	}
	if err := a.checkConnectionOperation(); err != nil {
		return speedLabPath{}, err
	}
	chosenExecution := "local"
	if native != nil {
		proof, proofErr := a.waitDesktopExternalProof(a.connectionOperationContextOrBackground(), native)
		err = proofErr
		chosenExecution = proof.Execution
		if err == nil {
			err = a.restoreDesktopCapturedMTU(a.connectionOperationContextOrBackground(), native)
		}
		if err == nil {
			err = a.verifyDesktopExternalCurrentPath(a.connectionOperationContextOrBackground(), native)
		}
		if err == nil {
			err = registerActiveDNSRuntimeConfig(a, external.ID, "external-"+exit.Protocol, filepath.Join(native.directory, "sing-box.json"))
		}
	} else if exit.Protocol == "openvpn" {
		err = a.proveOpenVPNStandardExitForOperation(exit.ExpectedPublicIP)
	} else {
		err = a.proveStandardExitForOperation(exit.ExpectedPublicIP)
	}
	if err != nil {
		return speedLabPath{}, fmt.Errorf("temporary external path proof failed: %w", err)
	}
	if err := a.checkConnectionOperation(); err != nil || !a.ownsConnectionRuntime(cmd) {
		cause := "temporary external runtime changed before proof adoption"
		if err != nil {
			cause = err.Error()
		}
		return speedLabPath{}, errors.New(cause)
	}
	a.mu.Lock()
	a.state.Connected = true
	a.state.Phase = "connected"
	a.mu.Unlock()
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return speedLabPath{}, err
	}
	if native != nil {
		a.monitorDesktopExternalRuntime(native)
	}
	path := speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: external.ID, NodeName: external.Name, ExitID: external.ID, ExitName: external.Name, RuntimeMode: "external-" + exit.Protocol, LogicalMode: "external-node", Base: sessionBase, ExternalProtocol: exit.Protocol, Execution: chosenExecution, Description: "temporary external direct/hopped exit; captured native node/DNS/execution proof passes before measurement and no profile selection is saved"}
	if !direct {
		path.EntryID, path.EntryName = entry.ID, entry.Name
		path.EntryMode = policy.MultihopEntryMode
	}
	return path, nil
}

func (a *app) startSpeedLabTorPath(q speedLabRequest, profile common.RouterProfile) (speedLabPath, error) {
	if q.EntryID != "" || q.EntryMode != "" || q.Execution != "" && q.Execution != "local" {
		return speedLabPath{}, errors.New("external Tor Speed Lab requires its direct owned Tor runtime")
	}
	if _, _, _, _, err := torBridgeProfile(profile); err != nil {
		return speedLabPath{}, err
	}
	if capability := torBridgeRuntimeCapability(); !capability.Supported {
		return speedLabPath{}, errors.New(capability.Reason)
	}
	policy, err := externalRuntimePolicy(profile)
	if err != nil {
		return speedLabPath{}, err
	}
	policy, err = externalDNSPolicyForPath(policy, common.RouterProfile{}, true)
	if err != nil {
		return speedLabPath{}, err
	}
	sessionTrackerFor(a).declareRequest("speed-lab:external", "tor")
	if err := a.speedLabStopRuntime(true); err != nil {
		return speedLabPath{}, err
	}
	command, err := torBridgeCommand(a, policy, profile)
	if err != nil {
		return speedLabPath{}, err
	}
	if err := a.checkConnectionOperation(); err != nil {
		return speedLabPath{}, err
	}
	if err := command.Start(); err != nil {
		return speedLabPath{}, err
	}
	a.mu.Lock()
	a.cmd = command
	a.state.Connected, a.state.Phase, a.state.LastError = false, "speed-lab:external:proving-tor", ""
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode, a.state.Base, a.state.RouterID = "external-node", "external-node", "external-tor-bridge", "tor", profile.ID
	a.mu.Unlock()
	if err := a.speedLabOwnRuntime(command); err != nil {
		return speedLabPath{}, err
	}
	if _, err := a.proveTorBridgeExit(); err != nil {
		return speedLabPath{}, err
	}
	if err := a.checkConnectionOperation(); err != nil || !a.ownsConnectionRuntime(command) {
		return speedLabPath{}, errors.Join(err, errors.New("Tor proof completed for a retired Speed Lab runtime"))
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil {
		return speedLabPath{}, err
	}
	return speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: profile.ID, NodeName: profile.Name, RuntimeMode: "external-tor-bridge", LogicalMode: "external-node", Base: "tor", ExternalProtocol: "tor-bridge", Execution: "local", Description: "temporary captured Tor bridge path with fresh dynamic Tor exit proof"}, nil
}

func (a *app) startSpeedLabTemporaryPath(q speedLabRequest) (speedLabPath, error) {
	topology := strings.ToLower(strings.TrimSpace(q.Topology))
	switch topology {
	case "", "router", "direct":
		return a.startSpeedLabRouterPath(q)
	case "multihop":
		return a.startSpeedLabMultihopPath(q)
	case "external":
		return a.startSpeedLabExternalPath(q)
	default:
		return speedLabPath{}, fmt.Errorf("unsupported temporary Speed Lab topology %q", topology)
	}
}
