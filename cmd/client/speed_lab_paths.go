package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type speedLabRequest struct {
	Scope              string   `json:"scope,omitempty"`
	Topology           string   `json:"topology,omitempty"`
	NodeID             string   `json:"node_id,omitempty"`
	EntryID            string   `json:"entry_id,omitempty"`
	ExitID             string   `json:"exit_id,omitempty"`
	Mode               string   `json:"mode,omitempty"`
	Base               string   `json:"base,omitempty"`
	ExitMode           string   `json:"exit_mode,omitempty"`
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
	ExitID           string    `json:"exit_id,omitempty"`
	ExitName         string    `json:"exit_name,omitempty"`
	RequestedMode    string    `json:"requested_mode,omitempty"`
	RuntimeMode      string    `json:"runtime_mode,omitempty"`
	LogicalMode      string    `json:"logical_mode,omitempty"`
	Base             string    `json:"base,omitempty"`
	ExitMode         string    `json:"exit_mode,omitempty"`
	ExternalProtocol string    `json:"external_protocol,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	Description      string    `json:"description"`
}

type speedLabPathIdentity struct {
	SessionID  string
	StateToken string
	RouterID   string
	Graph      activeMultihopGraph
	GraphOK    bool
}

type speedLabTemporarySnapshot struct {
	Profiles common.RouterProfileStore
	State    state
}

func captureSpeedLabIdentity(a *app) (speedLabPathIdentity, speedLabPath, error) {
	a.mu.Lock()
	st := a.state
	profile, profileOK := a.profileByIDLocked(strings.TrimSpace(st.RouterID))
	a.mu.Unlock()
	if !st.Connected || strings.TrimSpace(st.Phase) != "connected" {
		return speedLabPathIdentity{}, speedLabPath{}, errors.New("Speed Lab current-path test requires a stable connected VPN; choose system-direct or a temporary test path while disconnected")
	}
	session, err := captureAsyncMeasurementSession(a)
	if err != nil { return speedLabPathIdentity{}, speedLabPath{}, err }
	if strings.TrimSpace(st.RouterID) == "" || session.RouterID != st.RouterID { return speedLabPathIdentity{}, speedLabPath{}, errors.New("active Speed Lab path identity is unavailable or disagrees with the session tracker") }
	if !profileOK { return speedLabPathIdentity{}, speedLabPath{}, errors.New("active Speed Lab node disappeared") }
	graph, graphOK := getActiveMultihopGraph(a)
	if st.Mode == "multihop" && !graphOK { return speedLabPathIdentity{}, speedLabPath{}, errors.New("active multihop graph identity is unavailable") }
	path := speedLabPath{Scope: "current", Topology: "router", NodeID: profile.ID, NodeName: profile.Name, RuntimeMode: st.RuntimeMode, LogicalMode: st.LogicalMode, Base: st.Base, Description: "actual currently connected Router VPN path; mutable selection is not used as path proof"}
	if strings.EqualFold(profile.NodeKind, "external") || profile.External != nil { path.Topology = "external"; if profile.External != nil { path.ExternalProtocol = profile.External.Protocol } }
	if st.Mode == "multihop" {
		path.Topology = "multihop"; path.EntryID, path.ExitID = graph.EntryID, graph.ExitID; path.Base, path.ExitMode, path.StartedAt = graph.Base, graph.ExitMode, graph.Started
		a.mu.Lock(); if entry, ok := a.profileByIDLocked(graph.EntryID); ok { path.EntryName = entry.Name }; if exit, ok := a.profileByIDLocked(graph.ExitID); ok { path.ExitName = exit.Name }; a.mu.Unlock()
	}
	return speedLabPathIdentity{SessionID: session.ID, StateToken: mtuStateSnapshotToken(st), RouterID: st.RouterID, Graph: graph, GraphOK: graphOK}, path, nil
}

func validateSpeedLabIdentity(a *app, identity speedLabPathIdentity) error {
	session := sessionTrackerFor(a).snapshot(0)
	if identity.SessionID == "" || session.ID != identity.SessionID || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.RouterID != identity.RouterID { return errors.New("Speed Lab result became stale because the VPN session/path changed") }
	a.mu.Lock(); st := a.state; a.mu.Unlock()
	if !st.Connected || st.RouterID != identity.RouterID || mtuStateSnapshotToken(st) != identity.StateToken { return errors.New("Speed Lab result became stale because the active node/mode/base changed") }
	if identity.GraphOK { current, ok := getActiveMultihopGraph(a); if !ok || current.EntryID != identity.Graph.EntryID || current.ExitID != identity.Graph.ExitID || current.Base != identity.Graph.Base || current.ExitMode != identity.Graph.ExitMode || !current.Started.Equal(identity.Graph.Started) { return errors.New("Speed Lab result became stale because the launched multihop graph changed") } }
	return nil
}

func (a *app) speedLabSnapshotTemporary() speedLabTemporarySnapshot {
	a.mu.Lock(); defer a.mu.Unlock(); st := a.state
	st.Connected = false; st.Mode = "off"; st.LogicalMode = ""; st.RuntimeMode = ""; st.Base = ""; st.Phase = "off"; st.RouterID = a.profiles.SelectedID
	return speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(a.profiles), State: st}
}

func (a *app) speedLabWriteStore(store common.RouterProfileStore) error {
	body, err := json.MarshalIndent(store, "", "  "); if err != nil { return err }
	return atomicWritePrivate(a.cfg.ProfilesFile, append(body, '\n'))
}

func (a *app) speedLabRestoreTemporary(snapshot speedLabTemporarySnapshot) error {
	stopErr := a.stopMode()
	if stopErr != nil {
		persistErr := a.speedLabWriteStore(snapshot.Profiles)
		return errors.Join(stopErr, persistErr)
	}
	a.mu.Lock(); a.rollbackProfilesLocked(snapshot.Profiles); a.state = snapshot.State; a.mu.Unlock()
	return a.speedLabWriteStore(snapshot.Profiles)
}

func (a *app) applySpeedLabTemporaryProfile(nodeID string, q speedLabRequest) (common.RouterProfile, error) {
	nodeID = strings.TrimSpace(nodeID); if !validProfileID(nodeID) { return common.RouterProfile{}, errors.New("temporary Speed Lab path requires a valid linked node id") }
	a.mu.Lock(); defer a.mu.Unlock(); index := -1
	for i := range a.profiles.Profiles { if a.profiles.Profiles[i].ID == nodeID { index = i; break } }
	if index < 0 { return common.RouterProfile{}, errors.New("temporary Speed Lab node is not linked") }
	a.profiles.SelectedID = nodeID; p := &a.profiles.Profiles[index]
	if base := normalizeBase(q.Base); base == "wg" || base == "awg" { p.BaseTunnel = base }
	if q.RequireEncrypted != nil { p.AutoRequireEncrypted = *q.RequireEncrypted }
	if q.RequireObfuscation != nil { p.AutoRequireObfuscation = *q.RequireObfuscation }
	if q.DAITA != nil { a.state.DAITA = *q.DAITA }
	if q.Jumbo != nil { a.state.Jumbo = *q.Jumbo }
	a.state.RouterID = nodeID
	return *p, nil
}

func waitForSpeedLabConnectedIdentity(a *app, timeout time.Duration) (speedLabPathIdentity, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		identity, _, err := captureSpeedLabIdentity(a); if err == nil { return identity, nil }
		if opErr := a.checkConnectionOperation(); opErr != nil { return speedLabPathIdentity{}, opErr }
		time.Sleep(50 * time.Millisecond)
	}
	return speedLabPathIdentity{}, errors.New("temporary Speed Lab path connected but typed path proof did not become current")
}

func (a *app) startSpeedLabRouterPath(q speedLabRequest) (speedLabPath, error) {
	profile, err := a.applySpeedLabTemporaryProfile(q.NodeID, q); if err != nil { return speedLabPath{}, err }
	if strings.EqualFold(profile.NodeKind, "external") || profile.External != nil { return speedLabPath{}, errors.New("choose topology=external for an external custom node") }
	mode := strings.ToLower(strings.TrimSpace(q.Mode)); if mode == "" { mode = "smart-auto" }
	base := normalizeBase(q.Base); if base == "auto" { base = "" }
	var runtimeID, actualBase, logical string
	switch mode {
	case "smart-auto":
		result, runErr := a.runSmartStrategy(); if runErr != nil { return speedLabPath{}, runErr }; runtimeID, logical = result.RuntimeMode, "smart-auto"; a.mu.Lock(); actualBase = a.state.Base; a.mu.Unlock()
	case "auto":
		result, runErr := a.runAutoStrategy("auto"); if runErr != nil { return speedLabPath{}, runErr }; runtimeID, logical = result.RuntimeMode, "auto"; a.mu.Lock(); actualBase = a.state.Base; a.mu.Unlock()
	case "custom":
		result, runErr := a.runCustomStrategy(q.CustomLayers); if runErr != nil { return speedLabPath{}, runErr }; runtimeID, logical = result.RuntimeMode, "custom"; a.mu.Lock(); actualBase = a.state.Base; a.mu.Unlock()
	default:
		sessionTrackerFor(a).declareRequest("speed-lab:"+mode, base); used, runErr := a.startLogicalMode(mode, base); if runErr != nil { return speedLabPath{}, runErr }
		runtimeID, actualBase, logical = used.RuntimeID, used.Base, mode
		a.mu.Lock(); a.state.LogicalMode = logical; a.state.RuntimeMode = runtimeID; if actualBase != "native" && actualBase != "auto" { a.state.Base = actualBase }; a.state.RouterID = profile.ID; a.state.Connected = true; a.state.Phase = "connected"; a.mu.Unlock()
	}
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil { return speedLabPath{}, err }
	return speedLabPath{Scope: "temporary", Topology: "router", Temporary: true, NodeID: profile.ID, NodeName: profile.Name, RequestedMode: mode, RuntimeMode: runtimeID, LogicalMode: logical, Base: actualBase, Description: "temporary Router VPN path; linked-node selection and profile settings are restored after the test"}, nil
}

func (a *app) resolveSpeedLabMultihop(q speedLabRequest, control common.RouterProfile, profiles []common.RouterProfile) (multihopSelection, error) {
	request := multihopConnectRequest{EntryID: q.EntryID, ExitID: q.ExitID, Base: q.Base, ExitMode: q.ExitMode}
	if runtime.GOOS == "linux" { return resolveMultihopSelection(control, profiles, request) }
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" { return resolveNativeMultihopSelection(control, profiles, request) }
	return multihopSelection{}, errors.New("temporary desktop multihop Speed Lab is unavailable on this platform")
}

func (a *app) startSpeedLabMultihopPath(q speedLabRequest) (speedLabPath, error) {
	entryProfile, err := a.applySpeedLabTemporaryProfile(q.EntryID, q); if err != nil { return speedLabPath{}, err }
	if strings.EqualFold(entryProfile.NodeKind, "external") || entryProfile.External != nil { return speedLabPath{}, errors.New("Router VPN node-to-node multihop requires a Router VPN entry; use topology=external for an external entry/exit graph") }
	a.mu.Lock(); profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...); a.mu.Unlock()
	sel, err := a.resolveSpeedLabMultihop(q, entryProfile, profiles); if err != nil { return speedLabPath{}, err }
	sessionTrackerFor(a).declareRequest("speed-lab:multihop", sel.Base)
	if err := a.stopMode(); err != nil { return speedLabPath{}, err }
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" { cmd = multihopCommand(a, sel) } else { cmd, err = nativeMultihopPlatformCommand(a, sel); if err != nil { return speedLabPath{}, err } }
	if err := a.checkConnectionOperation(); err != nil { return speedLabPath{}, err }
	if err := cmd.Start(); err != nil { return speedLabPath{}, err }
	a.mu.Lock(); a.cmd = cmd; a.state.Mode = "multihop"; a.state.LogicalMode = "multihop"; a.state.RuntimeMode = sel.ExitMode; a.state.Base = sel.Base; a.state.RouterID = sel.Exit.ID; a.state.Connected = false; a.state.Phase = "speed-lab:multihop:proving-exit"; a.state.LastError = ""; a.mu.Unlock()
	setActiveMultihopGraph(a, sel)
	if err := a.checkConnectionOperation(); err != nil { message, _ := a.multihopStopFailure(cmd, err.Error()); return speedLabPath{}, errors.New(message) }
	if err := a.proveMultihopExit(sel.Exit); err != nil { message, _ := a.multihopStopFailure(cmd, "temporary multihop exit proof failed: "+err.Error()); return speedLabPath{}, errors.New(message) }
	if err := a.checkConnectionOperation(); err != nil || !a.ownsConnectionRuntime(cmd) {
		cause := "temporary multihop runtime changed before proof adoption"; if err != nil { cause = err.Error() }
		message, cleanupFailed := a.multihopStopFailure(cmd, cause); if !a.ownsConnectionRuntime(cmd) && !cleanupFailed { clearActiveMultihopGraph(a) }; return speedLabPath{}, errors.New(message)
	}
	a.mu.Lock(); a.state.Connected = true; a.state.Phase = "connected"; a.mu.Unlock()
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil { return speedLabPath{}, err }
	return speedLabPath{Scope: "temporary", Topology: "multihop", Temporary: true, EntryID: sel.Entry.ID, EntryName: sel.Entry.Name, ExitID: sel.Exit.ID, ExitName: sel.Exit.Name, RuntimeMode: sel.ExitMode, LogicalMode: "multihop", Base: sel.Base, ExitMode: sel.ExitMode, StartedAt: time.Now().UTC(), Description: "temporary proven multihop graph; entry/exit/base/exit transport are not saved"}, nil
}

func speedLabExternalEntry(profiles []common.RouterProfile, external common.RouterProfile, q speedLabRequest) (common.RouterProfile, string, bool, error) {
	entryID := strings.TrimSpace(q.EntryID); if entryID == "" { return common.RouterProfile{}, "", true, nil }
	if entryID == external.ID { return common.RouterProfile{}, "", false, errors.New("temporary external entry and exit must be different") }
	entry, ok := profileByID(profiles, entryID); if !ok { return common.RouterProfile{}, "", false, errors.New("temporary external entry is not linked") }
	kind := strings.TrimSpace(entry.NodeKind); if kind == "" { kind = "router-vpn" }
	switch kind {
	case "router-vpn":
		if base := normalizeBase(q.Base); base != "" && base != "auto" && base != "wg" { return common.RouterProfile{}, "", false, errors.New("Router VPN entry for an external exit currently requires standard WireGuard") }
		if strings.TrimSpace(entry.Endpoint) == "" { return common.RouterProfile{}, "", false, errors.New("Router VPN external-entry hop has no public endpoint") }
	case "external":
		entryExit, err := standardExitFromExternalProfile(entry); if err != nil { return common.RouterProfile{}, "", false, err }
		if entryExit.Protocol == "openvpn" { return common.RouterProfile{}, "", false, errors.New("external OpenVPN remains unavailable as an upstream hop") }
	default:
		return common.RouterProfile{}, "", false, errors.New("unsupported temporary external entry kind")
	}
	return entry, kind, false, nil
}

func (a *app) startSpeedLabExternalPath(q speedLabRequest) (speedLabPath, error) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" { return speedLabPath{}, errors.New("temporary external Speed Lab path requires the desktop external-node runtime on this platform") }
	external, err := a.applySpeedLabTemporaryProfile(q.NodeID, q); if err != nil { return speedLabPath{}, err }
	if external.NodeKind != "external" || external.External == nil { return speedLabPath{}, errors.New("temporary external Speed Lab path requires an external custom node") }
	policy, err := externalRuntimePolicy(external); if err != nil { return speedLabPath{}, err }
	exit, err := standardExitFromExternalProfile(external); if err != nil { return speedLabPath{}, err }
	a.mu.Lock(); profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...); a.mu.Unlock()
	entry, entryKind, direct, err := speedLabExternalEntry(profiles, external, q); if err != nil { return speedLabPath{}, err }
	if exit.Protocol == "openvpn" { capability := openVPNRuntimeCapability(); if runtime.GOOS == "windows" { capability = windowsOpenVPNRuntimeCapability() }; if !capability.Supported { return speedLabPath{}, errors.New(capability.Reason) }; if !direct && !openVPNProtocolIsTCP(exit.Method) { return speedLabPath{}, errors.New("hopped OpenVPN Speed Lab tests require TCP OpenVPN; UDP remains fail-closed") } }
	sessionBase := "external"; if !direct && entryKind == "router-vpn" { sessionBase = "wg" }
	sessionTrackerFor(a).declareRequest("speed-lab:external", sessionBase)
	if err := a.stopMode(); err != nil { return speedLabPath{}, err }
	var cmd *exec.Cmd
	if exit.Protocol == "openvpn" { if runtime.GOOS == "windows" { cmd, err = windowsOpenVPNStandardExitCommand(a, policy, entry, exit, direct) } else { cmd, err = openVPNStandardExitCommand(a, policy, entry, exit, direct) } } else if !direct && entryKind == "external" { cmd, err = nativeExternalEntryStandardExitCommand(a, policy, entry, exit) } else { cmd, err = nativeStandardExitCommand(a, policy, entry, exit, direct) }
	if err != nil { return speedLabPath{}, err }
	if err := a.checkConnectionOperation(); err != nil { return speedLabPath{}, err }
	if err := cmd.Start(); err != nil { return speedLabPath{}, err }
	a.mu.Lock(); a.cmd = cmd; a.state.Mode = "external-node"; a.state.LogicalMode = "external-node"; a.state.RuntimeMode = "external-" + exit.Protocol; a.state.Base = sessionBase; a.state.RouterID = external.ID; a.state.Connected = false; a.state.Phase = "speed-lab:external:proving-exit"; a.state.LastError = ""; a.mu.Unlock()
	if err := a.checkConnectionOperation(); err != nil { message, _ := a.externalProfileStopFailure(cmd, err.Error()); return speedLabPath{}, errors.New(message) }
	if exit.Protocol == "openvpn" { err = a.proveOpenVPNStandardExitForOperation(exit.ExpectedPublicIP) } else { err = a.proveStandardExitForOperation(exit.ExpectedPublicIP) }
	if err != nil { message, _ := a.externalProfileStopFailure(cmd, "temporary external public-exit proof failed: "+err.Error()); return speedLabPath{}, errors.New(message) }
	if err := a.checkConnectionOperation(); err != nil || !a.ownsConnectionRuntime(cmd) { cause := "temporary external runtime changed before public-exit proof adoption"; if err != nil { cause = err.Error() }; message, _ := a.externalProfileStopFailure(cmd, cause); return speedLabPath{}, errors.New(message) }
	a.mu.Lock(); a.state.Connected = true; a.state.Phase = "connected"; a.mu.Unlock()
	if _, err := waitForSpeedLabConnectedIdentity(a, 2500*time.Millisecond); err != nil { return speedLabPath{}, err }
	path := speedLabPath{Scope: "temporary", Topology: "external", Temporary: true, NodeID: external.ID, NodeName: external.Name, RuntimeMode: "external-" + exit.Protocol, LogicalMode: "external-node", Base: sessionBase, ExternalProtocol: exit.Protocol, Description: "temporary external direct/hopped exit; public-exit proof must pass and no profile selection is saved"}
	if !direct { path.EntryID, path.EntryName = entry.ID, entry.Name }
	return path, nil
}

func (a *app) startSpeedLabTemporaryPath(q speedLabRequest) (speedLabPath, error) {
	topology := strings.ToLower(strings.TrimSpace(q.Topology))
	switch topology {
	case "", "router", "direct": return a.startSpeedLabRouterPath(q)
	case "multihop": return a.startSpeedLabMultihopPath(q)
	case "external": return a.startSpeedLabExternalPath(q)
	default: return speedLabPath{}, fmt.Errorf("unsupported temporary Speed Lab topology %q", topology)
	}
}
