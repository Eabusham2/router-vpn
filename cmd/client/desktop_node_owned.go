package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// The original graph and the latest protection predecessor have separate
// lifetimes. Only the original private input is retained by a restore plan;
// every new process acquires its predecessor from the app's joined slot.
type desktopOwnedNodeRuntime struct {
	policy       *mobilemultihop.DesktopNodePolicy
	source       []byte
	network      string
	profileToken string
	options      [3]bool
	slot         *desktopNodeProtectionSlot
	attempt      *desktopNodeProtectionAttempt
	// Process, start, readiness and retirement fields use launch.workspaceMu.
	process       desktopNodeProcess
	started       time.Time
	ready         *mobilemultihop.DesktopNodeReadyRecord
	retired       bool
	monitorCancel context.CancelFunc
	monitorDone   chan struct{}
}

type desktopNodeHandoffRecord struct {
	Schema         int    `json:"schema"`
	Kind           string `json:"kind"`
	SessionID      string `json:"session_id"`
	SourceSHA256   string `json:"source_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	TransferSHA256 string `json:"transfer_sha256"`
	NetworkID      string `json:"network_id"`
	Policy         string `json:"policy"`
	BaselineSHA256 string `json:"baseline_sha256"`
	Nonce          string `json:"nonce"`
	Accepted       bool   `json:"accepted"`
}

// An effective MTU result and presentation booleans are not replacements for
// the saved source. The three runtime options are captured independently.
func desktopOwnedNodeProfileToken(profile common.RouterProfile) string {
	profile.EffectiveMTU = 0
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = false, false, false
	return liveMeasurementProfileToken(profile)
}

func newDesktopOwnedNodeLaunch(profile common.RouterProfile, original *mobilemultihop.NodeProfile, mode, root, endpoint, network, session string, restoredMTU int) (*desktopNodeLaunch, error) {
	if original == nil || network == "" || root == "" || profile.ID == "" ||
		(mode != "wg" && mode != "awg2-fast" && mode != "awg2-strong") ||
		(profile.StartLayer != "" && profile.StartLayer != "off") {
		return nil, errors.New("native Router ownership requires its captured supported graph")
	}
	policy, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, "windows", restoredMTU)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	if meta.ProfileID != profile.ID || meta.Mode != mode || meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always" {
		return nil, errors.New("native Router ownership changed its original node or protection policy")
	}
	source, err := original.LaunchInput()
	if err != nil {
		return nil, err
	}
	if err := validateDesktopOwnedNodeSourceProfile(profile, endpoint, source); err != nil {
		return nil, err
	}
	receipt, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return &desktopNodeLaunch{root: root, endpoint: endpoint, profileID: profile.ID, mode: mode,
		config: []byte(policy.Config()), metadata: receipt, configSHA256: meta.ConfigSHA256, mtuSession: session,
		ownedNode: &desktopOwnedNodeRuntime{policy: policy, source: []byte(source), network: network,
			profileToken: desktopOwnedNodeProfileToken(profile), options: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}}}, nil
}

// The caller captures endpoint from the same compileDesktopNode operation;
// a hostname resolution never substitutes a profile, credential or DNS policy.
// Recheck the sealed original input instead of trusting its public profile ID.
func validateDesktopOwnedNodeSourceProfile(profile common.RouterProfile, endpoint, source string) error {
	bad := errors.New("native Router source belongs to another captured profile")
	ip, err := netip.ParseAddr(endpoint)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Zone() != "" || ip.Is4In6() {
		return bad
	}
	if originalIP, err := netip.ParseAddr(profile.Endpoint); err == nil && originalIP != ip {
		return bad
	}
	var envelope struct {
		ProfileJSON string `json:"profile_json"`
	}
	var captured, expected common.RouterProfile
	if json.Unmarshal([]byte(source), &envelope) != nil || envelope.ProfileJSON == "" || json.Unmarshal([]byte(envelope.ProfileJSON), &captured) != nil {
		return bad
	}
	profile.Endpoint = endpoint
	if profile.NodeKind == "" {
		profile.NodeKind = "router-vpn"
	}
	raw, err := json.Marshal(profile)
	if err != nil || json.Unmarshal(raw, &expected) != nil {
		clear(raw)
		return bad
	}
	clear(raw)
	if desktopOwnedNodeProfileToken(captured) != desktopOwnedNodeProfileToken(expected) ||
		[3]bool{captured.DAITAEnabled, captured.JumboTUN, captured.SocksEnabled} != [3]bool{expected.DAITAEnabled, expected.JumboTUN, expected.SocksEnabled} {
		return bad
	}
	return nil
}

func (a *app) desktopOwnedNodeProtection() (*desktopNodeProtectionSlot, error) {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot != nil {
		return slot, nil
	}
	backend, err := desktopOwnedNodeProtectionBackend()
	if err != nil {
		return nil, err
	}
	candidate := &desktopNodeProtectionSlot{backend: backend}
	a.mu.Lock()
	if a.nodeProtection == nil {
		a.nodeProtection = candidate
	}
	slot = a.nodeProtection
	a.mu.Unlock()
	return slot, nil
}

func (a *app) retainedDesktopNodeProtection() bool {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	return slot != nil && !slot.provedEmpty()
}

func (s *desktopNodeProtectionSlot) provedEmpty() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known && s.target == nil && s.active == nil && s.retirement == nil
}

// current never takes the protection slot lock. The slot may invoke this guard
// while proving a prepared baseline; retirement's join callback likewise must
// only join the captured child and must not re-enter the slot.
func (a *app) desktopOwnedNodeCurrent(launch *desktopNodeLaunch, processRequired bool) bool {
	if a == nil || launch == nil || launch.ownedNode == nil || launch.command == nil {
		return false
	}
	owned := launch.ownedNode
	if owned.policy == nil || owned.policy.Validate() != nil || owned.network == "" || physicalNetworkIdentity() != owned.network {
		return false
	}
	if raw, exists := desktopNodeOwners.Load(a); !exists || raw != launch {
		return false
	}
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(launch.profileID)
	current := exists && !a.closing && a.cmd == launch.command && a.state.RouterID == launch.profileID &&
		a.state.RuntimeMode == launch.mode && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == owned.options &&
		desktopOwnedNodeProfileToken(profile) == owned.profileToken
	a.mu.Unlock()
	if !current {
		return false
	}
	launch.workspaceMu.Lock()
	process, retired := owned.process, owned.retired
	launch.workspaceMu.Unlock()
	return !retired && (!processRequired || process != nil && process.Started() && process.Alive() == nil)
}

func stageDesktopOwnedNodeInputs(a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.ownedNode == nil || launch.directoryRoot == nil || launch.external != nil || launch.tor != nil {
		return errors.New("native Router staging has no captured private owner")
	}
	owned := launch.ownedNode
	if owned.policy == nil || owned.policy.Validate() != nil || owned.attempt != nil || string(launch.config) != owned.policy.Config() ||
		launch.mtuSession != owned.policy.Metadata().SessionID || physicalNetworkIdentity() != owned.network {
		return errors.New("native Router staging changed its captured graph or network")
	}
	// Copy source first; no kernel mutation occurs in begin. A failed staging
	// attempt still owns an explicit predecessor expectation for safe discard.
	if err := writeDesktopRuntimeFile(launch, "node-source.json", owned.source, false); err != nil {
		return err
	}
	slot, err := a.desktopOwnedNodeProtection()
	if err != nil {
		return err
	}
	attempt, err := slot.begin(a.connectionOperationContextOrBackground(), launch, owned.policy)
	if err != nil {
		return err
	}
	owned.slot, owned.attempt = slot, attempt
	raw, err := mobiletor.CanonicalDesktopProtectionTransferRecord(attempt.transfer)
	if err != nil {
		return err
	}
	return writeDesktopRuntimeFile(launch, "node-protection-transfer.json", raw, false)
}

func desktopOwnedNodeArguments(launch *desktopNodeLaunch) ([]string, error) {
	if launch == nil || launch.ownedNode == nil || launch.ownedNode.policy == nil || launch.ownedNode.attempt == nil ||
		launch.ownedNode.attempt.launch != launch || launch.ownedNode.attempt.policy != launch.ownedNode.policy {
		return nil, errors.New("native Router command lost its captured transfer")
	}
	owned := launch.ownedNode
	meta := owned.policy.Metadata()
	args := []string{"routervpn-node", "--runtime-dir", launch.directory, "--session", meta.SessionID, "--config-sha256", meta.ConfigSHA256,
		"--physical-source-sha256", meta.SourceSHA256, "--physical-transfer-sha256", owned.attempt.digest}
	if meta.RestoredMTU != 0 {
		args = append(args, "--physical-mtu", strconv.Itoa(meta.RestoredMTU))
	}
	return validateDesktopNodeProcessArguments(args, launch.directory)
}

func startDesktopNodeLaunch(a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.command == nil {
		return errors.New("native Router process has no captured command")
	}
	if launch.ownedNode == nil {
		return launch.command.Start()
	}
	return startDesktopOwnedNodeLaunchWith(a.connectionOperationContextOrBackground(), a, launch, startDesktopOwnedNodeProcess)
}

func startDesktopOwnedNodeLaunchWith(ctx context.Context, a *app, launch *desktopNodeLaunch,
	start func(context.Context, []string, []string, string) (desktopNodeProcess, error)) error {
	if ctx == nil || ctx.Err() != nil || start == nil || !a.desktopOwnedNodeCurrent(launch, false) {
		return errors.New("native Router process no longer belongs to its captured operation")
	}
	owned := launch.ownedNode
	args, err := desktopOwnedNodeArguments(launch)
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	if owned.process != nil || !owned.started.IsZero() {
		launch.workspaceMu.Unlock()
		return errors.New("native Router process was already created")
	}
	owned.started = time.Now()
	launch.workspaceMu.Unlock()
	process, err := start(ctx, args, launch.command.Env, launch.directory)
	launch.workspaceMu.Lock()
	owned.process = process // Retain partial native creation even when start failed.
	launch.workspaceMu.Unlock()
	if err != nil || ctx.Err() != nil || process == nil || !process.Started() || !a.desktopOwnedNodeCurrent(launch, true) {
		return errors.Join(err, ctx.Err(), errors.New("native Router process did not retain its exact child owner"))
	}
	return a.admitDesktopOwnedNode(ctx, launch)
}

func desktopNodeHandoff(raw []byte, launch *desktopNodeLaunch) (desktopNodeHandoffRecord, mobiletor.DesktopWindowsProtectionTarget, error) {
	var record desktopNodeHandoffRecord
	bad := errors.New("native Router handoff belongs to another source or process")
	if launch == nil || launch.ownedNode == nil || launch.ownedNode.attempt == nil || len(raw) == 0 || len(raw) > 2048 {
		return record, mobiletor.DesktopWindowsProtectionTarget{}, bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 11 || decodeRelayControlJSON(raw, &record) != nil {
		return record, mobiletor.DesktopWindowsProtectionTarget{}, bad
	}
	meta := launch.ownedNode.policy.Metadata()
	if record.Schema != 1 || record.Kind != "routervpn-node-physical-handoff-v2" || record.Accepted ||
		record.SessionID != meta.SessionID || record.SourceSHA256 != meta.SourceSHA256 || record.ConfigSHA256 != meta.ConfigSHA256 ||
		record.TransferSHA256 != launch.ownedNode.attempt.digest || record.Policy != meta.KillSwitchPolicy || !desktopMTURequestPattern.MatchString(record.NetworkID) {
		return record, mobiletor.DesktopWindowsProtectionTarget{}, bad
	}
	for _, value := range []string{record.BaselineSHA256, record.Nonce} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
			return record, mobiletor.DesktopWindowsProtectionTarget{}, bad
		}
	}
	target := mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: record.SessionID, SourceSHA256: record.SourceSHA256, NetworkID: record.NetworkID}, Policy: record.Policy, BaselineSHA256: record.BaselineSHA256}
	if target.Validate() != nil {
		return record, mobiletor.DesktopWindowsProtectionTarget{}, bad
	}
	return record, target, nil
}

func (a *app) admitDesktopOwnedNode(parent context.Context, launch *desktopNodeLaunch) error {
	if parent == nil || parent.Err() != nil || launch == nil || launch.ownedNode == nil {
		return errors.New("native Router handoff has no active operation")
	}
	owned := launch.ownedNode
	if owned.attempt == nil || owned.attempt.launch != launch || owned.slot == nil {
		return errors.New("native Router handoff has no exact transfer owner")
	}
	current := func() bool { return parent.Err() == nil && a.desktopOwnedNodeCurrent(launch, true) }
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil || !current() {
			return errors.Join(ctx.Err(), errors.New("native Router handoff lost its captured child or network"))
		}
		raw, err := readDesktopRuntimeFile(launch, "node-physical-handoff-ready.json", 2048)
		if err == nil {
			record, target, err := desktopNodeHandoff(raw, launch)
			if err != nil {
				return err
			}
			if err := owned.slot.provePrepared(ctx, owned.attempt, target, current); err != nil {
				return err
			}
			record.Accepted = true
			ack, err := json.Marshal(record)
			if err != nil || !current() {
				return errors.Join(err, errors.New("native Router handoff retired before acknowledgement"))
			}
			if err := writeDesktopRuntimeFile(launch, "node-physical-handoff-ack.json", ack, false); err != nil {
				return err
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	// The physical baseline acknowledgement precedes native sockets/TUN. It is
	// not Connected: wait for a fresh selected-DNS query and actual TUN readback.
	readyContext, cancelReady := context.WithTimeout(parent, 25*time.Second)
	defer cancelReady()
	for {
		if readyContext.Err() != nil || !current() {
			return errors.Join(readyContext.Err(), errors.New("native Router readiness lost its captured child"))
		}
		record, err := a.readDesktopOwnedNodeReady(launch, true)
		if err == nil {
			launch.workspaceMu.Lock()
			copy := record
			owned.ready = &copy
			launch.workspaceMu.Unlock()
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-readyContext.Done():
			return readyContext.Err()
		case <-ticker.C:
		}
	}
}

func (a *app) readDesktopOwnedNodeReady(launch *desktopNodeLaunch, fresh bool) (mobilemultihop.DesktopNodeReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeReadyRecord
	if !a.desktopOwnedNodeCurrent(launch, true) {
		return empty, errors.New("native Router readiness no longer belongs to this process")
	}
	owned := launch.ownedNode
	raw, err := readDesktopRuntimeFile(launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
	if err != nil {
		return empty, err
	}
	record, err := mobilemultihop.ParseDesktopNodeReadyRecord(raw, owned.policy, owned.attempt.digest)
	if err != nil {
		return empty, err
	}
	launch.workspaceMu.Lock()
	started, captured := owned.started, owned.ready
	launch.workspaceMu.Unlock()
	now := time.Now().UnixMilli()
	if started.IsZero() || record.ProvedAt < started.UnixMilli() || record.ProvedAt > now ||
		fresh && now-record.ProvedAt > 30000 || !fresh && (captured == nil || *captured != record) {
		return empty, errors.New("native Router readiness is stale or belongs to a different start")
	}
	live, err := readDesktopNodeMTU(launch)
	provedExpiry := live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored"
	failed := live.Failure != "" && !provedExpiry
	// An owned MTU transaction may recreate the same named TUN with a new
	// kernel index. The child advances Reader only after adopting that exact
	// returned inbound and granting its new interface through the owned lower
	// policy. The original reader must still match the initial readiness index;
	// neither initial nor replacement readers may change the captured name.
	changedTUN := live.Interface != record.InterfaceName || live.Reader == 1 && live.Index != int(record.InterfaceIndex)
	if err != nil || failed || changedTUN || fresh && (live.Active || live.Failure != "" || live.Reader != 1 || live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU) || !a.desktopOwnedNodeCurrent(launch, true) {
		return empty, errors.Join(err, errors.New("native Router readiness lost its actual TUN owner"))
	}
	return record, nil
}

// A command descriptor is only transaction identity for this path. Never
// synthesize exec.Cmd.Process from a PID or join an unrelated wrapper instead.
func desktopOwnedNodeProcess(launch *desktopNodeLaunch) desktopNodeProcess {
	if launch == nil || launch.ownedNode == nil {
		return nil
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	return launch.ownedNode.process
}

func desktopOwnedNodeCreated(launch *desktopNodeLaunch) bool {
	process := desktopOwnedNodeProcess(launch)
	return process != nil && process.Started()
}

func (a *app) retireDesktopOwnedNode(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.ownedNode == nil {
		return errors.New("native Router retirement has no captured owner")
	}
	owned := launch.ownedNode
	if owned.attempt == nil && desktopOwnedNodeProcess(launch) == nil {
		// No transfer was begun and no child was created. This only retires
		// never-executed private inputs; it does not discover or mutate policy.
		launch.workspaceMu.Lock()
		owned.retired = true
		launch.workspaceMu.Unlock()
		return nil
	}
	if owned.attempt == nil || owned.slot == nil || owned.attempt.launch != launch {
		return errors.New("native Router retirement lost its exact predecessor")
	}
	launch.workspaceMu.Lock()
	retired := owned.retired
	launch.workspaceMu.Unlock()
	if retired {
		return nil
	}
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot != owned.slot {
		return errors.New("native Router retirement belongs to another application owner")
	}
	if err := stopDesktopOwnedNodeMonitor(ctx, launch); err != nil {
		return err
	}
	join := func(ctx context.Context) error {
		if process := desktopOwnedNodeProcess(launch); process != nil {
			return process.Close(ctx)
		}
		return nil
	}
	// A missing or malformed receipt cannot keep an already cancelled child
	// running. Join this exact Job first, but retain the baseline and workspace
	// until the receipt plus independent native read are proved below.
	if err := join(ctx); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	raw, err := readDesktopRuntimeFile(launch, "node-protection-retired.json", mobiletor.DesktopProtectionTransferRecordLimit)
	if err == nil {
		closed, closedErr := readDesktopNodeStopped(launch)
		if closedErr != nil || !closed {
			return errors.Join(closedErr, errors.New("native Router retirement has no joined stop acknowledgement"))
		}
		record, parseErr := mobiletor.ParseDesktopProtectionRetirementRecord(raw, owned.attempt.transfer)
		if parseErr != nil {
			return parseErr
		}
		err = owned.slot.finish(ctx, owned.attempt, record, join)
	} else if errors.Is(err, os.ErrNotExist) {
		// Includes a child that failed before native preparation. A missing
		// receipt after committed preparation fails the exact original read.
		err = owned.slot.abandonUnchanged(ctx, owned.attempt, join)
	}
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	owned.retired, owned.ready = true, nil
	launch.workspaceMu.Unlock()
	return nil
}

func (a *app) discardDesktopOwnedNodeUnstarted(launch *desktopNodeLaunch) error {
	if launch == nil || launch.ownedNode == nil {
		return errors.New("native Router discard has no captured input")
	}
	if desktopOwnedNodeCreated(launch) {
		return errors.New("native Router discard cannot delete an executed workspace")
	}
	launch.workspaceMu.Lock()
	retired := launch.ownedNode.retired
	launch.workspaceMu.Unlock()
	if retired {
		if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := a.retireDesktopOwnedNode(ctx, launch)
	if err == nil {
		err = cleanupDesktopNodeLaunch(launch)
	}
	if err != nil {
		// Staging can fail before a command descriptor exists. Retain its
		// directory and exact slot so ordinary Stop/shutdown can retry it.
		if previous, loaded := desktopNodeOwners.LoadOrStore(a, launch); loaded && previous != launch {
			return errors.Join(err, errors.New("native Router failed staging could not replace another owner"))
		}
		return err
	}
	clear(launch.ownedNode.source)
	clear(launch.config)
	clear(launch.metadata)
	desktopNodeOwners.CompareAndDelete(a, launch)
	return nil
}

func (a *app) publishDesktopOwnedNodeStart(launch *desktopNodeLaunch, phase, base string) error {
	if launch == nil || launch.ownedNode == nil || launch.command == nil || launch.ownedNode.attempt == nil || launch.ownedNode.attempt.launch != launch {
		return errors.New("native Router start has no staged operation")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || a.cmd != nil {
		return errors.New("native Router start cannot replace another process")
	}
	if prior, exists := desktopNodeOwners.LoadOrStore(a, launch); exists && prior != launch {
		return errors.New("native Router start cannot replace another native owner")
	}
	a.cmd = launch.command
	a.state.Connected, a.state.Phase, a.state.LastError = false, phase, ""
	a.state.Mode, a.state.RuntimeMode, a.state.RouterID = launch.mode, launch.mode, launch.profileID
	a.state.LogicalMode, a.state.Base = "", base
	return nil
}

// Check before draining the old path. Other graph families still need their
// own native successor and restore support; rejecting after Stop would destroy
// a working connection while the new path cannot consume its retained deny.
func (a *app) guardDesktopOwnedNodeTransition(next *desktopNodeLaunch) error {
	if a.retainedDesktopNodeProtection() && (next == nil || next.ownedNode == nil) {
		return errors.New("the selected path cannot yet inherit this captured native protection; disconnect the current on-connect path first")
	}
	if next == nil || next.ownedNode == nil {
		return nil
	}
	a.mu.Lock()
	active := a.cmd != nil || a.state.Connected || a.state.Mode != "" && a.state.Mode != "off"
	a.mu.Unlock()
	if raw, exists := desktopNodeOwners.Load(a); exists {
		prior, ok := raw.(*desktopNodeLaunch)
		if !ok || prior == nil || prior.ownedNode == nil {
			return errors.New("native Router protection cannot adopt this legacy runtime; its captured cleanup must finish first")
		}
	} else if active {
		return errors.New("native Router protection cannot adopt an unrelated running mode")
	}
	return nil
}

func (a *app) prepareDesktopOwnedNodeStop(launch *desktopNodeLaunch, command *exec.Cmd) error {
	if launch == nil || launch.ownedNode == nil || command != nil && command != launch.command {
		return errors.New("native Router stop lost its captured command")
	}
	current := func() error {
		if raw, exists := desktopNodeOwners.Load(a); !exists || raw != launch {
			return errors.New("native Router stop no longer owns this workspace")
		}
		a.mu.Lock()
		matches := a.cmd == nil || a.cmd == launch.command
		a.mu.Unlock()
		if !matches {
			return errors.New("native Router stop cannot alter a replacement connection")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	retired := launch.ownedNode.retired
	launch.workspaceMu.Unlock()
	if retired {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if !desktopOwnedNodeCreated(launch) || desktopNodeProcessExited(launch) {
		return errors.Join(a.retireDesktopOwnedNode(ctx, launch), current())
	}
	if closed, err := readDesktopNodeStopped(launch); err != nil || closed {
		return errors.Join(err, current())
	}
	request, err := json.Marshal(desktopExternalStop{Schema: 1, SessionID: launch.mtuSession, SourceSHA256: launch.configSHA256})
	if err != nil {
		return err
	}
	if err := writeDesktopRuntimeFile(launch, "stop.json", request, true); err != nil {
		return err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := current(); err != nil {
			return err
		}
		if closed, err := readDesktopNodeStopped(launch); err != nil || closed {
			return errors.Join(err, current())
		}
		if desktopNodeProcessExited(launch) {
			// A failed-before-prepare command may have no receipt. Exact child
			// join and the unchanged predecessor read are still mandatory.
			return errors.Join(a.retireDesktopOwnedNode(ctx, launch), current())
		}
		select {
		case <-ctx.Done():
			return errors.New("native Router close is still pending; exact protection and workspace retained")
		case <-ticker.C:
		}
	}
}

func (a *app) releaseDesktopOwnedNodeProtection() (bool, error) {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := slot.release(ctx); err != nil {
		return true, err
	}
	if slot.provedEmpty() {
		// After a proved on-connect release a later legacy session must retain
		// its own cleanup dispatch; an empty old slot cannot swallow it.
		a.mu.Lock()
		if a.nodeProtection == slot {
			a.nodeProtection = nil
		}
		a.mu.Unlock()
	}
	return true, nil
}

func desktopOwnedNodeDescriptor(launch *desktopNodeLaunch, packageRoot string, environment []string) (*exec.Cmd, error) {
	args, err := desktopOwnedNodeArguments(launch)
	if err != nil || packageRoot == "" {
		return nil, errors.Join(err, errors.New("native Router descriptor has no captured package"))
	}
	// The Image is independently captured by startDesktopOwnedNodeProcess.
	// This path is never invoked via exec.Cmd.Start or shell lookup.
	command := exec.Command(filepath.Join(packageRoot, "runtime", "native", nativeBinaryName()), args...)
	command.Dir, command.Env = launch.directory, append([]string(nil), environment...)
	return command, nil
}

func desktopOwnedNodeProtectionPolicy(profile common.RouterProfile) string {
	policy := strings.ToLower(strings.TrimSpace(profile.KillSwitchPolicy))
	if policy == "" {
		policy = "off"
		if profile.KillSwitch {
			policy = "on-connect"
		}
	}
	return policy
}

func desktopOwnedNodeModeEligible(profile common.RouterProfile, mode string) bool {
	policy := desktopOwnedNodeProtectionPolicy(profile)
	return (profile.NodeKind == "" || profile.NodeKind == "router-vpn") && profile.External == nil &&
		(mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong") &&
		(profile.StartLayer == "" || profile.StartLayer == "off") && (policy == "on-connect" || policy == "always")
}

func (a *app) guardDesktopOwnedNodeTemporary(request speedLabRequest, snapshot speedLabTemporarySnapshot) error {
	if !a.retainedDesktopNodeProtection() {
		return nil
	}
	if snapshot.Plan.native == nil || snapshot.Plan.native.ownedNode == nil {
		return errors.New("temporary testing must first resolve the retained native protection owner")
	}
	if strings.EqualFold(strings.TrimSpace(request.Topology), "system-direct") {
		if snapshot.Plan.native.ownedNode.policy.Metadata().KillSwitchPolicy != "on-connect" {
			return errors.New("the captured Always policy cannot become a system-direct temporary path")
		}
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(request.Topology)) {
	case "", "router", "direct":
	default:
		return errors.New("this temporary topology cannot yet inherit the captured native protection")
	}
	profile, err := a.previewSpeedLabTemporaryProfile(request.NodeID, request)
	if err != nil {
		return err
	}
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if logical, exists := a.logicalModeByID(mode); exists {
		candidates := a.candidatesForLogical(logical, request.Base)
		if len(candidates) == 0 {
			return errors.New("temporary Router mode has no captured native successor")
		}
		for _, candidate := range candidates {
			if !desktopOwnedNodeModeEligible(profile, candidate.RuntimeID) {
				return errors.New("temporary Router strategy includes a graph without native protection succession")
			}
		}
		return nil
	}
	if !desktopOwnedNodeModeEligible(profile, mode) {
		return errors.New("temporary Router mode has no captured native protection successor")
	}
	return nil
}

func (a *app) captureDesktopOwnedNodeRestore(launch *desktopNodeLaunch, profile common.RouterProfile) (*desktopNodeLaunch, error) {
	if launch == nil || launch.ownedNode == nil || desktopOwnedNodeProfileToken(profile) != launch.ownedNode.profileToken {
		return nil, errors.New("native Router restore changed its captured profile")
	}
	owned := launch.ownedNode
	if _, err := a.readDesktopOwnedNodeReady(launch, false); err != nil {
		return nil, err
	}
	mtu, err := captureDesktopNodeRestoreMTU(launch)
	if err != nil {
		return nil, err
	}
	config, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
	if err != nil {
		return nil, err
	}
	exact := string(config) == owned.policy.Config()
	clear(config)
	if !exact {
		return nil, errors.New("native Router restore lost its original compiled configuration")
	}
	source, err := readDesktopRuntimeFile(launch, "node-source.json", mobilemultihop.NodeLaunchInputLimit)
	if err != nil {
		return nil, err
	}
	defer clear(source)
	if string(source) != string(owned.source) {
		return nil, errors.New("native Router restore lost its retained private constructor input")
	}
	original, err := mobilemultihop.ParseNodeLaunchInput(string(source))
	prior := owned.policy.OriginalProfile()
	if err != nil || prior == nil || original.SourceSHA256() != prior.SourceSHA256() || original.Config() != prior.Config() || original.Metadata() != prior.Metadata() {
		return nil, errors.New("native Router restore could not reconstruct its exact original graph")
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = owned.options[0], owned.options[1], owned.options[2]
	restored, err := newDesktopOwnedNodeLaunch(profile, original, launch.mode, launch.root, launch.endpoint, owned.network, session, mtu)
	if err != nil {
		return nil, err
	}
	if !a.desktopOwnedNodeCurrent(launch, true) {
		clear(restored.config)
		clear(restored.metadata)
		clear(restored.ownedNode.source)
		return nil, errors.New("native Router restore capture was replaced before adoption")
	}
	// No predecessor is copied here. stageDesktopOwnedNodeInputs consumes the
	// latest independently joined trial target when this new process starts.
	return restored, nil
}
