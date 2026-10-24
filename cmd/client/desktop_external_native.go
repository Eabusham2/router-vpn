package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
)

// One desktop process owns the same compiled graph and native proof lifecycle
// as PacketTunnel/VpnService. The controller never implements comparison with
// host-default HTTP requests or treats the start of a helper as Connected.
type desktopExternalRuntime struct {
	mu                                     sync.Mutex
	source, capture                        []byte
	predecessor                            string
	session, network, selection, execution string
	expected                               mobilemultihop.ExternalProofResult
	profile, entry                         common.RouterProfile
	direct                                 bool
	started                                time.Time
	checkedAt                              int64
	stopAcknowledged                       bool
	waitOnce                               sync.Once
	waitDone                               chan struct{}
	waitErr                                error
	progress                               *comparisonOwner
}

type desktopExternalProof struct {
	mobilemultihop.ExternalProofResult
	Healthy     bool            `json:"healthy"`
	HeartbeatAt int64           `json:"heartbeat_at"`
	Progress    json.RawMessage `json:"progress,omitempty"`
}

type desktopExternalStop struct {
	Schema       int    `json:"schema"`
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	Closed       bool   `json:"closed,omitempty"`
}

type desktopExternalProgressRecord struct {
	Schema       int                     `json:"schema"`
	SessionID    string                  `json:"session_id"`
	SourceSHA256 string                  `json:"source_sha256"`
	ConfigSHA256 string                  `json:"config_sha256"`
	Stage        string                  `json:"stage"`
	Progress     mobilemultihop.Progress `json:"progress"`
}

// Exactly one goroutine reaps the wrapper. Startup, heartbeat monitoring and
// Disconnect observe this same channel; none may race a second Cmd.Wait.
func desktopExternalProcessDone(launch *desktopNodeLaunch) <-chan struct{} {
	if launch == nil || launch.external == nil || launch.command == nil || launch.command.Process == nil {
		return nil
	}
	owner := launch.external
	owner.waitOnce.Do(func() {
		owner.waitDone = make(chan struct{})
		go func() {
			err := launch.command.Wait()
			owner.mu.Lock()
			owner.waitErr = err
			owner.mu.Unlock()
			close(owner.waitDone)
		}()
	})
	return owner.waitDone
}

func desktopExternalProcessExited(launch *desktopNodeLaunch) bool {
	select {
	case <-desktopExternalProcessDone(launch):
		return true
	default:
		return false
	}
}

func desktopConnectionProcessDone(a *app, command *exec.Cmd) <-chan struct{} {
	if raw, ok := desktopNodeOwners.Load(a); ok {
		if launch, ok := raw.(*desktopNodeLaunch); ok && launch.command == command && launch.external != nil {
			return desktopExternalProcessDone(launch)
		}
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	return done
}

func desktopExternalNativeProtocol(protocol string) bool {
	switch protocol {
	case "wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect":
		return true
	}
	return false
}

func externalExecutionChoice(profile common.RouterProfile, requested string, direct bool) (string, error) {
	choice := requested
	if choice == "" {
		choice = profile.MultihopExecution
	}
	execution, err := routeExecution(multihopConnectRequest{Execution: choice})
	if err != nil {
		return "", err
	}
	if direct {
		if requested != "" && requested != "local" {
			return "", errors.New("Server/Compare requires a captured Router entry")
		}
		return "local", nil
	}
	return string(execution), nil
}

func compileDesktopExternalGraph(graph map[string]any, profile, entry common.RouterProfile, exit standardExit, direct bool, restored string) (*desktopNodeLaunch, error) {
	return compileDesktopExternalGraphWithPredecessor(graph, profile, entry, exit, direct, restored, "")
}

func compileDesktopExternalGraphWithPredecessor(graph map[string]any, profile, entry common.RouterProfile, exit standardExit, direct bool, restored, predecessor string) (*desktopNodeLaunch, error) {
	profile = cloneRouterProfile(profile)
	entry = cloneRouterProfile(entry)
	if profile.NodeKind != "external" || profile.External == nil || profile.ID != exit.ID || !desktopExternalNativeProtocol(exit.Protocol) {
		return nil, errors.New("desktop external capture requires its exact private native node")
	}
	if profile.MultihopExecution == "" {
		profile.MultihopExecution = "local"
	}
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = !direct, "", ""
	if !direct {
		profile.MultihopEntryID, profile.MultihopExitID = entry.ID, profile.ID
	}
	// One native TUN is the sole OS and DNS owner. The old loopback public-IP
	// probe listener is not part of this runtime: Box proves its own routes.
	var tun map[string]any
	ins, ok := graph["inbounds"].([]any)
	if !ok {
		return nil, errors.New("external source has no captured native TUN")
	}
	for _, raw := range ins {
		in, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("external source inbound is invalid")
		}
		if in["type"] == "tun" {
			if tun != nil {
				return nil, errors.New("external source has competing native TUN owners")
			}
			tun = in
		} else if in["tag"] != "standard-exit-proof" || in["type"] != "mixed" || in["listen"] != "127.0.0.1" {
			return nil, errors.New("external source contains an unowned listener")
		}
	}
	if tun == nil {
		return nil, errors.New("external source has no captured native TUN")
	}
	tun["mtu"] = 1280 // cached MTU is historical; the compiler applies captured Fixed policy.
	if runtime.GOOS == "darwin" {
		delete(tun, "interface_name")
	} else {
		tun["interface_name"] = "router-vpn"
	}
	graph["inbounds"] = []any{tun}
	rawProfile, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	var capturedProfile map[string]any
	if json.Unmarshal(rawProfile, &capturedProfile) != nil {
		return nil, errors.New("external profile capture is invalid")
	}
	capturedProfile["multihop_exit_mode"] = exit.Protocol
	capture := map[string]any{"schema": 1, "exit_id": exit.ID, "protocol": exit.Protocol, "expected_public_ip": exit.ExpectedPublicIP, "profile": capturedProfile}
	if !direct {
		capture["entry"], capture["entry_tag"] = entry, "entry-wg"
		if entry.NodeKind == "external" || predecessor != "" {
			capture["entry_tag"] = "external-entry"
		}
		if predecessor != "" {
			capture["predecessor_config"] = predecessor
		}
	} else if predecessor != "" {
		return nil, errors.New("direct external source cannot acquire an unrelated predecessor")
	}
	source, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	rawCapture, err := json.Marshal(capture)
	if err != nil {
		return nil, err
	}
	prepared, err := mobilemultihop.PrepareExternalExecutionCapture(string(source), string(rawCapture), restored)
	if err != nil {
		return nil, err
	}
	compiled, err := mobilemultihop.NewExternalPolicy(string(source), prepared)
	if err != nil {
		return nil, err
	}
	var expected mobilemultihop.ExternalProofResult
	if json.Unmarshal([]byte(compiled.Metadata()), &expected) != nil {
		return nil, errors.New("external native compiler returned invalid identity metadata")
	}
	expected.IP = exit.ExpectedPublicIP
	expected.DNSProven, expected.EntryProven = true, !direct
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	expected.SessionID = session
	policyID := profile.ID
	physicalID, endpoint := profile.ID, exit.Server
	if !direct {
		physicalID, endpoint = entry.ID, entry.Endpoint
	}
	selection := profile.MultihopExecution
	if restored != "" {
		selection = restored // Restoring an already proved winner never reruns Compare.
	}
	progress := &comparisonOwner{value: routeComparisonProgress{ID: session, Stage: "starting", Measurements: []routechoice.Measurement{}}}
	return &desktopNodeLaunch{profileID: physicalID, policyProfileID: policyID, endpoint: endpoint, mode: "external-" + exit.Protocol, config: []byte(compiled.Config()), metadata: []byte(compiled.Metadata()), external: &desktopExternalRuntime{source: source, capture: []byte(prepared), predecessor: predecessor, session: session, selection: selection, expected: expected, profile: profile, entry: entry, direct: direct, progress: progress}}, nil
}

func prepareDesktopExternalLaunch(a *app, profile, entry common.RouterProfile, exit standardExit, direct bool, restored string) (*desktopNodeLaunch, error) {
	binary, err := verifyBundledNative(desktopAmneziaPackageRoot())
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(clientRoot(a))
	if err != nil {
		return nil, err
	}
	network := physicalNetworkIdentity()
	if network == "" {
		return nil, errors.New("external connection cannot capture the physical network")
	}
	var files, start map[string][]byte
	if !direct && entry.NodeKind != "external" {
		mode, err := desktopExternalEntryMode(profile, entry, "", "")
		if err != nil {
			return nil, err
		}
		profile.MultihopEntryMode = mode
		files, err = readDesktopNodeAssets(root, entry.ID, mode)
		if err != nil {
			return nil, err
		}
		defer func() {
			for _, data := range files {
				clear(data)
			}
		}()
		if entry.StartLayer != "" && entry.StartLayer != "off" && !mobilemultihop.MAXMode(mode) && mode != "shadowsocks" {
			start, err = readDesktopNodeAssets(root, entry.ID, "shadowsocks")
			if err != nil {
				return nil, err
			}
			defer func() {
				for _, data := range start {
					clear(data)
				}
			}()
		}
	}
	ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), 10*time.Second)
	launch, err := compileDesktopExternalCaptured(ctx, profile, entry, exit, direct, restored, files, start, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
	cancel()
	if err != nil {
		return nil, err
	}
	launch.root, launch.external.network = root, network
	if err = a.checkConnectionOperation(); err != nil {
		return nil, err
	}
	if network != physicalNetworkIdentity() {
		return nil, errors.New("external network changed during native preparation")
	}
	if err = preflightDesktopExternalLaunch(a.connectionOperationContextOrBackground(), binary, launch, runDesktopExternalPreflightCommand); err != nil {
		return nil, err
	}
	if err = a.checkConnectionOperation(); err != nil {
		return nil, err
	}
	if network != physicalNetworkIdentity() {
		return nil, errors.New("external network changed during native preflight")
	}
	return launch, nil
}

func validateDesktopExternalProof(raw []byte, owner *desktopExternalRuntime, now time.Time) (desktopExternalProof, error) {
	var proof desktopExternalProof
	bad := errors.New("native external proof is stale or differs from the captured session, DNS or node path")
	if owner == nil || len(raw) == 0 || len(raw) > 256<<10 || decodeRelayControlJSON(raw, &proof) != nil {
		return proof, bad
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	expected := owner.expected
	if proof.Schema != 1 || !proof.Healthy || !proof.DNSProven || proof.EntryProven != expected.EntryProven || proof.SessionID != expected.SessionID || proof.SourceSHA256 != expected.SourceSHA256 || proof.ConfigSHA256 != expected.ConfigSHA256 || proof.ExitID != expected.ExitID || proof.EntryID != expected.EntryID || proof.EntryNodeID != expected.EntryNodeID || proof.IP != expected.IP || proof.CheckedAt <= 0 || proof.CheckedAt < owner.started.Add(-time.Second).UnixMilli() || proof.CheckedAt > now.Add(time.Second).UnixMilli() || proof.HeartbeatAt < now.Add(-3*time.Second).UnixMilli() || proof.HeartbeatAt > now.Add(time.Second).UnixMilli() || proof.HeartbeatAt < proof.CheckedAt {
		return proof, bad
	}
	if owner.selection == "auto" {
		if proof.Execution != "local" && proof.Execution != "server" {
			return proof, bad
		}
	} else if proof.Execution != owner.selection && !(owner.selection == "local" && proof.Execution == "") {
		return proof, bad
	}
	if proof.Execution == "" {
		proof.Execution = "local"
	}
	if owner.execution != "" && owner.execution != proof.Execution || owner.checkedAt != 0 && owner.checkedAt != proof.CheckedAt {
		return proof, bad
	}
	return proof, nil
}

func (a *app) readDesktopExternalProof(launch *desktopNodeLaunch) (desktopExternalProof, error) {
	if launch == nil || launch.external == nil || launch.command == nil || launch.command.Process == nil || !a.ownsConnectionRuntime(launch.command) {
		return desktopExternalProof{}, errors.New("external native process is no longer owned")
	}
	owner := launch.external
	if desktopExternalProcessExited(launch) {
		return desktopExternalProof{}, errors.New("native external process exited before the captured proof could be retained")
	}
	if owner.network == "" || owner.network != physicalNetworkIdentity() {
		return desktopExternalProof{}, errors.New("external proof belongs to a retired physical network")
	}
	raw, err := readDesktopRuntimeFile(launch, "proof.json", 256<<10)
	if err != nil {
		return desktopExternalProof{}, err
	}
	proof, err := validateDesktopExternalProof(raw, owner, time.Now())
	if err == nil && (!a.ownsConnectionRuntime(launch.command) || desktopExternalProcessExited(launch) || owner.network != physicalNetworkIdentity()) {
		err = errors.New("native external process or physical network changed during proof adoption")
	}
	return proof, err
}

func readDesktopExternalStopped(launch *desktopNodeLaunch) (bool, error) {
	raw, err := readDesktopRuntimeFile(launch, "stopped.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var closed desktopExternalStop
	owner := launch.external
	if decodeRelayControlJSON(raw, &closed) != nil || !closed.Closed || closed.Schema != 1 || closed.SessionID != owner.session || closed.SourceSHA256 != owner.expected.SourceSHA256 {
		return false, errors.New("native external teardown acknowledgement has another owner")
	}
	owner.mu.Lock()
	owner.stopAcknowledged = true
	owner.mu.Unlock()
	return true, nil
}

func (a *app) readDesktopExternalProgress(launch *desktopNodeLaunch) error {
	raw, err := readDesktopRuntimeFile(launch, "progress.json", 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	owner := launch.external
	var record desktopExternalProgressRecord
	if decodeRelayControlJSON(raw, &record) != nil || record.Schema != 1 || record.SessionID != owner.session || record.SourceSHA256 != owner.expected.SourceSHA256 || record.ConfigSHA256 != owner.expected.ConfigSHA256 || len(record.Progress.Measurements) > 8 {
		return errors.New("external progress does not belong to the captured graph")
	}
	switch record.Stage {
	case "starting", "proving", "connected", "stopping", "cleanup-pending", "closed":
	default:
		return errors.New("external progress has an invalid lifecycle stage")
	}
	stage := record.Stage
	if stage == "proving" {
		switch record.Progress.Stage {
		case "prepared", "starting", "probing", "stopping", "measured", "activating", "activation-failed", "selected", "failed":
			stage += ":" + record.Progress.Stage
		}
	}
	if len(record.Progress.Measurements) != 0 && (record.Progress.LastNodeMeasurement != "https-response-time" || record.Progress.ExternalMeasurement != "https-response-time") {
		return errors.New("external comparison progress has incorrect measurement labels")
	}
	// Error details and native keys never enter the public status. Only a
	// captured candidate's checked numeric response measurements are displayed.
	for i := range record.Progress.Measurements {
		measurement := &record.Progress.Measurements[i]
		if !measurement.Candidate.Valid() || measurement.Candidate.EntryID != owner.expected.EntryID || measurement.Candidate.ExitID != owner.expected.ExitID || measurement.Candidate.Transport != owner.profile.External.Protocol || measurement.Eligible && (measurement.ScoreMS == nil || measurement.LastNodeMS <= 0 || measurement.ExternalMS <= 0 || *measurement.ScoreMS != measurement.LastNodeMS/2+measurement.ExternalMS/2) || !measurement.Eligible && measurement.ScoreMS != nil {
			return errors.New("external progress has an invalid captured path measurement")
		}
		if measurement.Failure != "" {
			measurement.Failure = "candidate did not pass its routed proof"
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cmd != launch.command {
		return errors.New("external progress belongs to a retired connection")
	}
	if !a.state.Connected {
		a.state.Phase = "external-node:" + stage
	}
	if owner.progress != nil {
		owner.progress.mu.Lock()
		owner.progress.value.Stage = stage
		owner.progress.value.Complete = record.Progress.Complete || record.Stage == "closed"
		owner.progress.value.Measurements = append([]routechoice.Measurement{}, record.Progress.Measurements...)
		owner.progress.value.LastNodeMeasurement = record.Progress.LastNodeMeasurement
		owner.progress.value.ExternalMeasurement = record.Progress.ExternalMeasurement
		if record.Progress.Failure != "" {
			owner.progress.value.Failure = "captured external execution failed"
		}
		owner.progress.mu.Unlock()
		desktopComparisons.Store(a, owner.progress)
	}
	return nil
}

func (a *app) waitDesktopExternalProof(ctx context.Context, launch *desktopNodeLaunch) (result desktopExternalProof, failure error) {
	if launch == nil || launch.external == nil {
		return result, errors.New("external proof has no captured native owner")
	}
	defer func() {
		if failure != nil && launch.external.progress != nil {
			progress := launch.external.progress
			progress.mu.Lock()
			progress.value.Stage, progress.value.Complete, progress.value.Failure = "failed", true, "captured external execution did not complete"
			progress.mu.Unlock()
		}
	}()
	deadline, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if deadline.Err() != nil {
			return desktopExternalProof{}, deadline.Err()
		}
		if err := a.checkConnectionOperation(); err != nil {
			return desktopExternalProof{}, err
		}
		closed, err := readDesktopExternalStopped(launch)
		if err != nil {
			return desktopExternalProof{}, err
		}
		if closed {
			return desktopExternalProof{}, errors.New("native external startup failed and its captured resources were closed")
		}
		if err := a.readDesktopExternalProgress(launch); err != nil {
			return desktopExternalProof{}, err
		}
		proof, err := a.readDesktopExternalProof(launch)
		if err == nil {
			launch.external.mu.Lock()
			launch.external.execution = proof.Execution
			launch.external.checkedAt = proof.CheckedAt
			launch.external.mu.Unlock()
			if progress := launch.external.progress; progress != nil {
				progress.mu.Lock()
				progress.value.Stage, progress.value.Complete, progress.value.Execution, progress.value.Failure = "selected", true, proof.Execution, ""
				progress.mu.Unlock()
			}
			return proof, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return desktopExternalProof{}, err
		}
		select {
		case <-deadline.Done():
			return desktopExternalProof{}, deadline.Err()
		case <-ticker.C:
		case <-desktopExternalProcessDone(launch):
			return desktopExternalProof{}, errors.New("native external startup exited before a valid path proof")
		}
	}
}

// Request native lease-first close before signalling the platform wrapper. A
// Windows force-stop cannot certify server cleanup; only the exact native
// acknowledgement permits the enclosing disconnect transaction to continue.
func prepareDesktopExternalStop(a *app, command *exec.Cmd) error {
	raw, exists := desktopNodeOwners.Load(a)
	if !exists {
		return nil
	}
	launch, ok := raw.(*desktopNodeLaunch)
	if !ok || launch == nil || launch.external == nil {
		return nil
	}
	if command != nil && command != launch.command {
		return errors.New("external teardown belongs to another runtime")
	}
	current := func() error {
		if raw, ok := desktopNodeOwners.Load(a); !ok || raw != launch {
			return errors.New("external teardown owner changed before acknowledgement")
		}
		a.mu.Lock()
		owned := a.cmd == nil || a.cmd == launch.command
		a.mu.Unlock()
		if !owned {
			return errors.New("external teardown cannot change a replacement connection")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	owner := launch.external
	owner.mu.Lock()
	acknowledged := owner.stopAcknowledged
	owner.mu.Unlock()
	if acknowledged {
		// A later firewall-release retry may follow successful private cleanup.
		// It still refuses a new directory at the retired owner's pathname.
		if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	if closed, err := readDesktopExternalStopped(launch); err != nil || closed {
		return errors.Join(err, current())
	}
	request := desktopExternalStop{Schema: 1, SessionID: owner.session, SourceSHA256: owner.expected.SourceSHA256}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err = writeDesktopRuntimeFile(launch, "stop.json", encoded, true); err != nil {
		return err
	}
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := current(); err != nil {
			return err
		}
		closed, err := readDesktopExternalStopped(launch)
		if err != nil || closed {
			return errors.Join(err, current())
		}
		if desktopExternalProcessExited(launch) {
			// A dead wrapper cannot vouch for a native server lease. Preserve the
			// guard and capture; an exact close acknowledgement is still needed.
			return errors.New("native external process exited without a checked close acknowledgement; protection and private ownership retained")
		}
		select {
		case <-deadline.C:
			return errors.New("native external teardown is pending; private lease and protection ownership retained")
		case <-ticker.C:
		case <-desktopExternalProcessDone(launch):
			// Inspect the final atomically published acknowledgement once more.
		}
	}
}

func desktopExternalProfilesUnchanged(current, captured common.RouterProfile) bool {
	return reflect.DeepEqual(current, captured)
}

func desktopExternalLiteralEndpoint(profile common.RouterProfile) bool {
	address, err := netip.ParseAddr(strings.Trim(profile.Endpoint, "[]"))
	return err == nil && address.Zone() == "" && !address.Is4In6()
}

func (a *app) monitorDesktopExternalRuntime(launch *desktopNodeLaunch) {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				continue
			}
			if !a.operationMu.TryLock() {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				a.operationMu.Unlock()
				return
			}
			if _, err := a.readDesktopExternalProof(launch); err == nil {
				a.operationMu.Unlock()
				continue
			}
			err := a.stopModeWithIntent(true)
			message := "external native proof or physical network retired; protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			a.operationMu.Unlock()
			return
		}
	}()
}
