//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
)

const macOSCONNECTExecutionMarker = "fixture-connect-execution-host"

type macOSCONNECTExecutionCase struct{ Mode, Protocol, Requested, Winner, Fault string }

var macOSCONNECTExecutionCases = []string{
	"http-wg-server",
	"http-awg-fast-auto-local",
	"http-awg-strong-auto-server",
	"https-awg-strong-server",
	"https-wg-auto-local",
	"https-awg-fast-auto-server",
	"http-wrong-auth",
	"https-wrong-auth",
	"https-tls-name",
	"http-wrong-public",
	"https-wrong-final",
	"https-failed-dns",
	"http-replaced-source",
	"https-held-cleanup",
}
var macOSCONNECTExecutionScenarios = map[string]macOSCONNECTExecutionCase{
	"http-wg-server":              {"wg", "http-connect", "server", "server", ""},
	"http-awg-fast-auto-local":    {"awg2-fast", "http-connect", "auto", "local", ""},
	"http-awg-strong-auto-server": {"awg2-strong", "http-connect", "auto", "server", ""},
	"https-awg-strong-server":     {"awg2-strong", "https-connect", "server", "server", ""},
	"https-wg-auto-local":         {"wg", "https-connect", "auto", "local", ""},
	"https-awg-fast-auto-server":  {"awg2-fast", "https-connect", "auto", "server", ""},
	"http-wrong-auth":             {"wg", "http-connect", "server", "server", "wrong-auth"},
	"https-wrong-auth":            {"wg", "https-connect", "server", "server", "wrong-auth"},
	"https-tls-name":              {"wg", "https-connect", "server", "server", "tls-name"},
	"http-wrong-public":           {"wg", "http-connect", "server", "server", "wrong-public"},
	"https-wrong-final":           {"wg", "https-connect", "server", "server", "wrong-final"},
	"https-failed-dns":            {"wg", "https-connect", "server", "server", "failed-dns"},
	"http-replaced-source":        {"wg", "http-connect", "server", "server", "replaced-source"},
	"https-held-cleanup":          {"wg", "https-connect", "server", "server", "held-cleanup"},
}

func macOSCONNECTExecutionScenario(value string) (mode, protocol, requested, winner, fault string, err error) {
	x, found := macOSCONNECTExecutionScenarios[value]
	if !found {
		err = errors.New("uncaptured CONNECT execution case")
		return
	}
	return x.Mode, x.Protocol, x.Requested, x.Winner, x.Fault, nil
}

func macOSCONNECTExecutionEntryLayer(scenario string) string {
	switch scenario {
	case "http-awg-fast-auto-local", "https-awg-strong-server":
		return "aes-256-gcm"
	case "http-awg-strong-auto-server", "https-wg-auto-local":
		return "aes-256-gcm+xor-whitening"
	default:
		return "off"
	}
}

type macOSCONNECTExecutionObservation struct {
	Connected, PublicConnect, Joined, Restored bool
	Requested, Winner, Source, Transfer        string
	PID                                        int
	Ready                                      mobilemultihop.DesktopNodeChainExecutionReadyRecord
	Baseline                                   *desktopMacOSNodeChainReceipt
	Comparison                                 json.RawMessage
}

func macOSCONNECTExecutionObserve(ctx context.Context, a *app) (macOSCONNECTExecutionObservation, error) {
	var result macOSCONNECTExecutionObservation
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return result, errors.Join(err, errors.New("original execution owner absent"))
	}
	s := owner.session
	if err = s.Current(ctx); err != nil {
		return result, err
	}
	h := s.launch.chain.platform.host
	if h == nil || h.execution != s.execution || h.executionPreparation != s.execution.preparation || h.executionPhysical != nil || h.executionCONNECTPhysical != s.execution.connectPhysical || h.executionCONNECTPhysical == nil {
		return result, errors.New("execution observation replaced original Darwin host")
	}
	if err = h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err = h.readReadyLocked(ctx, false); err != nil {
		return result, err
	}
	s.execution.mu.Lock()
	if s.execution.ready == nil {
		s.execution.mu.Unlock()
		return result, errors.New("original selected proof missing")
	}
	result.Ready = *s.execution.ready
	s.execution.mu.Unlock()
	_, meta, capture, err := s.execution.readPolicy()
	if err != nil || meta.TargetOS != "darwin" || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Host != "192.168.50.133" {
		return result, errors.Join(err, errors.New("original physical/DNS source changed"))
	}
	if h.process == nil || h.process.command == nil || h.process.command.Process == nil || h.baseline == nil {
		return result, errors.New("original process/PF owner absent")
	}
	result.PID = h.process.command.Process.Pid
	result.Source = meta.SourceSHA256
	result.Transfer = h.transfer
	copy := *h.baseline
	result.Baseline = &copy
	result.Winner = result.Ready.Progress.Execution
	result.Requested = s.execution.preparation.Execution()
	result.Comparison, _ = json.Marshal(result.Ready.Progress.Comparison)
	a.mu.Lock()
	result.Connected = a.state.Connected && a.cmd == s.launch.command
	a.mu.Unlock()
	if !result.Connected || result.Transfer == "" || result.Ready.Kind != "routervpn-node-chain-connect-execution-ready-v1" || result.Ready.TransferSHA256 != result.Transfer || result.Ready.InterfaceIndex == 0 || !strings.HasPrefix(result.Ready.InterfaceName, "utun") || !result.Ready.Progress.DNSProven {
		return result, errors.New("selected native TUN/DNS proof not retained")
	}
	return result, nil
}

// The selected endpoint and both routed samples come from the actual ready
// record. Last restoration preserves the choice, not stale measurement values.
func macOSCONNECTExecutionRequireMeasurements(t *testing.T, result routechoice.Result, winner string, compare bool) {
	t.Helper()
	valid := func(m routechoice.Measurement) bool {
		positive := func(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
		return m.Candidate.Valid() && m.Eligible && m.Failure == "" && positive(m.LastNodeMS) && positive(m.ExternalMS) && m.ScoreMS != nil && positive(*m.ScoreMS) && math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2)) <= 0.000001
	}
	target := false
	for _, original := range mobilemultihop.Targets {
		target = target || result.Target == original
	}
	if !target || result.Winner == nil || string(result.Winner.Execution) != winner || result.Final == nil || result.Final.Candidate != *result.Winner || !valid(*result.Final) {
		t.Fatal("original chosen path lost its routed final measurement")
	}
	if !compare {
		if len(result.Measurements) != 0 {
			t.Fatal("retained choice reran candidate comparison")
		}
		return
	}
	if len(result.Measurements) != 2 {
		t.Fatal("original Compare omitted a candidate")
	}
	seen := map[routechoice.Execution]bool{}
	for _, m := range result.Measurements {
		if seen[m.Candidate.Execution] || !valid(m) || m.Candidate.Transport != result.Winner.Transport || m.Candidate.EntryID != result.Winner.EntryID || m.Candidate.ExitID != result.Winner.ExitID {
			t.Fatal("original Compare lost a routed candidate or score")
		}
		seen[m.Candidate.Execution] = true
	}
	if !seen[routechoice.Local] || !seen[routechoice.Server] {
		t.Fatal("original Compare replaced a candidate")
	}
}

func macOSCONNECTExecutionNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSCONNECTExecutionMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	scenario := strings.TrimSpace(string(raw))
	_, protocol, requested, _, fault, err := macOSCONNECTExecutionScenario(scenario)
	if err != nil {
		return true, err
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress, ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(macOSOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(macOSOwnedControllerRoot, "modes"), StateFile: filepath.Join(macOSOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != 3 {
		return true, errors.New("original imported trio catalog absent")
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return true, errors.New("original mode catalog absent")
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	release, err := a.holdCapturedMTU(context.Background())
	if err != nil {
		return true, err
	}
	defer release()
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	var public, restored atomic.Bool
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller lost", 409)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(a.state)
	})
	mux.HandleFunc("/api/native-connect-execution-source", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		profiles := cloneRouterProfileStore(a.profiles)
		a.mu.Unlock()
		if !found {
			http.Error(w, "original control absent", 409)
			return
		}
		selection, err := resolveDesktopNodeChainSelection(control, profiles.Profiles, control.MultihopNodes, "local")
		if err == nil {
			selection, err = captureNativeMultihopSelection(r.Context(), macOSOwnedControllerRoot, selection, []string{protocol}, nil)
		}
		if err != nil || selection.Native == nil || selection.Native.chain == nil {
			http.Error(w, fmt.Sprint(err), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"local_source": selection.Native.chain.input})
	})
	mux.HandleFunc("/api/native-ordered-request", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		tokens, err := a.connectionProfileTokensLocked(control)
		if !found || err != nil {
			http.Error(w, "source changed", 409)
			return
		}
		selected := a.profiles.SelectedID
		_ = json.NewEncoder(w).Encode(multihopConnectRequest{Nodes: append([]common.MultihopNodeSelection(nil), control.MultihopNodes...), Execution: requested, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: tokens}})
	})
	mux.HandleFunc("/api/multihop/connect", func(w http.ResponseWriter, r *http.Request) {
		public.Store(true)
		a.nativeMultihopConnect(w, r)
	})
	mux.HandleFunc("/api/multihop/status", a.nativeMultihopStatus)
	mux.HandleFunc("/api/disconnect", a.disconnect)
	mux.HandleFunc("/api/native-connect-execution-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := macOSCONNECTExecutionObserve(r.Context(), a)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		value.PublicConnect = public.Load()
		value.Restored = restored.Load()
		_ = json.NewEncoder(w).Encode(value)
	})
	// The trigger is test-only. Capture, retained Stop, successor launch and
	// restoration use the real Speed Lab coordinator and its original intent.
	mux.HandleFunc("/api/native-connect-execution-restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "" {
			http.Error(w, "uncaptured restore", 409)
			return
		}
		_, snapshot, finish, err := a.beginSpeedLabTemporaryOperationExpectedContext(r.Context(), nil)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		defer finish()
		if err = a.speedLabSuspendPrevious(snapshot, false); err == nil {
			err = a.speedLabRestoreTemporary(snapshot)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		restored.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]bool{"restored": true})
	})
	mux.HandleFunc("/api/native-connect-execution-cleanup-retry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "held-cleanup" {
			http.Error(w, "uncaptured cleanup retry", 409)
			return
		}
		owner, err := a.desktopOrderedExecutionOwner()
		if err != nil || owner == nil || owner.session.Current(r.Context()) != nil {
			http.Error(w, "original live owner absent", 409)
			return
		}
		original := owner.session.launch.chain.platform.host
		if original == nil || original.executionCONNECTPhysical != owner.session.execution.connectPhysical || original.enter(r.Context()) != nil {
			http.Error(w, "original native gate absent", 409)
			return
		}
		released := false
		releaseGate := func() {
			if !released {
				original.gate <- struct{}{}
				released = true
			}
		}
		defer releaseGate()
		// Hold the actual original host gate, not a replacement cleanup method.
		// The bounded public request must refuse without forgetting this live child.
		call, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		request := httptest.NewRequest(http.MethodPost, "/api/disconnect", strings.NewReader("{}")).WithContext(call)
		result := httptest.NewRecorder()
		a.disconnect(result, request)
		cancel()
		releaseGate()
		if result.Code == http.StatusOK || !strings.Contains(result.Body.String(), context.DeadlineExceeded.Error()) {
			http.Error(w, "held original native cleanup was not bounded", 500)
			return
		}
		retained, err := a.desktopOrderedExecutionOwner()
		if err != nil || retained != owner || retained.session.launch.chain.platform.host != original || retained.session.Current(r.Context()) != nil {
			http.Error(w, "failed cleanup replaced original native owner", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"refused": true, "same_owner": true, "joined": false})
	})
	mux.HandleFunc("/api/native-connect-execution-replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "replaced-source" {
			http.Error(w, "uncaptured replacement", 409)
			return
		}
		a.mu.Lock()
		if a.profiles.Profiles[1].External.HTTPConnect != nil {
			a.profiles.Profiles[1].External.HTTPConnect.Password += "changed"
		} else {
			a.profiles.Profiles[1].External.HTTPSConnect.Password += "changed"
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"changed": true})
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSCONNECTExecutionPeer struct {
	*macOSImportedExecutionPeer
	protocol, fault string
}

func startMacOSCONNECTExecutionPeer(t *testing.T, p *macOSCONNECTExecutionPeer, mode, protocol, fault string) {
	t.Helper()
	p.peer = macOSNodeChainPeerForModes(t, []string{mode, protocol})
	peer := p.peer
	peer.physical = macOSExternalNativeAddress(t)
	image := os.Getenv("ROUTERVPN_MACOS_NODE_CHAIN_PEER")
	raw, err := os.ReadFile(image)
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(image) || hex.EncodeToString(sum[:]) != os.Getenv("ROUTERVPN_MACOS_NODE_CHAIN_PEER_SHA256") {
		t.Fatal("original peer image changed")
	}
	worker := filepath.Join(os.Getenv("ROUTERVPN_MACOS_EXTERNAL_BUNDLE"), "sing-box-routervpn")
	workerRaw, err := os.ReadFile(worker)
	workerHash := sha256.Sum256(workerRaw)
	if err != nil {
		t.Fatal("shipping portable worker missing", err)
	}
	peer.command = exec.Command(image, "-test.run=^TestRouterVPNDesktopCONNECTExecutionReferenceProcess$", "-test.count=1", "-test.timeout=240s")
	peer.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_CONNECT_EXECUTION_REFERENCE=1", "ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1", "ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=" + peer.physical.String()}
	peer.command.Stderr = os.Stderr
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		inputRead.Close()
		inputWrite.Close()
		t.Fatal(err)
	}
	peer.input, peer.output = inputWrite, outputRead
	peer.reader = bufio.NewReaderSize(outputRead, 32768)
	peer.command.Stdin, peer.command.Stdout = inputRead, outputWrite
	if err = peer.command.Start(); err != nil {
		inputRead.Close()
		inputWrite.Close()
		outputRead.Close()
		outputWrite.Close()
		t.Fatal(err)
	}
	p.started = true
	inputRead.Close()
	outputWrite.Close()
	go func() { peer.failure = peer.command.Wait(); close(peer.done) }()
	paired := map[string]any{"schema": 1, "address": peer.physical.String(), "client_address": peer.physical.String(), "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": macOSNodeChainProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token", "benchmark_port": 45998}
	wire := map[string]any{"schema": 1, "peer": map[string]any{"schema": 1, "paired": paired, "middle_method": peer.middleMethod, "middle_password": peer.middlePassword}, "image": worker, "image_sha256": hex.EncodeToString(workerHash[:])}
	wire["protocol"], wire["username"], wire["password"], wire["fault"] = protocol, "captured-native-user", peer.middlePassword, fault
	wire["layers"] = map[string]string{"entry": p.layers.Entry, "final": "off", "entry_password": p.entryPassword}
	reply := p.exchange(t, wire)
	if json.Unmarshal(reply["peer"], &peer.reply) != nil || json.Unmarshal(reply["middle_address"], &p.middle) != nil || p.middle == "" || peer.reply.PublicCA == "" {
		t.Fatal("original imported peer identity missing")
	}
	if json.Unmarshal(reply["layers"], &p.layerObservation) != nil {
		t.Fatal("original entry layer capture missing")
	}
	macOSNodeChainCONNECTReadback(t, peer, peer.reply)
}

func TestMacOSCONNECTTrioExecutionNative(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("typed CONNECT native execution requires explicit real disposable controller")
	}
	for _, scenario := range macOSCONNECTExecutionCases {
		t.Run(scenario, func(t *testing.T) { macOSCONNECTExecutionNativeCase(t, scenario) })
	}
}

// macOSCONNECTExecutionJoinPartialController retains the original supervisor
// result for the base fixture cleanup. It also checks the original peer joins
// and released process locks; launch intent alone never retires aliases.
func macOSCONNECTExecutionJoinPartialController(ctx context.Context, fixture *macOSControllerNativeFixture) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := os.Lstat(macOSOwnedControllerRoot)
	if err != nil || !os.SameFile(fixture.root, current) {
		return errors.New("original partial controller root changed")
	}
	if fixture.supervisor != nil && fixture.supervisor.Process == nil {
		// Start failed before creating a process; avoid passing an unstarted
		// command to the base fixture's original-process cleanup.
		fixture.supervisor = nil
	}
	if fixture.supervisor != nil {
		if fixture.joined == nil {
			return errors.New("original supervisor has no join owner")
		}
		if err := os.WriteFile(macOSControllerFixtureEventPath(macOSOwnedControllerRoot, "fixture-release"), []byte("joined\n"), 0600); err != nil {
			return err
		}
		if err := fixture.supervisor.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case outcome := <-fixture.joined:
			fixture.joined <- outcome // the base fixture still owns final retirement
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, peer := range fixture.peers {
		select {
		case <-peer.joined:
			if peer.err != nil {
				return fmt.Errorf("original partial desktop peer join: %w", peer.err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var locks []*os.File
	defer func() {
		for _, lock := range locks {
			_ = lock.Close()
		}
	}()
	for _, path := range []string{macOSOwnedInstallLock, macOSOwnedProcessLock, macOSOwnedSupervisorLock} {
		if err := ctx.Err(); err != nil {
			return err
		}
		lock, err := ownedDesktopLock(path, true)
		if err != nil {
			return fmt.Errorf("original partial controller still owns %s: %w", path, err)
		}
		locks = append(locks, lock)
	}
	return ctx.Err()
}

func macOSCONNECTExecutionNativeCase(t *testing.T, scenario string) {
	mode, protocol, requested, winner, fault, err := macOSCONNECTExecutionScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	aliases, err := macOSImportedExecutionOwnAliases(context.Background())
	var peer *macOSCONNECTExecutionPeer
	controllerJoined := true
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := aliases.Close(ctx, func(ctx context.Context) error {
			if !controllerJoined {
				return errors.New("original controller not joined")
			}
			if peer != nil {
				return peer.close(ctx)
			}
			return nil
		}); err != nil {
			t.Error("original private alias retirement", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	peer = &macOSCONNECTExecutionPeer{macOSImportedExecutionPeer: &macOSImportedExecutionPeer{}, protocol: protocol, fault: fault}
	peer.layers = &macOSImportedExecutionLayerCase{Name: scenario, Mode: mode, Entry: macOSCONNECTExecutionEntryLayer(scenario), Final: "off", Requested: requested, Winner: winner}
	if peer.layers.Entry != "off" {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		peer.entryPassword = base64.StdEncoding.EncodeToString(key[:])
		clear(key[:])
	}
	startMacOSCONNECTExecutionPeer(t, peer, mode, protocol, fault)
	macOSExternalNativeTrust(t, &macOSExternalNativePeer{ca: peer.peer.reply.PublicCA})
	if protocol == "https-connect" {
		macOSExternalNativeTrust(t, &macOSExternalNativePeer{ca: peer.peer.reply.CONNECTCA})
	}
	sourceFault := ""
	if fault == "tls-name" {
		sourceFault = fault
	}
	store := installMacOSNodeChainProfiles(t, peer.peer, sourceFault)
	macOSImportedExecutionInstallLayers(t, peer.macOSImportedExecutionPeer, &store)
	host, port, err := net.SplitHostPort(peer.middle)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || host != peer.peer.physical.String() {
		t.Fatal("captured imported literal changed")
	}
	store.Profiles[1].Endpoint = host
	proxy := store.Profiles[1].External.HTTPConnect
	if protocol == "https-connect" {
		proxy = store.Profiles[1].External.HTTPSConnect
	}
	if proxy == nil {
		t.Fatal("original CONNECT profile absent")
	}
	proxy.Host, proxy.Port = host, n
	control := &store.Profiles[2]
	control.MultihopExecution = requested
	raw, _ := json.Marshal(store)
	if os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), raw, 0600) != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, macOSCONNECTExecutionMarker), []byte(scenario+"\n"), 0600) != nil {
		t.Fatal("original private source staging failed")
	}
	// Capture launch intent before any fallible supervisor/IPC operation. A
	// partial start never grants alias retirement without its original join.
	controllerJoined = false
	t.Cleanup(func() {
		if controllerJoined {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		if err := macOSCONNECTExecutionJoinPartialController(cleanup, fixture); err != nil {
			t.Error("original partial controller cleanup", err)
			return
		}
		controllerJoined = true
	})
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err = connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	controllerJoined = false
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 150 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	t.Cleanup(func() {
		if controllerJoined {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		_, _, _ = macOSExternalNativeHTTP(cleanup, client, http.MethodPost, "/api/disconnect", "{}")
		if err := connection.CloseWrite(); err != nil {
			t.Error(err)
			return
		}
		receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
		if receipt.ExitCode != 0 {
			t.Error("original imported controller failed cleanup", receipt.ExitCode)
			return
		}
		controllerJoined = true
	})
	macOSControllerNativeAwait(t, func() bool {
		call, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		status, _, err := macOSExternalNativeHTTP(call, client, http.MethodGet, "/api/status", "")
		return err == nil && status == 200
	}, "original imported controller did not start")
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-connect-execution-source", "")
	var source map[string]string
	if err != nil || status != 200 || json.Unmarshal(raw, &source) != nil || source["local_source"] == "" {
		t.Fatal("original complete source capture failed", status, err, string(raw))
	}
	configured := peer.exchange(t, map[string]string{"local_source": source["local_source"], "winner": winner})
	if string(configured["ready"]) != "true" {
		t.Fatal("registered original suffix unavailable")
	}
	commands := map[string]string{"wrong-public": "wrong-middle-public", "failed-dns": "fail-dns"}
	if command := commands[fault]; command != "" {
		peer.exchange(t, map[string]string{"command": command})
	}
	status, request, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-ordered-request", "")
	if err != nil || status != 200 {
		t.Fatal("original execution request unavailable")
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/connect", string(request))
	negative := commands[fault] != "" || fault == "wrong-auth" || fault == "tls-name" || fault == "wrong-final"
	if err != nil || negative && status == 200 || !negative && status != 200 {
		t.Fatal("actual Darwin public execution verdict", status, err, string(raw))
	}
	if fault == "tls-name" {
		peer.exchange(t, map[string]string{"command": "tls-refused"})
	}
	read := func() macOSCONNECTExecutionObservation {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-connect-execution-observation", "")
		var value macOSCONNECTExecutionObservation
		if err != nil || status != 200 || json.Unmarshal(raw, &value) != nil {
			t.Fatal("original execution observation missing", status, err, string(raw))
		}
		return value
	}
	var restoreLaunches uint64
	var comparisonTrials int
	if !negative {
		before := read()
		macOSCONNECTExecutionRequireMeasurements(t, before.Ready.Progress.Comparison, winner, requested == "auto")
		comparisonTrials = len(before.Ready.Progress.Comparison.Measurements)
		if !before.Connected || !before.PublicConnect || before.Requested != requested || before.Winner != winner || before.PID == 0 {
			t.Fatal("public execution replaced original chosen graph")
		}
		if fault == "replaced-source" {
			status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-connect-execution-replace", "{}")
			if err != nil || status != 200 {
				t.Fatal(err)
			}
			status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-connect-execution-observation", "")
			if err != nil || status == 200 {
				t.Fatal("foreign source remained current")
			}
		} else if fault == "" {
			beforeStats := peer.exchange(t, map[string]string{"command": "stats"})
			var beforeLaunches uint64
			if json.Unmarshal(beforeStats["launches"], &beforeLaunches) != nil {
				t.Fatal("original worker launch count absent")
			}
			status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-connect-execution-restore", "{}")
			if err != nil || status != 200 {
				t.Fatal("actual retained-choice restoration failed", status, err, string(raw))
			}
			after := read()
			macOSCONNECTExecutionRequireMeasurements(t, after.Ready.Progress.Comparison, winner, false)
			if !after.Restored || after.PID == before.PID || after.Ready.Identity == before.Ready.Identity || after.Winner != before.Winner || after.Ready.Progress.Comparison.Target != before.Ready.Progress.Comparison.Target || !reflect.DeepEqual(after.Ready.Progress.Comparison.Winner, before.Ready.Progress.Comparison.Winner) {
				t.Fatal("restoration replaced retained choice or reused original native reader")
			}
			afterStats := peer.exchange(t, map[string]string{"command": "stats"})
			var afterLaunches uint64
			if json.Unmarshal(afterStats["launches"], &afterLaunches) != nil || afterLaunches < beforeLaunches {
				t.Fatal("original worker launch count regressed")
			}
			restoreLaunches = afterLaunches - beforeLaunches
			expectedLaunches := uint64(0)
			if winner == "server" {
				expectedLaunches = 1
			}
			if restoreLaunches != expectedLaunches {
				t.Fatal("Last restoration reran discovery or replaced original worker")
			}
		}
	}
	if fault == "held-cleanup" {
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-connect-execution-cleanup-retry", "{}")
		var refusal struct {
			Refused bool `json:"refused"`
			Same    bool `json:"same_owner"`
			Joined  bool `json:"joined"`
		}
		if err != nil || status != 200 || json.Unmarshal(raw, &refusal) != nil || !refusal.Refused || !refusal.Same || refusal.Joined {
			t.Fatal("original held cleanup did not retain retry authority", status, err, string(raw))
		}
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != 200 {
		t.Fatal("actual public Disconnect did not join", status, err, string(raw))
	}
	stats := peer.exchange(t, map[string]string{"command": "stats"})
	var observed macOSNodeChainPeerReply
	var launches uint64
	if string(stats["workers_joined"]) != "true" || json.Unmarshal(stats["peer"], &observed) != nil || json.Unmarshal(stats["launches"], &launches) != nil {
		t.Fatal("original relay worker survived public Disconnect or lost its counters")
	}
	var layers macOSImportedExecutionLayerObservation
	if json.Unmarshal(stats["layers"], &layers) != nil || layers.Entry != peer.layers.Entry || layers.Final != "off" || layers.FinalTransport == nil || layers.FinalTransport.Address != peer.layerObservation.FinalTransport.Address {
		t.Fatal("original entry/final layer ownership changed")
	}
	var layerPackets, layerCiphertext int64
	var layerAuth uint32
	if layers.Entry == "off" {
		if layers.EntryTransport != nil {
			t.Fatal("Off borrowed a layer owner")
		}
	} else {
		transport := layers.EntryTransport
		if transport == nil || peer.layerObservation.EntryTransport == nil || transport.Address != peer.layerObservation.EntryTransport.Address || transport.Method != "2022-blake3-aes-256-gcm" || transport.PhysicalUDP == 0 || transport.Packets == 0 || transport.AuthUDP != 0 {
			t.Fatal("original entry layer did not carry and decrypt captured packets")
		}
		layerPackets, layerCiphertext, layerAuth = transport.Packets, transport.PhysicalUDP, transport.AuthUDP
	}
	macOSNodeChainCONNECTReadback(t, peer.peer, observed)
	if *observed.OpenCONNECTStreams != 0 {
		t.Fatal("original CONNECT streams survived Disconnect")
	}
	if launches == 0 || len(observed.Prefixes) != 1 || observed.Prefixes[0].Mode != mode || observed.Prefixes[0].RawUDP == 0 || observed.Prefixes[0].TCP == 0 || observed.Prefixes[0].ProofQueries == 0 {
		t.Fatal("execution refused before original encrypted prefix and worker")
	}
	switch fault {
	case "wrong-auth":
		macOSNodeChainCONNECTNegativeCounters(t, observed, "wrong-middle-key")
	case "tls-name":
		macOSNodeChainCONNECTNegativeCounters(t, observed, "tls-name")
	case "wrong-public":
		macOSNodeChainCONNECTNegativeCounters(t, observed, "wrong-middle-public")
	case "wrong-final":
		if observed.Final.FinalRawTCP == 0 || observed.Final.FinalTCP != 0 || observed.Final.RouterQueries != 0 {
			t.Fatal("wrong original final key did not fail at encrypted final")
		}
	default:
		macOSNodeChainCONNECTPositiveCounters(t, observed, false)
		if observed.Final.RouterQueries == 0 || observed.Final.DNSQueries == 0 {
			t.Fatal("omitted original final proof or selected DNS")
		}
	}
	if negative {
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var current state
		if err != nil || status != 200 || json.Unmarshal(raw, &current) != nil || current.Connected {
			t.Fatal("refused execution published Connected")
		}
	}
	{
		counters, err := json.Marshal(map[string]any{"case": scenario, "launches": launches, "restore_launches": restoreLaunches, "comparison_trials": comparisonTrials, "entry_raw_udp": observed.Prefixes[0].RawUDP, "entry_tcp": observed.Prefixes[0].TCP, "entry_proofs": observed.Prefixes[0].ProofQueries, "middle_raw_tcp": observed.Middle.RawTCP, "middle_tcp": observed.Middle.TCP, "middle_public": observed.Middle.PublicQueries, "final_raw_tcp": observed.Final.FinalRawTCP, "final_tcp": observed.Final.FinalTCP, "final_proofs": observed.Final.RouterQueries, "dns": observed.Final.DNSQueries, "middle_raw_udp": observed.Middle.RawUDP, "final_raw_udp": observed.Final.FinalRawUDP, "auth_refusals": observed.CONNECTAuthRefusals, "tls_refusals": observed.CONNECTTLSRefusals, "open_streams": *observed.OpenCONNECTStreams, "entry_layer": layers.Entry, "entry_layer_packets": layerPackets, "entry_layer_ciphertext": layerCiphertext, "entry_layer_auth": layerAuth})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("DARWIN_CONNECT_EXECUTION_COUNTERS %s", counters)
	}
	if err = connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	if receipt.ExitCode != 0 {
		t.Fatal("original controller did not join")
	}
	controllerJoined = true
	if err = aliases.Close(ctx, peer.close); err != nil {
		t.Fatal(err)
	}
	t.Logf("DARWIN_CONNECT_EXECUTION_RECEIPT case=%s requested=%s winner=%s negative=%t restored=%t cleanup_retry=%t native_joined=true relay_joined=true aliases_retired=true", scenario, requested, winner, negative, !negative && fault == "", fault == "held-cleanup")
}
