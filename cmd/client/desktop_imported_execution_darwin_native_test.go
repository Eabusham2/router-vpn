//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

const macOSImportedExecutionMarker = "fixture-imported-execution-host"

var macOSImportedExecutionCases = []string{
	"wg-server", "awg2-fast-server", "awg2-strong-server",
	"wg-auto-local", "awg2-fast-auto-local", "awg2-strong-auto-local",
	"wg-auto-server", "awg2-fast-auto-server", "awg2-strong-auto-server",
	"wg-wrong-public", "wg-wrong-final", "wg-failed-dns", "wg-replaced-source",
}

func macOSImportedExecutionScenario(value string) (mode, requested, winner, fault string, err error) {
	found := false
	for _, candidate := range macOSImportedExecutionCases {
		found = found || candidate == value
	}
	if !found {
		return "", "", "", "", errors.New("uncaptured imported execution case")
	}
	mode = "wg"
	for _, candidate := range []string{"awg2-fast", "awg2-strong"} {
		if strings.HasPrefix(value, candidate+"-") {
			mode = candidate
		}
	}
	suffix := strings.TrimPrefix(value, mode+"-")
	requested, winner = "server", "server"
	switch suffix {
	case "server":
	case "auto-local":
		requested, winner = "auto", "local"
	case "auto-server":
		requested = "auto"
	default:
		fault = suffix
	}
	return
}

type macOSImportedExecutionObservation struct {
	Connected, PublicConnect, Joined, Restored bool
	Requested, Winner, Source, Transfer        string
	PID                                        int
	Ready                                      mobilemultihop.DesktopNodeChainExecutionReadyRecord
	Baseline                                   *desktopMacOSNodeChainReceipt
	Comparison                                 json.RawMessage
}

func macOSImportedExecutionObserve(ctx context.Context, a *app) (macOSImportedExecutionObservation, error) {
	var result macOSImportedExecutionObservation
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return result, errors.Join(err, errors.New("original execution owner absent"))
	}
	s := owner.session
	if err = s.Current(ctx); err != nil {
		return result, err
	}
	h := s.launch.chain.platform.host
	if h == nil || h.execution != s.execution || h.executionPreparation != s.execution.preparation || h.executionPhysical != s.execution.physical {
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
	if !result.Connected || result.Transfer == "" || result.Ready.TransferSHA256 != result.Transfer || result.Ready.InterfaceIndex == 0 || !strings.HasPrefix(result.Ready.InterfaceName, "utun") || !result.Ready.Progress.DNSProven {
		return result, errors.New("selected native TUN/DNS proof not retained")
	}
	return result, nil
}

func macOSImportedExecutionNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSImportedExecutionMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	scenario := strings.TrimSpace(string(raw))
	_, requested, _, fault, err := macOSImportedExecutionScenario(scenario)
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
	mux.HandleFunc("/api/native-imported-source", func(w http.ResponseWriter, r *http.Request) {
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
			selection, err = captureNativeMultihopSelection(r.Context(), macOSOwnedControllerRoot, selection, []string{"shadowsocks"}, nil)
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
	mux.HandleFunc("/api/native-imported-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := macOSImportedExecutionObserve(r.Context(), a)
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
	mux.HandleFunc("/api/native-imported-restore", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/native-imported-replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "replaced-source" {
			http.Error(w, "uncaptured replacement", 409)
			return
		}
		a.mu.Lock()
		a.profiles.Profiles[1].External.Shadowsocks.Password += "changed"
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"changed": true})
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSImportedExecutionPeer struct {
	peer          *macOSNodeChainPeer
	middle        string
	joined        bool
	started       bool
	quitAttempted bool
}

func (p *macOSImportedExecutionPeer) exchange(t *testing.T, value any) map[string]json.RawMessage {
	t.Helper()
	if err := p.peer.output.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer p.peer.output.SetReadDeadline(time.Time{})
	if json.NewEncoder(p.peer.input).Encode(value) != nil {
		t.Fatal("original peer input closed")
	}
	line, err := p.peer.reader.ReadBytes('\n')
	if err != nil || len(line) > 32768 {
		t.Fatal("original peer output missing", err)
	}
	var reply map[string]json.RawMessage
	if json.Unmarshal(line, &reply) != nil {
		t.Fatal("original peer output changed")
	}
	return reply
}
func (p *macOSImportedExecutionPeer) close(ctx context.Context) error {
	if p == nil || !p.started || p.joined {
		return nil
	}
	if !p.quitAttempted {
		p.quitAttempted = true
		// A partial startup may already have closed its input. Still wait for
		// this exact process; retry must never send a second shutdown command.
		_ = json.NewEncoder(p.peer.input).Encode(map[string]string{"command": "quit"})
		_ = p.peer.input.Close()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.peer.done:
	}
	if p.peer.failure != nil {
		return p.peer.failure
	}
	raw, err := io.ReadAll(io.LimitReader(p.peer.reader, 4097))
	if err != nil || len(raw) > 4096 || !strings.Contains(string(raw), `"joined":true`) || !strings.HasSuffix(string(raw), "PASS\n") {
		return errors.New("original peer omitted Manager/worker joined receipt")
	}
	p.joined = true
	return p.peer.output.Close()
}
func startMacOSImportedExecutionPeer(t *testing.T, p *macOSImportedExecutionPeer, mode string) {
	t.Helper()
	p.peer = macOSNodeChainPeerForModes(t, []string{mode, "shadowsocks"})
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
	peer.command = exec.Command(image, "-test.run=^TestRouterVPNDesktopImportedExecutionReferenceProcess$", "-test.count=1", "-test.timeout=240s")
	peer.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_IMPORTED_EXECUTION_REFERENCE=1", "ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1", "ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=" + peer.physical.String()}
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
	reply := p.exchange(t, map[string]any{"schema": 1, "peer": map[string]any{"schema": 1, "paired": paired, "middle_method": peer.middleMethod, "middle_password": peer.middlePassword}, "image": worker, "image_sha256": hex.EncodeToString(workerHash[:])})
	if json.Unmarshal(reply["peer"], &peer.reply) != nil || json.Unmarshal(reply["middle_address"], &p.middle) != nil || p.middle == "" || peer.reply.PublicCA == "" {
		t.Fatal("original imported peer identity missing")
	}
}

func TestMacOSImportedTrioExecutionNative(t *testing.T) {
	for _, scenario := range macOSImportedExecutionCases {
		t.Run(scenario, func(t *testing.T) { macOSImportedExecutionNativeCase(t, scenario) })
	}
}
func macOSImportedExecutionNativeCase(t *testing.T, scenario string) {
	mode, requested, winner, fault, err := macOSImportedExecutionScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	aliases, err := macOSImportedExecutionOwnAliases(context.Background())
	var peer *macOSImportedExecutionPeer
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
	peer = &macOSImportedExecutionPeer{}
	startMacOSImportedExecutionPeer(t, peer, mode)
	macOSExternalNativeTrust(t, &macOSExternalNativePeer{ca: peer.peer.reply.PublicCA})
	store := installMacOSNodeChainProfiles(t, peer.peer, "")
	host, port, err := net.SplitHostPort(peer.middle)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || host != peer.peer.physical.String() {
		t.Fatal("captured imported literal changed")
	}
	store.Profiles[1].Endpoint = host
	store.Profiles[1].External.Shadowsocks.Server = host
	store.Profiles[1].External.Shadowsocks.Port = n
	control := &store.Profiles[2]
	control.MultihopExecution = requested
	raw, _ := json.Marshal(store)
	if os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), raw, 0600) != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, macOSImportedExecutionMarker), []byte(scenario+"\n"), 0600) != nil {
		t.Fatal("original private source staging failed")
	}
	// Capture launch intent before any fallible supervisor/IPC operation. A
	// partial start never grants alias retirement without its original join.
	controllerJoined = false
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
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-imported-source", "")
	var source map[string]string
	if err != nil || status != 200 || json.Unmarshal(raw, &source) != nil || source["local_source"] == "" {
		t.Fatal("original complete source capture failed", status, err, string(raw))
	}
	configured := peer.exchange(t, map[string]string{"local_source": source["local_source"], "winner": winner})
	if string(configured["ready"]) != "true" {
		t.Fatal("registered original suffix unavailable")
	}
	commands := map[string]string{"wrong-public": "wrong-middle-public", "wrong-final": "wrong-node", "failed-dns": "fail-dns"}
	if command := commands[fault]; command != "" {
		peer.exchange(t, map[string]string{"command": command})
	}
	status, request, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-ordered-request", "")
	if err != nil || status != 200 {
		t.Fatal("original execution request unavailable")
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/connect", string(request))
	negative := commands[fault] != ""
	if err != nil || negative && status == 200 || !negative && status != 200 {
		t.Fatal("actual Darwin public execution verdict", status, err, string(raw))
	}
	read := func() macOSImportedExecutionObservation {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-imported-observation", "")
		var value macOSImportedExecutionObservation
		if err != nil || status != 200 || json.Unmarshal(raw, &value) != nil {
			t.Fatal("original execution observation missing", status, err, string(raw))
		}
		return value
	}
	if !negative {
		before := read()
		if !before.Connected || !before.PublicConnect || before.Requested != requested || before.Winner != winner || before.PID == 0 {
			t.Fatal("public execution replaced original chosen graph")
		}
		if fault == "replaced-source" {
			status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-imported-replace", "{}")
			if err != nil || status != 200 {
				t.Fatal(err)
			}
			status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-imported-observation", "")
			if err != nil || status == 200 {
				t.Fatal("foreign source remained current")
			}
		} else {
			status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-imported-restore", "{}")
			if err != nil || status != 200 {
				t.Fatal("actual retained-choice restoration failed", status, err, string(raw))
			}
			after := read()
			if !after.Restored || after.PID == before.PID || after.Ready.Identity == before.Ready.Identity || after.Winner != before.Winner || !reflect.DeepEqual(after.Comparison, before.Comparison) {
				t.Fatal("restoration reran Compare or reused original native reader")
			}
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
	if launches == 0 || observed.Schema != 1 || observed.Address != peer.peer.reply.Address || observed.PublicCA != peer.peer.reply.PublicCA || len(observed.Prefixes) != 1 || observed.Prefixes[0].Mode != mode || observed.Prefixes[0].RawUDP == 0 || observed.Prefixes[0].TCP == 0 || observed.Prefixes[0].ProofQueries == 0 || observed.Middle == nil || observed.Middle.Method != peer.peer.middleMethod || observed.Middle.RawTCP == 0 || observed.Middle.TCP == 0 || observed.Middle.PublicQueries == 0 {
		t.Fatal("native execution failed before its original encrypted entry, suffix worker or public middle proof")
	}
	switch fault {
	case "wrong-public":
		macOSNodeChainImportedNegativeCounters(t, observed, "wrong-middle-public")
	case "wrong-final":
		if observed.Final.FinalRawTCP == 0 || observed.Final.FinalTCP == 0 || observed.Final.RouterQueries == 0 || observed.Final.DNSQueries != 0 {
			t.Fatal("wrong final identity failed outside its original paired proof")
		}
	default:
		if observed.Final.FinalRawTCP == 0 || observed.Final.FinalTCP == 0 || observed.Final.RouterQueries == 0 || observed.Final.DNSQueries == 0 {
			t.Fatal("native execution omitted original final proof or selected DNS traffic")
		}
	}
	if negative {
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var current state
		if err != nil || status != 200 || json.Unmarshal(raw, &current) != nil || current.Connected {
			t.Fatal("refused execution published Connected")
		}
	}
	counters, err := json.Marshal(map[string]any{"case": scenario, "launches": launches, "entry_raw_udp": observed.Prefixes[0].RawUDP, "entry_tcp": observed.Prefixes[0].TCP, "entry_proofs": observed.Prefixes[0].ProofQueries, "middle_raw_tcp": observed.Middle.RawTCP, "middle_tcp": observed.Middle.TCP, "middle_public": observed.Middle.PublicQueries, "final_raw_tcp": observed.Final.FinalRawTCP, "final_tcp": observed.Final.FinalTCP, "final_proofs": observed.Final.RouterQueries, "dns": observed.Final.DNSQueries})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DARWIN_IMPORTED_EXECUTION_COUNTERS %s", counters)
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
	t.Logf("DARWIN_IMPORTED_EXECUTION_RECEIPT case=%s requested=%s winner=%s negative=%t restored=%t native_joined=true relay_joined=true aliases_retired=true", scenario, requested, winner, negative, !negative && fault == "")
}
