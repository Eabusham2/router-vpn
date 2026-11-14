//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

const macOSNodeChainNativeMarker = "fixture-node-chain-host"

// This entry exists only in the explicitly installed, root-owned test image.
// It consumes the production decoder, source capture, preflight, stage, proof,
// publication and cleanup. The ordinary Darwin public capability stays closed
// until the native acceptance gate has passed; once opened, this role must use
// the production public handler without its temporary admission bridge.
func macOSNodeChainNativeConnect(a *app, w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime) {
	if nativeNodeChainPlatformSupported() {
		a.nativeMultihopConnectOwned(w, r, driver)
		return
	}
	operation, finish, err := a.beginConnectionOperationContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer finish()
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	q, err := decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || !q.ordered() {
		http.Error(w, "original ordered request required", http.StatusBadRequest)
		return
	}
	if execution, err := routeExecution(q); err != nil || execution != "local" {
		http.Error(w, "original local execution required", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	selection, err := a.resolveNativeMultihopRequestLocked(q)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.nativeMultihopConnectLocalOwned(w, r, operation, selection, driver)
}

func macOSNodeChainNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSNodeChainNativeMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || string(raw) != "explicit disposable macOS ordered PF and TUN fixture\n" {
		return true, errors.Join(err, errors.New("ordered native test has no original disposable authority"))
	}
	raw, err = readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, "fixture-node-chain-case"), 128)
	scenario := strings.TrimSpace(string(raw))
	modes, action, caseErr := macOSNodeChainScenario(scenario)
	if err != nil || caseErr != nil {
		return true, errors.Join(err, caseErr)
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{
		AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress,
		ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(macOSOwnedControllerRoot, "modes.json"),
		ScriptsDir: filepath.Join(macOSOwnedControllerRoot, "modes"), StateFile: filepath.Join(macOSOwnedControllerRoot, "state.json"),
	}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || a.profiles.SelectedID != "installed-ordered-final" || len(a.profiles.Profiles) != len(modes)+1 {
		return true, errors.Join(err, errors.New("ordered native test lost its complete saved original catalog"))
	}
	control, found := a.profileByIDLocked(a.profiles.SelectedID)
	if !found || len(control.MultihopNodes) != len(modes)+1 || !control.MultihopEnabled || control.MultihopExecution != "local" {
		return true, errors.New("ordered native test lost its original control path")
	}
	for i, node := range control.MultihopNodes {
		expected := "shadowsocks"
		if strings.HasPrefix(scenario, "node-chain-hy2-") {
			expected = "hysteria2"
		}
		if i < len(modes) {
			expected = modes[i]
		}
		if node.ID != a.profiles.Profiles[i].ID || node.Mode != expected {
			return true, errors.New("ordered native test changed original member order or cipher")
		}
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return true, errors.New("ordered native test lost actual mode catalog")
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	// Non-measurement scenarios retain the actual Auto hold, so a simultaneous
	// optimizer never changes the negative boundary being exercised.
	if action != "mtu" {
		hold, stop := context.WithTimeout(context.Background(), 5*time.Second)
		release, err := a.holdCapturedMTU(hold)
		stop()
		if err != nil {
			return true, err
		}
		defer release()
	}
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	var originalMu sync.Mutex
	var original *desktopMacOSNodeChainHost
	var stopped atomic.Bool
	var initialReady *mobilemultihop.DesktopNodeChainReadyRecord
	driver := nativeMultihopConnectRuntime{capture: captureNativeMultihopForApp, stage: stageOwnedNativeMultihopCommand,
		preflight: func(owner *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			launch, err := preflightOwnedNativeMultihopCommand(owner, selection, descriptor)
			if launch == nil || launch.chain == nil || launch.chain.platform == nil {
				return launch, err
			}
			h := launch.chain.platform.host
			originalMu.Lock()
			defer originalMu.Unlock()
			if h == nil || h.parent.parent != captured.parent || h.parent.session != captured.session || original != nil && original != h {
				return launch, errors.New("ordered native observation received a replacement owner")
			}
			original = h
			baseline := h.baselineRun
			// Observe the actual stopped record after authenticated native Stop and
			// sole-waiter join, before the real baseline release removes workspace.
			// This forwards the shipping protection operation without replacement.
			h.baselineRun = func(ctx context.Context, parent *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
				action string, expected *desktopMacOSNodeChainReceipt, started func()) (*desktopMacOSNodeChainReceipt, error) {
				if (action == "retire" || action == "release") && h.process != nil && h.process.started.Load() {
					if !h.nativeRetired || h.process.NativeCleanup(ctx) != nil {
						return nil, errors.New("native ordered retirement lacks original Stop acknowledgment and join")
					}
					closed, stopErr := readDesktopNodeStoppedContext(ctx, h.launch)
					if stopErr != nil || !closed {
						return nil, errors.Join(stopErr, errors.New("native ordered retirement omitted its original stopped record"))
					}
					stopped.Store(true)
				}
				return baseline(ctx, parent, selection, action, expected, started)
			}
			return launch, err
		},
		proof: func(owner *app, selection multihopSelection, command *exec.Cmd) error {
			if err := owner.proveNativeMultihop(selection, command); err != nil {
				return err
			}
			originalMu.Lock()
			defer originalMu.Unlock()
			if original == nil || original.launch.command != command {
				return errors.New("ordered proof changed its observed original command")
			}
			original.launch.chain.mu.Lock()
			defer original.launch.chain.mu.Unlock()
			if original.launch.chain.ready == nil {
				return errors.New("native ordered proof omitted ready record")
			}
			copy := *original.launch.chain.ready
			initialReady = &copy
			return nil
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller unavailable", http.StatusConflict)
			return
		}
		a.mu.Lock()
		value := a.state
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.HandleFunc("/api/native-ordered-request", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		tokens, err := a.connectionProfileTokensLocked(control)
		if !found || err != nil {
			http.Error(w, "original source inventory unavailable", http.StatusConflict)
			return
		}
		selected := a.profiles.SelectedID
		_ = json.NewEncoder(w).Encode(multihopConnectRequest{Nodes: append([]common.MultihopNodeSelection(nil), control.MultihopNodes...), Execution: "local",
			desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: tokens}})
	})
	mux.HandleFunc("/api/multihop/connect", func(w http.ResponseWriter, r *http.Request) { macOSNodeChainNativeConnect(a, w, r, driver) })
	mux.HandleFunc("/api/multihop/status", a.multihopStatus)
	mux.HandleFunc("/api/multihop/speed-test", a.multihopSpeedTest)
	mux.HandleFunc("/api/disconnect", a.disconnect)
	mux.HandleFunc("/api/mtu/retest", a.retestMTU)
	mux.HandleFunc("/api/mtu/status", a.desktopMTUStatus)
	mux.HandleFunc("/api/mtu/cancel", a.cancelDesktopMTURoute)
	mux.HandleFunc("/api/native-ordered-replace-middle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || action != "middle-source" {
			http.Error(w, "uncaptured source fault", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		middle := &a.profiles.Profiles[1]
		if middle.NodeKind == "external" && middle.External != nil && middle.External.SOCKS5 != nil {
			middle.External.SOCKS5.Password += "-replaced-after-original-proof"
		} else if middle.NodeKind == "external" && middle.External != nil && middle.External.Shadowsocks != nil {
			middle.External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("r", 32)))
		} else {
			middle.APIToken += "-replaced-after-original-proof"
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/native-ordered-observation", func(w http.ResponseWriter, r *http.Request) {
		originalMu.Lock()
		h, initial := original, initialReady
		originalMu.Unlock()
		if h == nil {
			http.Error(w, "original ordered host missing", http.StatusConflict)
			return
		}
		value, err := macOSNodeChainNativeObservation(r.Context(), h, initial, stopped.Load())
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSNodeChainNativeResult struct {
	Session, Source, Config, Transfer, ViewSession, Profile, PhysicalAddress       string
	ProcessID                                                                      int
	Connected, Closed, NativeJoined, Stopped, WorkspaceRetired, Monitor, MTUActive bool
	Nodes                                                                          []common.MultihopNodeSelection
	SourceTokens                                                                   map[string]string
	Baseline                                                                       *desktopMacOSNodeChainReceipt
	Ready, InitialReady                                                            *mobilemultihop.DesktopNodeChainReadyRecord
	MTU                                                                            desktopNodeMTURecord
	EffectiveMTU                                                                   int
	EffectiveSource                                                                string
}

func macOSNodeChainNativeObservation(ctx context.Context, h *desktopMacOSNodeChainHost, initial *mobilemultihop.DesktopNodeChainReadyRecord, stopped bool) (macOSNodeChainNativeResult, error) {
	var result macOSNodeChainNativeResult
	if err := h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.launch == nil || !h.launch.chain.hasPolicy() || h.launch.chain.policy != h.policy || h.launch.chain.socksPolicy != h.socksPolicy || h.runtime == nil || h.runtime.host != h || h.process == nil {
		return result, errors.New("native ordered observation lost exact owner")
	}
	_, meta, capture, err := h.launch.chain.readPolicy()
	if err != nil || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 ||
		capture.PhysicalRoots[0].Destinations[0].Network != "udp" || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Host != "192.168.50.133" ||
		meta.TargetOS != "darwin" || meta.ProfileID != "installed-ordered-final" || meta.Mode != h.launch.chain.selection.ExitMode {
		return result, errors.New("native ordered observation changed full policy or selected Home DNS")
	}
	physical := capture.PhysicalRoots[0].Destinations[0]
	result.PhysicalAddress = net.JoinHostPort(physical.Host, fmt.Sprint(physical.Port))
	result.Session, result.Source, result.Config, result.Profile = meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.ProfileID
	result.Closed, result.Stopped, result.WorkspaceRetired = h.closed, stopped, h.workspaceRetired
	if h.process.command == nil || h.process.command.Process == nil {
		return result, errors.New("native ordered process never started")
	}
	result.ProcessID = h.process.command.Process.Pid
	result.Transfer, err = h.launch.chain.macOSTransfer(h.process.capture.Selection())
	if err != nil || h.transfer != "" && result.Transfer != h.transfer {
		return result, errors.New("native ordered transfer changed")
	}
	if h.baseline != nil {
		copy := *h.baseline
		result.Baseline = &copy
	}
	if initial != nil {
		copy := *initial
		result.InitialReady = &copy
	}
	a := h.parent.app
	if h.closed {
		result.NativeJoined = h.nativeRetired && h.process.NativeCleanup(ctx) == nil
		if !result.NativeJoined || !stopped || !h.workspaceRetired {
			return result, errors.New("native ordered cleanup lacks original native acknowledgment or joined retirement")
		}
		if _, err := os.Lstat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
			return result, errors.New("native ordered private workspace remains")
		}
		return result, nil
	}
	if err := h.readReadyLocked(ctx, false); err != nil {
		return result, err
	}
	if h.bound == nil || h.bound.launch != h.launch || h.bound.selection.Native == nil || h.bound.selection.Native.validate(h.bound.selection) != nil {
		return result, errors.New("native ordered observation lost original complete source")
	}
	if _, other := desktopNodeOwners.Load(a); other {
		return result, errors.New("native ordered path acquired another process registry")
	}
	for _, node := range h.bound.selection.Nodes {
		result.Nodes = append(result.Nodes, common.MultihopNodeSelection{ID: node.Profile.ID, Mode: node.Mode})
	}
	h.launch.chain.mu.Lock()
	if h.launch.chain.ready != nil {
		copy := *h.launch.chain.ready
		result.Ready = &copy
	}
	h.launch.chain.mu.Unlock()
	result.MTU, err = readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil {
		return result, err
	}
	result.MTUActive = h.mtu != nil || result.MTU.Active
	result.Monitor = h.monitorDone != nil
	if result.Monitor {
		select {
		case <-h.monitorDone:
			result.Monitor = false
		default:
		}
	}
	a.mu.Lock()
	result.Connected = a.state.Connected && a.cmd == h.launch.command
	profile, found := a.profileByIDLocked(result.Profile)
	if found {
		result.EffectiveMTU, result.EffectiveSource = profile.EffectiveMTU, profile.EffectiveMTUSource
		result.SourceTokens, err = a.connectionProfileTokensLocked(profile)
	}
	a.mu.Unlock()
	if err != nil || !found {
		return result, errors.New("native ordered observation lost original control source")
	}
	result.ViewSession = sessionTrackerFor(a).snapshot(0).ID
	return result, nil
}

func TestMacOSRetainedNodeChainNativeHost(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("ordered native host acceptance requires its explicit real disposable controller")
	}
	for _, scenario := range macOSNodeChainHostCases {
		t.Run(scenario, func(t *testing.T) { macOSNodeChainNativeCase(t, scenario) })
	}
}

func macOSNodeChainNativeRead(t *testing.T, ctx context.Context, client *http.Client) macOSNodeChainNativeResult {
	t.Helper()
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-ordered-observation", "")
	var result macOSNodeChainNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &result) != nil {
		t.Fatal("original ordered native observation failed", status, err, string(raw))
	}
	return result
}

func macOSNodeChainNativeCase(t *testing.T, scenario string) {
	t.Helper()
	modes, action, err := macOSNodeChainScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	peer := startMacOSNodeChainPeerFinal(t, modes, strings.HasPrefix(scenario, "node-chain-hy2-"))
	macOSExternalNativeTrust(t, &macOSExternalNativePeer{ca: peer.reply.PublicCA})
	store := installMacOSNodeChainProfiles(t, peer, action)
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-node-chain-case"), []byte(scenario+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	switch action {
	case "wrong-middle-proof":
		peer.observe(t, "wrong-node:1")
	case "wrong-middle-public":
		peer.observe(t, "wrong-middle-public")
	case "final-dns-failure":
		peer.observe(t, "fail-dns")
	case "final-node-failure":
		peer.observe(t, "wrong-node")
	}
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 150 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	joined := false
	t.Cleanup(func() {
		if joined {
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
			t.Error("original ordered controller cleanup failed", receipt.ExitCode)
		}
		joined = true
	})
	macOSControllerNativeAwait(t, func() bool {
		call, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		status, _, err := macOSExternalNativeHTTP(call, client, http.MethodGet, "/api/status", "")
		return err == nil && status == http.StatusOK
	}, "original ordered controller did not start")
	beforeTunnels := macOSExternalNativeTunnels(t)
	status, body, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-ordered-request", "")
	var request multihopConnectRequest
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &request) != nil || request.ExpectedSelectedNodeID == nil || *request.ExpectedSelectedNodeID != store.SelectedID ||
		!reflect.DeepEqual(request.Nodes, store.Profiles[len(store.Profiles)-1].MultihopNodes) || len(request.ExpectedProfileTokens) != len(store.Profiles) {
		t.Fatal("native request lost original complete inventory", status, err, string(body))
	}
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/connect", string(body))
	negative := action == "wrong-middle-key" || action == "wrong-middle-public" || action == "wrong-awg-parameters" || action == "wrong-middle-proof" || action == "final-dns-failure" || action == "final-node-failure" || action == "final-password" || action == "final-trust" || action == "final-mask"
	if err != nil || negative && status == http.StatusOK || !negative && status != http.StatusOK {
		t.Fatal("ordered native Connect reached wrong verdict", status, err, string(raw))
	}
	var live macOSNodeChainNativeResult
	var performanceCapture string
	if action == "mtu" {
		macOSNodeChainNativeAwaitAuto(t, ctx, client, peer)
	}
	live = macOSNodeChainNativeRead(t, ctx, client)
	stats := peer.observe(t, "stats")
	macOSNodeChainHysteriaCounters(t, peer, stats, action)
	if negative {
		if !live.Closed || !live.NativeJoined || !live.Stopped || live.Ready != nil || live.Session == "" || stats.Prefixes[0].RawUDP == 0 || stats.Prefixes[0].ProofQueries == 0 {
			t.Fatal("negative did not reach actual original encrypted boundary and joined refusal", live, stats)
		}
		if action == "wrong-middle-proof" && stats.Prefixes[1].ProofQueries == 0 || action == "final-dns-failure" && stats.Final.DNSQueries == 0 || action == "final-node-failure" && stats.Final.RouterQueries == 0 {
			t.Fatal("negative failed before intended actual service", stats)
		}
		if peer.middlePassword == "" && (action == "wrong-middle-key" || action == "wrong-awg-parameters") && (stats.Prefixes[1].RawUDP == 0 || stats.Prefixes[1].ProofQueries != 0 || stats.Final.RouterQueries != 0) {
			t.Fatal("wrong middle cipher bypassed encrypted boundary", stats)
		}
		if peer.middlePassword != "" {
			macOSNodeChainImportedNegativeCounters(t, stats, action)
		}
	} else {
		macOSNodeChainNativeProved(t, peer, request, live, started.ProcessID)
		// Observe a later native heartbeat, not an assumed delay or saved label.
		deadline := time.Now().Add(5 * time.Second)
		for {
			next := macOSNodeChainNativeRead(t, ctx, client)
			if next.Session != live.Session || next.ProcessID != live.ProcessID || next.Transfer != live.Transfer || next.Baseline == nil || next.Baseline.Token != live.Baseline.Token {
				t.Fatal("completed Connect lost original native owner")
			}
			if next.Ready.ObservedAt > live.Ready.ObservedAt {
				live = next
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("original native heartbeat did not advance after Connect")
			}
			time.Sleep(25 * time.Millisecond)
		}
		if action == "mtu" {
			macOSNodeChainNativeMTU(t, ctx, client, peer, live)
			live = macOSNodeChainNativeRead(t, ctx, client)
		}
		performanceCapture = macOSNodeChainNativeMeasurement(t, ctx, client, peer, request, live)
		if action == "prefix-lost" {
			if peer.middlePassword != "" {
				peer.observe(t, "stop-middle")
			} else {
				peer.observe(t, "wrong-node:1")
			}
		}
		if action == "middle-source" {
			status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-ordered-replace-middle", "{}")
			if err != nil || status != http.StatusOK {
				t.Fatal("original middle source fault failed", status, err, string(raw))
			}
		}
		if action == "middle-source" || action == "prefix-lost" {
			deadline := time.Now().Add(12 * time.Second)
			for {
				status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/status", "")
				var state state
				if err != nil || status != http.StatusOK || json.Unmarshal(raw, &state) != nil {
					t.Fatal("monitor state unavailable", status, err, string(raw))
				}
				if !state.Connected {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("original native monitor retained a lost source or prefix")
				}
				time.Sleep(25 * time.Millisecond)
			}
		}
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != http.StatusOK || strings.TrimSpace(string(raw)) != `{"ok":true}` {
		t.Fatal("actual ordered public Disconnect failed", status, err, string(raw))
	}
	retired := macOSNodeChainNativeRead(t, ctx, client)
	if performanceCapture != "" {
		status, body, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/multihop/status", "")
		var closed struct {
			Connected bool   `json:"connected"`
			Capture   string `json:"ordered_capture"`
			Count     int    `json:"ordered_nodes"`
		}
		if err != nil || status != http.StatusOK || json.Unmarshal(body, &closed) != nil || closed.Connected || closed.Capture != "" || closed.Count != 0 {
			t.Fatal("retired native owner exposed another public Performance capture", status, err, string(body))
		}
		q, err := json.Marshal(routedSpeedRequest{EntryID: request.Nodes[0].ID, ExitID: request.Nodes[len(request.Nodes)-1].ID, Bytes: 8 << 20, OrderedCapture: performanceCapture})
		if err != nil {
			t.Fatal(err)
		}
		status, body, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/speed-test", string(q))
		if err != nil || status != http.StatusConflict {
			t.Fatal("closed original native owner replayed a former Performance capture", status, err, string(body))
		}
	}
	// A monitor's completed hold retires the native host before the later
	// public Disconnect releases its durable journal. That closed host keeps
	// its original historical held receipt; actual PF absence is checked below.
	baselineRetired := retired.Baseline != nil && retired.Baseline.Phase == "retired" && !retired.Baseline.Baseline.Present
	baselineHeldHistory := (action == "middle-source" || action == "prefix-lost") && retired.Baseline != nil && retired.Baseline.Phase == "held" && retired.Baseline.Baseline.Present
	if !retired.Closed || !retired.NativeJoined || !retired.Stopped || !retired.WorkspaceRetired || retired.Session != live.Session || retired.ProcessID != live.ProcessID || retired.Transfer != live.Transfer ||
		!baselineRetired && !baselineHeldHistory || live.Baseline == nil || retired.Baseline.Token != live.Baseline.Token {
		t.Fatal("ordered cleanup omitted exact original native/PF/workspace receipt", retired)
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, beforeTunnels)
	if peer.middleSOCKS {
		stats := peer.observe(t, "stats")
		if stats.Associations == nil || *stats.Associations != 0 {
			t.Fatal("installed typed child left a remote SOCKS association after joined retirement", stats.Associations)
		}
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	joined = true
	if receipt.ExitCode != 0 {
		t.Fatal("original ordered controller did not join", receipt.ExitCode)
	}
	t.Logf("actual sealed Darwin ordered host verified %s: original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join", scenario)
}

func macOSNodeChainNativeMeasurement(t *testing.T, ctx context.Context, client *http.Client, peer *macOSNodeChainPeer,
	request multihopConnectRequest, original macOSNodeChainNativeResult) string {
	t.Helper()
	before := peer.observe(t, "stats")
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/multihop/status", "")
	var preflight struct {
		Connected bool   `json:"connected"`
		Entry     string `json:"entry_id"`
		Exit      string `json:"exit_id"`
		Capture   string `json:"ordered_capture"`
		Count     int    `json:"ordered_nodes"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &preflight) != nil || !preflight.Connected ||
		preflight.Entry != request.Nodes[0].ID || preflight.Exit != request.Nodes[len(request.Nodes)-1].ID ||
		preflight.Count != len(request.Nodes) || len(preflight.Capture) != 64 {
		t.Fatal("original protected host has no complete public Performance capture", status, err, string(raw))
	}
	foreign := "0" + preflight.Capture[1:]
	if foreign == preflight.Capture {
		foreign = "1" + preflight.Capture[1:]
	}
	for _, token := range []string{"", foreign} {
		body, err := json.Marshal(routedSpeedRequest{EntryID: preflight.Entry, ExitID: preflight.Exit, Bytes: 8 << 20, OrderedCapture: token})
		if err != nil {
			t.Fatal(err)
		}
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/speed-test", string(body))
		if err != nil || status != http.StatusConflict {
			t.Fatal("public Performance admitted a missing or replaced ordered capture", status, err, string(raw))
		}
	}
	q, err := json.Marshal(routedSpeedRequest{EntryID: preflight.Entry, ExitID: preflight.Exit, Bytes: 8 << 20, OrderedCapture: preflight.Capture})
	if err != nil {
		t.Fatal(err)
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/speed-test", string(q))
	var result struct {
		Connected  bool                     `json:"connected"`
		Mode       string                   `json:"mode"`
		Entry      string                   `json:"entry_id"`
		Exit       string                   `json:"exit_id"`
		Capture    string                   `json:"ordered_capture"`
		Count      int                      `json:"ordered_nodes"`
		Bytes      int64                    `json:"bytes"`
		Hops       []speedLabHopMeasurement `json:"hops"`
		MeasuredAt time.Time                `json:"measured_at"`
		Note       string                   `json:"note"`
	}
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &result) != nil || !result.Connected ||
		result.Mode != "multihop" || result.Entry != preflight.Entry || result.Exit != preflight.Exit ||
		result.Capture != preflight.Capture || result.Count != len(request.Nodes) || result.Bytes != 8<<20 || len(result.Hops) != len(request.Nodes) {
		t.Fatal("actual public ordered measurement omitted complete original rows", status, err, string(raw))
	}
	positive := func(value float64) bool { return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0) }
	for i, row := range result.Hops {
		role := "intermediate"
		if i == 0 {
			role = "entry"
		}
		if i == len(request.Nodes)-1 {
			role = "exit"
		}
		label := fmt.Sprintf("Cumulative path through node %d of %d", i+1, len(request.Nodes))
		if peer.middlePassword != "" && i == 1 {
			label += " to the public benchmark"
		}
		if row.RouterID != request.Nodes[i].ID || row.Role != role || row.LatencyLabel != label+" HTTP response" || row.SpeedLabel != label+" transfer" ||
			row.LatencyError != "" || row.SpeedError != "" || row.Latency == nil || row.Speed == nil ||
			row.Latency.RouterID != row.RouterID || !row.Latency.Connected || row.Latency.Samples != 6 || !positive(row.Latency.MedianMs) ||
			row.Speed.RouterID != row.RouterID || row.Speed.Bytes != 8<<20 || !positive(row.Speed.DownloadMs) || !positive(row.Speed.UploadMs) ||
			!positive(row.Speed.DownloadMbps) || !positive(row.Speed.UploadMbps) {
			t.Fatal("actual encrypted prefix measurement lost original identity, samples or exact transfer", i, row)
		}
	}
	after := peer.observe(t, "stats")
	if after.Final.DownloadBytes < before.Final.DownloadBytes+(8<<20) || after.Final.UploadBytes < before.Final.UploadBytes+(8<<20) ||
		after.Final.DirectQueries != 0 || len(after.Prefixes) != len(before.Prefixes) {
		t.Fatal("ordered public measurement lacks independent actual final transferred bytes", before, after)
	}
	for i, prefix := range after.Prefixes {
		if prefix.RawUDP <= before.Prefixes[i].RawUDP || prefix.TCP <= before.Prefixes[i].TCP ||
			prefix.ProofQueries < before.Prefixes[i].ProofQueries+6 || prefix.AuthRefusals != 0 {
			t.Fatal("ordered measurement skipped an original encrypted prefix", i, before.Prefixes[i], prefix)
		}
	}
	if peer.middlePassword != "" {
		macOSNodeChainImportedPositiveCounters(t, after)
		if before.Middle == nil || after.Middle.Method != before.Middle.Method ||
			after.Middle.DownloadBytes < before.Middle.DownloadBytes+(8<<20) || after.Middle.UploadBytes < before.Middle.UploadBytes+(8<<20) ||
			after.Middle.PublicQueries < before.Middle.PublicQueries+6 {
			t.Fatal("ordered measurement skipped the original imported cipher, public samples or transferred bytes", before.Middle, after.Middle)
		}
	}
	live := macOSNodeChainNativeRead(t, ctx, client)
	macOSNodeChainNativeProved(t, peer, request, live, 0)
	if live.Session != original.Session || live.Source != original.Source || live.Config != original.Config ||
		live.ProcessID != original.ProcessID || live.Transfer != original.Transfer || live.Ready.Generation != original.Ready.Generation ||
		live.Baseline.Token != original.Baseline.Token || live.MTU.Reader != original.MTU.Reader || live.MTU.Path != original.MTU.Path ||
		live.MTU.Interface != original.MTU.Interface || live.MTU.Index != original.MTU.Index || live.MTU.MTU != original.MTU.MTU {
		t.Fatal("public Performance replaced its original native process, PF or TUN reader")
	}
	t.Log("actual sealed Darwin ordered measurement: every original prefix transferred 8 MiB per direction with six HTTP samples, original native process PF and TUN reader retained")
	return preflight.Capture
}

func macOSNodeChainNativeProved(t *testing.T, peer *macOSNodeChainPeer, request multihopConnectRequest, value macOSNodeChainNativeResult, controllerPID int) {
	t.Helper()
	if !value.Connected || value.Closed || !value.Monitor || value.ProcessID <= 0 || value.ProcessID == controllerPID || value.Ready == nil || value.InitialReady == nil ||
		value.Ready.TransferSHA256 != value.Transfer || value.Ready.SourceSHA256 != value.Source || value.Ready.Identity.SessionID != value.Session ||
		!reflect.DeepEqual(value.Nodes, request.Nodes) || !maps.Equal(value.SourceTokens, request.ExpectedProfileTokens) || value.PhysicalAddress != peer.reply.Address ||
		value.Baseline == nil || value.Baseline.Phase != "active" || !value.Baseline.Baseline.Present || value.Baseline.Capture.Session != value.Session ||
		value.MTUActive || value.MTU.Failure != "" || value.Ready.InterfaceName != value.MTU.Interface || value.Ready.InterfaceIndex != uint32(value.MTU.Index) || value.Ready.MTU != value.MTU.MTU || value.Ready.Reader != value.MTU.Reader {
		t.Fatal("ordered host lost original complete readiness/MTU/PF identity", value)
	}
	if peer.middleSOCKS && (value.Ready.Kind != "routervpn-node-chain-socks-ready-v1" || value.Baseline.Capture.Family != macosprocess.NodeChainSOCKSFamily) {
		t.Fatal("typed installed host borrowed ordinary readiness or PF family")
	}
	link, err := net.InterfaceByIndex(value.MTU.Index)
	if err != nil || link.Name != value.MTU.Interface || link.MTU != value.MTU.MTU || link.Flags&net.FlagUp == 0 {
		t.Fatal("original actual utun readback failed", err, link)
	}
	stats := peer.observe(t, "stats")
	macOSNodeChainHysteriaCounters(t, peer, stats, "connect")
	for i, prefix := range stats.Prefixes {
		if prefix.Mode != request.Nodes[i].Mode || prefix.RawUDP == 0 || prefix.TCP == 0 || prefix.UDP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 {
			t.Fatal("ordered path omitted actual independent authenticated prefix", i, prefix)
		}
	}
	if peer.middlePassword != "" && (len(request.Nodes) != 3 || request.Nodes[1].Mode != peer.observedMiddleProtocol() || stats.Middle == nil ||
		stats.Middle.Method != peer.observedMiddleMethod() || stats.Middle.RawTCP == 0 || stats.Middle.RawUDP == 0 || stats.Middle.TCP == 0 || stats.Middle.UDP == 0 || stats.Middle.PublicQueries == 0) {
		t.Fatal("ordered path omitted actual independent imported cipher or public-path proof", stats.Middle)
	}
	if stats.Final.RouterQueries == 0 || stats.Final.DNSQueries == 0 || stats.Final.FinalPublicQueries == 0 || peer.hysteriaPassword == "" && (stats.Final.FinalTCP == 0 || stats.Final.FinalUDP == 0) || stats.Final.DirectQueries != 0 {
		t.Fatal("ordered final did not carry selected DNS/private/public proof", stats)
	}
}

type macOSNodeChainMTUView struct {
	Session   string           `json:"session_id"`
	Profile   string           `json:"profile_id"`
	Requested bool             `json:"requested"`
	Status    mobilemtu.Status `json:"status"`
}

func macOSNodeChainNativeMTUStatus(t *testing.T, ctx context.Context, client *http.Client, request string) macOSNodeChainMTUView {
	t.Helper()
	path := "/api/mtu/status"
	if request != "" {
		path += "?request_id=" + request
	}
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, path, "")
	var value macOSNodeChainMTUView
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual ordered MTU status unavailable", status, err, string(raw))
	}
	return value
}

func macOSNodeChainNativeAwaitAuto(t *testing.T, ctx context.Context, client *http.Client, peer *macOSNodeChainPeer) {
	t.Helper()
	deadline := time.Now().Add(130 * time.Second)
	for {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/mtu/status", "")
		var value macOSNodeChainMTUView
		if err != nil || status != http.StatusOK && status != http.StatusConflict || status == http.StatusOK && json.Unmarshal(raw, &value) != nil {
			t.Fatal("actual automatic MTU status lost its bounded public response", status, err, string(raw))
		}
		// A reader replacement can own the native observation gate longer than
		// the status request's four-second proof budget. Only a later complete
		// successful response can satisfy Auto; a conflict is never a result.
		if status == http.StatusOK && value.Status.Complete && !value.Status.Running {
			if !value.Status.Measured || value.Status.Failure != "" || value.Status.Source != "auto-throughput-multihop-exit-path" || value.Status.EffectiveMTU < 1280 {
				t.Fatal("actual ordered automatic MTU did not adopt a measured winner", value)
			}
			stats := peer.observe(t, "stats")
			if stats.Benchmark == nil || stats.Benchmark.Replies == 0 || stats.Benchmark.SentBytes == 0 || stats.Benchmark.ReceivedBytes == 0 || stats.Benchmark.MaximumPayload < 1252 {
				t.Fatal("automatic MTU lacked real final-only UDP benchmark bytes", stats)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("actual ordered automatic MTU exceeded unchanged measurement budget", status, string(raw), value)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func macOSNodeChainNativeMTU(t *testing.T, ctx context.Context, client *http.Client, peer *macOSNodeChainPeer, original macOSNodeChainNativeResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	if original.InitialReady == nil || original.Ready.Reader <= original.InitialReady.Reader || original.Ready.Generation <= original.InitialReady.Generation || original.EffectiveSource != "auto-throughput-multihop-exit-path" || original.EffectiveMTU != original.MTU.MTU {
		t.Fatal("Auto did not adopt actual ordered reader succession", original)
	}
	before := peer.observe(t, "hold-benchmark")
	if before.Benchmark == nil || !before.Benchmark.Held {
		t.Fatal("actual independent benchmark hold was not admitted")
	}
	request := strings.Repeat("a", 32)
	makeBody := func(session, id string) string {
		raw, _ := json.Marshal(mtuViewRequest{Request: id, Session: session, Profile: original.Profile})
		return string(raw)
	}
	type completion struct {
		status int
		raw    []byte
		err    error
	}
	done := make(chan completion, 1)
	joined := false
	go func() {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
		done <- completion{status, raw, err}
	}()
	defer func() {
		if joined {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("original ordered MTU HTTP worker did not join after fixture cancellation")
		}
	}()
	deadline := time.Now().Add(25 * time.Second)
	for {
		select {
		case result := <-done:
			joined = true
			t.Fatal("held actual optimizer completed before captured Cancel", result.status, result.err, string(result.raw))
		default:
		}
		stats := peer.observe(t, "stats")
		if stats.Benchmark.HeldPackets > before.Benchmark.HeldPackets {
			view := macOSNodeChainNativeMTUStatus(t, ctx, client, "")
			if view.Status.Running && view.Status.Request == request {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("actual Retest did not reach held final-only benchmark and original Running receipt", stats)
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", makeBody(original.ViewSession+"-foreign", request))
	if err != nil || status != http.StatusConflict {
		t.Fatal("foreign ordered MTU Cancel acquired original operation", status, err, string(raw))
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/cancel", makeBody(original.ViewSession, request))
	if err != nil || status != http.StatusOK {
		t.Fatal("original ordered MTU Cancel failed", status, err, string(raw))
	}
	select {
	case result := <-done:
		joined = true
		if result.err != nil || result.status != http.StatusRequestTimeout {
			t.Fatal("canceled actual optimizer did not join its rollback", result.status, result.err, string(result.raw))
		}
	case <-time.After(25 * time.Second):
		t.Fatal("canceled actual optimizer retained an unjoined worker")
	}
	view := macOSNodeChainNativeMTUStatus(t, ctx, client, request)
	if view.Status.Running || !view.Status.Complete || view.Status.Measured || !view.Status.Restored || view.Status.EffectiveMTU != original.MTU.MTU {
		t.Fatal("public cancellation omitted exact MTU restoration", view)
	}
	restored := macOSNodeChainNativeRead(t, ctx, client)
	if restored.MTUActive || !restored.Connected || restored.Session != original.Session || restored.ProcessID != original.ProcessID || restored.Transfer != original.Transfer || restored.MTU.MTU != original.MTU.MTU || restored.MTU.Reader <= original.MTU.Reader || restored.EffectiveMTU != original.EffectiveMTU || restored.Baseline.Token != original.Baseline.Token {
		t.Fatal("public Cancel lost original native owner or restored reader", restored)
	}
	peer.observe(t, "release-benchmark")
	before = peer.observe(t, "stats")
	request = strings.Repeat("b", 32)
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
	var result struct {
		OK     bool   `json:"ok"`
		MTU    int    `json:"effective_mtu"`
		Source string `json:"effective_mtu_source"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &result) != nil || !result.OK || result.MTU < 1280 || result.Source != "auto-throughput-multihop-exit-path" {
		t.Fatal("actual ordered Retest did not adopt fresh final-path winner", status, err, string(raw))
	}
	view = macOSNodeChainNativeMTUStatus(t, ctx, client, request)
	adopted := macOSNodeChainNativeRead(t, ctx, client)
	after := peer.observe(t, "stats")
	if view.Status.Running || !view.Status.Complete || !view.Status.Measured || view.Status.Request != request || view.Status.EffectiveMTU != result.MTU ||
		adopted.MTUActive || !adopted.Connected || adopted.Session != original.Session || adopted.ProcessID != original.ProcessID || adopted.Transfer != original.Transfer || adopted.MTU.Reader <= restored.MTU.Reader || adopted.MTU.MTU != result.MTU || adopted.EffectiveMTU != result.MTU || adopted.Baseline.Token != original.Baseline.Token ||
		after.Benchmark.Replies <= before.Benchmark.Replies || after.Benchmark.SentBytes <= before.Benchmark.SentBytes || after.Benchmark.ReceivedBytes <= before.Benchmark.ReceivedBytes {
		t.Fatal("fresh Retest omitted actual transfer and original reader adoption", view, adopted, after)
	}
	for i, prefix := range after.Prefixes {
		if prefix.UDP <= before.Prefixes[i].UDP || prefix.RawUDP <= before.Prefixes[i].RawUDP {
			t.Fatal("MTU benchmark bypassed an original encrypted prefix", i)
		}
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/mtu/retest", makeBody(original.ViewSession, request))
	if err != nil || status != http.StatusConflict {
		t.Fatal("completed ordered MTU request was replayed", status, err, string(raw))
	}
	t.Log("actual sealed Darwin ordered MTU: Auto and Retest transferred final-only UDP, held Cancel joined exact rollback, original process PF and reader succession retained")
}
