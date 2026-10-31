package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// Public HTTP handlers, the catalog/strategy loops, compilation, private
// staging, real HTTP parsing, readiness and complete Stop/restore run here.
// Only native controller/package verification, process/BFE and the connection
// beneath the HTTP transport are modeled. No selector, health-result, startMode
// or restore callback is substituted. These are not native networking tests.
type desktopNodeConnectionFixture struct {
	a             *app
	profile       common.RouterProfile
	data          string
	packageDir    string
	kernel        *desktopNodeProtectionFixture
	lifetime      context.Context
	retire        context.CancelFunc
	releaseMTU    func()
	controller    atomic.Bool
	mu            sync.Mutex
	children      []*desktopNodeConnectionChild
	verifies      int
	failedMode    map[string]bool
	onStart       func(*desktopNodeConnectionChild)
	onHTTP        func(*desktopNodeConnectionChild)
	requests      atomic.Int32
	telemetryDone chan struct{}
}

type desktopNodeConnectionChild struct {
	fixture  *desktopNodeConnectionFixture
	launch   *desktopNodeLaunch
	target   desktopNodeHandoffRecord
	mu       sync.Mutex
	live     desktopNodeMTURecord
	closeErr error
	closed   bool
	closes   int
	cancel   chan struct{}
	exited   chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newDesktopNodeConnectionFixture(t *testing.T, policy, layer string) *desktopNodeConnectionFixture {
	t.Helper()
	root := t.TempDir()
	data, packageDir := filepath.Join(root, "Data"), filepath.Join(root, "App", "RouterVPN")
	profile, _ := desktopNodeFixture(t, "198.51.100.8")
	profile.KillSwitch, profile.KillSwitchPolicy, profile.StartLayer = policy != "off", policy, layer
	profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU = "auto", 0, 9000
	profile.PathProbeURL = profile.RouterAPI + "/health"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	f := &desktopNodeConnectionFixture{profile: profile, data: data, packageDir: packageDir,
		kernel: &desktopNodeProtectionFixture{}, failedMode: map[string]bool{}}
	f.lifetime, f.retire = context.WithCancel(context.Background())
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		_, files := viaEntryBaseFixture(t, mode)
		f.writeAssets(t, mode, files)
	}
	f.writeAssets(t, "shadowsocks", desktopOwnedNodePreparationAES(t, profile.Endpoint))
	hy2, _ := json.Marshal(map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": profile.Endpoint, "server_port": 8443,
			"password": "captured-hysteria-credential", "obfs": map[string]any{"type": "salamander", "password": "captured-hysteria-obfuscation"},
			"tls": map[string]any{"enabled": true, "server_name": "captured-node.test"}}},
		"route": map[string]any{"final": "proxy", "rules": []any{}},
	})
	f.writeAssets(t, "hysteria2", map[string][]byte{"sing-box.json": hy2})
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		f.writeAssets(t, mode, nativeMultihopProxyExitAssets(t, profile, mode))
	}
	nativeDir := filepath.Join(packageDir, "runtime", "native")
	if err := os.MkdirAll(nativeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativeDir, nativeBinaryName()), []byte("modeled native verification boundary\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// No receipt is created: a missing native receipt must never cause the
	// Windows selector to execute a catalog's legacy helper instead.
	var modes []common.Mode
	catalog, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil || json.Unmarshal(catalog, &modes) != nil {
		t.Fatal("could not read the actual complete runtime catalog", err)
	}
	f.a = &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(data, "routers.json"), AutoTestSeconds: 8,
		HealthURL: "http://10.88.0.1:8787/another-node", ScriptsDir: filepath.Join(packageDir, "modes")},
		modes: modes, state: state{Mode: "off", Phase: "off"},
		profiles:       common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		nodeProtection: &desktopNodeProtectionSlot{backend: f.kernel.backend()}}
	f.a.nodeConnectionHost = &desktopNodeConnectionHost{
		capture: func(a *app) (desktopOwnedNodePreparation, error) {
			if a != f.a {
				return desktopOwnedNodePreparation{}, errors.New("fixture controller belongs to another application")
			}
			return desktopOwnedNodePreparation{packageRoot: packageDir, dataRoot: data, lifetime: f.lifetime, current: func() error {
				if f.controller.Load() {
					return errors.New("captured controller was replaced")
				}
				return f.lifetime.Err()
			}}, nil
		},
		verify: func(ctx context.Context, path string) (string, error) {
			if ctx == nil || ctx.Err() != nil || path != packageDir {
				return "", errors.New("native verification changed its captured root or operation")
			}
			f.mu.Lock()
			f.verifies++
			f.mu.Unlock()
			return filepath.Join(nativeDir, nativeBinaryName()), nil
		},
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("literal captured endpoint unexpectedly required ambient DNS")
		},
		start: f.start,
	}
	t.Setenv("HOMEVPN_ROOT", data)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	if err := f.a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	tracker := &sessionTracker{a: f.a}
	sessionTrackers.Store(f.a, tracker)
	// Drive the production observation method on its normal cadence, with a
	// fixture-owned stop so this otherwise permanent app loop joins in tests.
	// Its session/proof fields come only from the real handler-owned state.
	f.telemetryDone = make(chan struct{})
	go func() {
		defer close(f.telemetryDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-f.lifetime.Done():
				return
			case <-ticker.C:
				tracker.observe(tracker.capture())
			}
		}
	}()
	// This real bounded hold isolates the separate automatic-MTU transaction;
	// child live records below still exercise actual capture/restore parsing.
	f.releaseMTU, err = f.a.holdCapturedMTU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.installHTTP(t)
	t.Cleanup(func() { f.close(t) })
	return f
}

func (f *desktopNodeConnectionFixture) writeAssets(t *testing.T, mode string, files map[string][]byte) {
	t.Helper()
	directory := filepath.Join(f.data, "generated", f.profile.ID, mode)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *desktopNodeConnectionFixture) start(ctx context.Context, a *app, launch *desktopNodeLaunch, arguments, environment []string, directory string) (desktopNodeProcess, error) {
	if a != f.a || ctx == nil || ctx.Err() != nil || directory != launch.directory || launch.command.Process != nil ||
		launch.ownedNode.host == nil || launch.ownedNode.host.capture.packageRoot != f.packageDir {
		return nil, errors.New("public native start changed its captured host")
	}
	want, err := desktopOwnedNodeArguments(launch)
	if err != nil || !reflect.DeepEqual(want, arguments) || !reflect.DeepEqual(environment, launch.command.Env) ||
		f.kernel.locked || !reflect.DeepEqual(launch.ownedNode.attempt.transfer.Predecessor, f.kernel.target) {
		return nil, errors.Join(err, errors.New("public native start lost its exact joined predecessor or command"))
	}
	for name, value := range map[string]string{"HOMEVPN_NATIVE_PACKAGE": f.packageDir, "HOMEVPN_ROOT": f.data, "HOMEVPN_ENDPOINT": ""} {
		matches := 0
		for _, entry := range environment {
			key, actual, _ := strings.Cut(entry, "=")
			if strings.EqualFold(key, name) {
				matches++
				if actual != value {
					return nil, errors.New("public native command borrowed a mutable package/data root")
				}
			}
		}
		if matches != 1 {
			return nil, errors.New("public native command repeated or lost its captured environment")
		}
	}
	child := &desktopNodeConnectionChild{fixture: f, launch: launch, target: desktopOwnedNodeTestHandoff(launch),
		cancel: make(chan struct{}), exited: make(chan struct{}), done: make(chan struct{})}
	raw, _ := json.Marshal(child.target)
	_, target, err := desktopNodeHandoff(raw, launch)
	if err != nil {
		return nil, err
	}
	f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&target), true
	meta := launch.ownedNode.policy.Metadata()
	capture, err := launch.ownedNode.policy.Capture()
	if err != nil {
		return nil, err
	}
	mtu := capture.ConfiguredMTU
	if meta.RestoredMTU != 0 {
		mtu = meta.RestoredMTU
	}
	ready := mobilemultihop.DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: launch.ownedNode.attempt.digest,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 71, MTU: mtu,
		ProvedAt: time.Now().UnixMilli(), DNSMilliseconds: 1.25}
	child.live = desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256,
		Path: strings.Repeat("f", 64), Reader: 1, Interface: "router-vpn", Index: 71, MTU: mtu, Heartbeat: time.Now().UnixMilli()}
	for name, value := range map[string]any{"node-physical-handoff-ready.json": child.target, "node-ready.json": ready, "node-mtu-status.json": child.live} {
		if err := child.publish(name, value); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	f.children = append(f.children, child)
	f.mu.Unlock()
	go child.serve()
	if f.onStart != nil {
		f.onStart(child)
	}
	return child, nil
}

func (child *desktopNodeConnectionChild) publish(name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	child.launch.workspaceMu.Lock()
	defer child.launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(child.launch); err != nil {
		return err
	}
	return atomicWritePrivate(filepath.Join(child.launch.directory, name), body)
}

func (child *desktopNodeConnectionChild) serve() {
	defer close(child.done)
	defer close(child.exited)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-child.cancel:
			return
		case <-ticker.C:
		}
		raw, err := readDesktopRuntimeFile(child.launch, "stop.json", 2048)
		if err == nil {
			var request desktopExternalStop
			if json.Unmarshal(raw, &request) != nil || request.Schema != 1 || request.SessionID != child.launch.mtuSession || request.SourceSHA256 != child.launch.configSHA256 || request.Closed {
				return
			}
			target := desktopNodeProtectionInstalled(child.launch.ownedNode.policy)
			if child.publish("node-protection-retired.json", desktopNodeProtectionRetired(child.launch.ownedNode.attempt, &target)) != nil {
				return
			}
			request.Closed = true
			_ = child.publish("stopped.json", request)
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			return
		}
		child.mu.Lock()
		child.live.Heartbeat = time.Now().UnixMilli()
		live := child.live
		child.mu.Unlock()
		if child.publish("node-mtu-status.json", live) != nil {
			return
		}
	}
}

func (*desktopNodeConnectionChild) Started() bool { return true }
func (child *desktopNodeConnectionChild) Alive() error {
	select {
	case <-child.exited:
		return errors.New("captured native child exited")
	default:
		return nil
	}
}
func (child *desktopNodeConnectionChild) Wait(ctx context.Context) (uint32, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-child.exited:
		return 0, nil
	}
}
func (child *desktopNodeConnectionChild) Close(ctx context.Context) error {
	child.mu.Lock()
	child.closes++
	err := child.closeErr
	closed := child.closed
	child.mu.Unlock()
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if closed {
		return nil
	}
	child.once.Do(func() { close(child.cancel) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-child.done:
	}
	expected := desktopNodeProtectionInstalled(child.launch.ownedNode.policy)
	if child.fixture.kernel.target == nil || *child.fixture.kernel.target != expected {
		return errors.New("captured native join cannot unlock a replacement target")
	}
	child.fixture.kernel.locked = false
	child.mu.Lock()
	child.closed = true
	child.mu.Unlock()
	return nil
}

func (f *desktopNodeConnectionFixture) installHTTP(t *testing.T) {
	t.Helper()
	prior := http.DefaultTransport
	transport := prior.(*http.Transport).Clone()
	var workers sync.WaitGroup
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx.Err() != nil || network != "tcp" || address != "10.77.0.1:8787" {
			return nil, fmt.Errorf("public proof changed its captured private destination: %s/%s", network, address)
		}
		client, server := net.Pipe()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			defer request.Body.Close()
			if request.URL.Path != "/health" {
				t.Error("public proof changed its retained private endpoint", request.URL)
				return
			}
			f.mu.Lock()
			child := f.children[len(f.children)-1]
			failed := f.failedMode[child.launch.mode]
			f.mu.Unlock()
			f.requests.Add(1)
			if f.onHTTP != nil {
				f.onHTTP(child)
			}
			node := f.profile.NodeProofID
			if failed {
				node = strings.Repeat("f", 64)
			}
			body, _ := json.Marshal(map[string]any{"ok": true, "node_id": node, "proof": desktopNodeProofKind})
			response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: true}
			_ = response.Write(server)
		}()
		return client, nil
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		workers.Wait()
		http.DefaultTransport = prior
	})
}

func (f *desktopNodeConnectionFixture) close(t *testing.T) {
	t.Helper()
	f.a.mu.Lock()
	f.a.closing = true
	f.a.mu.Unlock()
	f.retire()
	<-f.telemetryDone
	for _, child := range f.children {
		if err := stopDesktopOwnedNodeMonitor(context.Background(), child.launch); err != nil {
			t.Error(err)
		}
		child.mu.Lock()
		child.closeErr = nil
		child.mu.Unlock()
		if err := child.Close(context.Background()); err != nil {
			t.Error(err)
		}
		if child.launch.directoryRoot != nil {
			_ = child.launch.directoryRoot.Close()
		}
	}
	f.releaseMTU()
	desktopNodeOwners.Delete(f.a)
	sessionTrackers.Delete(f.a)
	strategyLocks.Delete(f.a)
	mtuSuspensions.Delete(f.a)
	routerNodeAutomaticMTUs.Delete(f.a)
	activeDNSRuntimeIdentities.Delete(f.a)
}

func TestDesktopNodePublicConnectUsesCapturedOwnedHost(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			label := layer
			if label == "" {
				label = "off"
			}
			t.Run(mode+"/"+label, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newDesktopNodeConnectionFixture(t, "always", layer)
					response := httptest.NewRecorder()
					f.a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"`+mode+`"}`)))
					if response.Code != http.StatusOK || !f.a.state.Connected || f.a.state.RuntimeMode != mode || len(f.children) != 1 || f.requests.Load() != 1 {
						t.Fatal("public Connect did not execute its captured owned native path", response.Code, response.Body.String(), len(f.children), f.requests.Load())
					}
					child := f.children[0]
					meta := child.launch.ownedNode.policy.Metadata()
					if meta.Mode != mode || meta.StartLayer != layer || meta.KillSwitchPolicy != "always" ||
						child.launch.command.Process != nil || child.launch.ownedNode.host == nil || f.kernel.prepared != 3 || f.verifies != 1 {
						t.Fatal("public Connect substituted its selected graph/layer/host or skipped native proof")
					}
					if f.a.connectionContext != nil || f.a.connectionCancel != nil || child.Alive() != nil {
						t.Fatal("completed HTTP operation retired the successfully connected native child")
					}
					capabilities := f.capabilities(t)
					activeLayer := layer != ""
					if capabilities.EffectiveLayer != label || capabilities.Runtime != mode || !capabilities.Supported || capabilities.Active != activeLayer {
						t.Fatal("public capability response lost its captured native graph or Start Layer", capabilities)
					}
				})
			})
		}
	}
}

type desktopNodePublicCapabilities struct {
	Selected       string   `json:"selected_profile_id"`
	Effective      string   `json:"effective_profile_id"`
	EffectiveLayer string   `json:"effective_start_layer"`
	Runtime        string   `json:"current_runtime_mode"`
	Supported      bool     `json:"current_runtime_supported"`
	Active         bool     `json:"current_runtime_layer_active"`
	Reason         string   `json:"current_runtime_reason"`
	Modes          []string `json:"supported_raw_modes"`
}

func (f *desktopNodeConnectionFixture) capabilities(t *testing.T) desktopNodePublicCapabilities {
	t.Helper()
	response := httptest.NewRecorder()
	f.a.startLayerCapabilities(response, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	var result desktopNodePublicCapabilities
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatal("could not read actual public Start Layer capabilities", response.Code, response.Body.String())
	}
	return result
}

func TestDesktopNodePublicCapabilitiesRequireCapturedReadiness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "aes-256-gcm+xor-whitening")
		response := httptest.NewRecorder()
		f.a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
		if response.Code != http.StatusOK || len(f.children) != 1 {
			t.Fatal("fixture public connection failed", response.Code, response.Body.String())
		}
		other := cloneRouterProfile(f.profile)
		other.ID, other.StartLayer = "another-saved-node", common.StartLayerOff
		f.a.mu.Lock()
		f.a.profiles.Profiles = append(f.a.profiles.Profiles, other)
		f.a.profiles.SelectedID = other.ID
		f.a.mu.Unlock()
		current := f.capabilities(t)
		if current.Selected != other.ID || current.Effective != f.profile.ID || current.EffectiveLayer != common.StartLayerAES256GCMXOR || !current.Active {
			t.Fatal("public capabilities replaced active captured Start Layer with mutable selection", current)
		}
		foundWG := false
		for _, mode := range current.Modes {
			foundWG = foundWG || mode == "wg"
			if !mobilemultihop.DesktopNodePhysicalGraphSupported(mode, common.StartLayerAES256GCMXOR) {
				t.Fatal("public capabilities advertised an unadmitted protected graph", mode)
			}
		}
		if !foundWG {
			t.Fatal("public capabilities searched Data instead of its captured native App", current)
		}
		if err := os.Remove(filepath.Join(f.children[0].launch.directory, "node-ready.json")); err != nil {
			t.Fatal(err)
		}
		unproved := f.capabilities(t)
		if unproved.Active || unproved.Reason == "" || unproved.EffectiveLayer != common.StartLayerAES256GCMXOR {
			t.Fatal("public capabilities called an unproved native Start Layer active", unproved)
		}
	})
}

func TestDesktopNodePublicAutoRetainsCatalogAndExactPredecessor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "")
		catalog, _ := json.Marshal(f.a.modes)
		f.failedMode["wg"] = true
		response := httptest.NewRecorder()
		f.a.strategyAuto(response, httptest.NewRequest(http.MethodPost, "/api/strategy/auto", nil))
		var result strategyResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.OK ||
			result.RuntimeMode != "awg2-fast" || result.LogicalMode != "auto" || !f.a.state.Connected ||
			f.a.state.LogicalMode != "auto" || len(f.children) != 2 || len(result.Attempts) != 2 {
			t.Fatal("public AUTO did not advance through real owned candidate proof", response.Code, response.Body.String(), len(f.children))
		}
		first, winner := f.children[0], f.children[1]
		first.mu.Lock()
		joined := first.closed
		first.mu.Unlock()
		prior := desktopNodeProtectionInstalled(first.launch.ownedNode.policy)
		if !joined || winner.Alive() != nil || first.launch.mode != "wg" || winner.launch.mode != "awg2-fast" ||
			winner.launch.ownedNode.attempt.transfer.Predecessor == nil || *winner.launch.ownedNode.attempt.transfer.Predecessor != prior ||
			f.a.nodeProtection.active != winner.launch.ownedNode.attempt || f.kernel.releases != 0 {
			t.Fatal("public AUTO bypassed the joined failed path or erased its retained Always protection")
		}
		after, _ := json.Marshal(f.a.modes)
		if !bytes.Equal(catalog, after) || len(f.a.modes) != 22 || result.Attempts[0].Success || !result.Attempts[1].Success {
			t.Fatal("public AUTO changed the complete catalog or fabricated failed candidate success")
		}
	})
}

func TestDesktopNodePublicSmartRestoresCapturedSourceAndLiveMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "aes-256-gcm+xor-whitening")
		catalog, _ := json.Marshal(f.a.modes)
		for _, mode := range []string{"wg", "awg2-fast", "shadowsocks"} {
			f.failedMode[mode] = true
		}
		var firstGood *desktopNodeConnectionChild
		var source []byte
		corrupted := false
		f.onStart = func(child *desktopNodeConnectionChild) {
			if child.launch.mode == "awg2-strong" && firstGood == nil {
				firstGood = child
				source = append([]byte(nil), child.launch.ownedNode.source...)
			}
			if child.launch.mode == "awg2-fast" && firstGood != nil {
				// The simplification has already captured its last proved graph.
				// Replacing saved assets cannot rewrite that restoration source.
				for _, mode := range []string{"awg2-strong", "wg"} {
					name := "wg.conf"
					if mode == "awg2-strong" {
						name = "awg.conf"
					}
					if err := os.WriteFile(filepath.Join(f.data, "generated", f.profile.ID, mode, name), []byte("replacement private bundle\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				corrupted = true
			}
		}
		f.onHTTP = func(child *desktopNodeConnectionChild) {
			if child.launch.mode != "awg2-strong" || child.launch.ownedNode.policy.Metadata().RestoredMTU != 0 {
				return
			}
			child.mu.Lock()
			child.live.Reader, child.live.Index, child.live.MTU = 2, 72, 1392
			child.live.Heartbeat = time.Now().UnixMilli()
			live := child.live
			child.mu.Unlock()
			if err := child.publish("node-mtu-status.json", live); err != nil {
				t.Error("fixture could not publish its current native TUN reading", err)
			}
		}
		response := httptest.NewRecorder()
		f.a.strategySmartAuto(response, httptest.NewRequest(http.MethodPost, "/api/strategy/smart-auto", nil))
		var result strategyResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.OK ||
			result.RuntimeMode != "awg2-strong" || result.RestoredMode != "awg2-strong" || !f.a.state.Connected ||
			f.a.state.LogicalMode != "smart-auto" || !corrupted || firstGood == nil || len(f.children) != 6 {
			t.Fatal("public SMART did not restore its proved captured graph after an actual failed trial", response.Code, response.Body.String(), len(f.children))
		}
		winner, trial := f.children[len(f.children)-1], f.children[len(f.children)-2]
		previous := desktopNodeProtectionInstalled(trial.launch.ownedNode.policy)
		if winner == firstGood || winner.Alive() != nil || winner.launch.mode != "awg2-strong" ||
			winner.launch.ownedNode.policy.Metadata().RestoredMTU != 1392 || !bytes.Equal(winner.launch.ownedNode.source, source) ||
			winner.launch.ownedNode.host != firstGood.launch.ownedNode.host ||
			winner.launch.ownedNode.attempt.transfer.Predecessor == nil || *winner.launch.ownedNode.attempt.transfer.Predecessor != previous ||
			f.a.nodeProtection.active != winner.launch.ownedNode.attempt {
			t.Fatal("public SMART restored changed assets, stale MTU, another host or the original obsolete protection target")
		}
		restored, retained, rejectedPQ := false, false, false
		for _, attempt := range result.Attempts {
			restored = restored || attempt.Mode == "awg2-strong" && attempt.Action == "restore" && attempt.Success
			retained = retained || attempt.Mode == "awg2-strong" && attempt.Action == "retain" && attempt.Success
			rejectedPQ = rejectedPQ || attempt.Mode == "wg-pq" && attempt.Action == "candidate" && !attempt.Success
		}
		after, _ := json.Marshal(f.a.modes)
		if !restored || !retained || !rejectedPQ || !bytes.Equal(catalog, after) || f.kernel.releases != 0 {
			t.Fatal("public SMART omitted a required catalog candidate or stopped its proved winner on unsupported preflight", result.Attempts)
		}
	})
}

func TestDesktopNodePublicSpeedLabCancellationRestoresExactWinner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "aes-256-gcm")
		f.onHTTP = func(child *desktopNodeConnectionChild) {
			if child.launch.mode != "wg" || child.launch.ownedNode.policy.Metadata().RestoredMTU != 0 {
				return
			}
			child.mu.Lock()
			child.live.Reader, child.live.Index, child.live.MTU = 2, 72, 1392
			child.live.Heartbeat = time.Now().UnixMilli()
			live := child.live
			child.mu.Unlock()
			if err := child.publish("node-mtu-status.json", live); err != nil {
				t.Error(err)
			}
		}
		connected := httptest.NewRecorder()
		f.a.strategyAuto(connected, httptest.NewRequest(http.MethodPost, "/api/strategy/auto", nil))
		if connected.Code != http.StatusOK || !f.a.state.Connected || f.a.state.RuntimeMode != "wg" || len(f.children) != 1 {
			t.Fatal("could not establish the public AUTO winner", connected.Code, connected.Body.String())
		}
		prior := f.children[0]
		for deadline := time.Now().Add(time.Second); ; {
			if _, _, err := captureSpeedLabIdentity(f.a); err == nil {
				break
			} else if !time.Now().Before(deadline) {
				t.Fatal("actual session observation did not capture the public winner", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		source := append([]byte(nil), prior.launch.ownedNode.source...)
		privateBefore, err := os.ReadFile(f.a.cfg.ProfilesFile)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancelRequest := context.WithCancel(context.Background())
		defer cancelRequest()
		f.onStart = func(child *desktopNodeConnectionChild) {
			if child.launch.mode == "hysteria2" {
				if err := os.WriteFile(filepath.Join(f.data, "generated", f.profile.ID, "wg", "wg.conf"), []byte("replacement private bundle\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		f.onHTTP = func(child *desktopNodeConnectionChild) {
			if child.launch.mode == "hysteria2" {
				cancelRequest() // cancels the test, while its restore intent survives
			}
		}
		request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(
			`{"scope":"temporary","topology":"router","node_id":"`+f.profile.ID+`","mode":"hysteria2","duration_mode":"custom","min_seconds":1,"max_seconds":1}`)).WithContext(ctx)
		response := httptest.NewRecorder()
		f.a.speedLabRun(response, request)
		if response.Code != http.StatusConflict || ctx.Err() == nil || !f.a.state.Connected || f.a.state.Phase != "connected" ||
			f.a.state.RuntimeMode != "wg" || f.a.state.LogicalMode != "auto" || len(f.children) != 3 {
			t.Fatal("public Speed Lab cancellation did not restore its already-proved winner", response.Code, response.Body.String(), len(f.children), f.a.state)
		}
		trial, restored := f.children[1], f.children[2]
		expected := desktopNodeProtectionInstalled(trial.launch.ownedNode.policy)
		if restored.launch.ownedNode.policy.Metadata().RestoredMTU != 1392 || restored.launch.ownedNode.host != prior.launch.ownedNode.host ||
			!bytes.Equal(restored.launch.ownedNode.source, source) || restored.launch.ownedNode.attempt.transfer.Predecessor == nil ||
			*restored.launch.ownedNode.attempt.transfer.Predecessor != expected || restored.Alive() != nil || f.requests.Load() != 3 {
			t.Fatal("Speed Lab reran selection or replaced the captured source, live MTU, host or latest protection predecessor")
		}
		privateAfter, err := os.ReadFile(f.a.cfg.ProfilesFile)
		if err != nil || !bytes.Equal(privateBefore, privateAfter) || f.a.connectionContext != nil || f.a.connectionCancel != nil {
			t.Fatal("temporary public test changed saved profile state or retained its cancelled operation", err)
		}
		if _, exists := speedLabTemporaryOwners.Load(f.a); exists {
			t.Fatal("completed Speed Lab restore retained a stale transaction owner")
		}
	})
}

func TestDesktopNodePublicConnectRejectsReplacedRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "")
		replacement, cancelReplacement := context.WithCancel(context.Background())
		defer cancelReplacement()
		f.onStart = func(*desktopNodeConnectionChild) {
			f.a.mu.Lock()
			f.a.connectionContext, f.a.connectionCancel = replacement, cancelReplacement
			f.a.state.Phase, f.a.state.LastError = "replacement-request", "replacement operation owns its state"
			f.a.mu.Unlock()
		}
		response := httptest.NewRecorder()
		f.a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
		if response.Code != http.StatusConflict || f.a.state.Connected || f.a.state.Phase != "replacement-request" ||
			f.a.state.LastError != "replacement operation owns its state" || f.a.connectionContext != replacement || replacement.Err() != nil ||
			f.requests.Load() != 0 || f.kernel.prepared != 0 {
			t.Fatal("public Connect adopted or mutated a replacement request from an old native completion", response.Code, response.Body.String(), f.a.state, f.requests.Load(), f.kernel.prepared)
		}
	})
}

func TestDesktopNodePublicConnectCancellationAndProofReplacement(t *testing.T) {
	for _, change := range []string{"cancel-at-start", "request-during-proof", "runtime-during-proof", "native-owner-during-proof"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopNodeConnectionFixture(t, "always", "")
				replacementContext, cancel := context.WithCancel(context.Background())
				defer cancel()
				replacement := &desktopNodeLaunch{command: exec.Command("captured-replacement")}
				if change == "cancel-at-start" {
					f.onStart = func(*desktopNodeConnectionChild) { f.a.cancelConnectionOperation() }
				} else {
					f.onHTTP = func(child *desktopNodeConnectionChild) {
						f.a.mu.Lock()
						f.a.state.Phase, f.a.state.LastError = "replacement-pending", "replacement retained"
						if change == "request-during-proof" {
							f.a.connectionContext = replacementContext
						} else {
							if change == "native-owner-during-proof" {
								replacement.command = child.launch.command
							}
							f.a.cmd = replacement.command
							desktopNodeOwners.Store(f.a, replacement)
						}
						f.a.mu.Unlock()
					}
				}
				response := httptest.NewRecorder()
				f.a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
				if response.Code < 400 || len(f.children) != 1 || f.a.state.Connected {
					t.Fatal("public Connect accepted a cancelled or replaced native operation", response.Code, response.Body.String())
				}
				child := f.children[0]
				if change == "cancel-at-start" {
					child.mu.Lock()
					joined := child.closed
					child.mu.Unlock()
					if !joined || f.a.cmd != nil || f.a.nodeProtection.active != nil || f.kernel.locked || f.kernel.target == nil ||
						f.requests.Load() != 0 || f.kernel.prepared != 0 {
						t.Fatal("cancelled public Connect failed to join its exact child while retaining Always protection", response.Code, response.Body.String())
					}
				} else {
					if f.a.state.Phase != "replacement-pending" || f.a.state.LastError != "replacement retained" || f.requests.Load() != 1 {
						t.Fatal("old public proof overwrote replacement presentation", response.Code, response.Body.String(), f.a.state)
					}
					if change == "request-during-proof" && (f.a.connectionContext != replacementContext || replacementContext.Err() != nil) {
						t.Fatal("old public proof finished or cancelled a replacement request")
					}
					if change == "runtime-during-proof" || change == "native-owner-during-proof" {
						current, _ := desktopNodeOwners.Load(f.a)
						if f.a.cmd != replacement.command || current != replacement {
							t.Fatal("old public proof replaced the current command or native owner")
						}
					}
				}
			})
		})
	}
}

func TestDesktopNodePublicDisconnectAndOffRetainUnjoinedOwners(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "always", "")
		off := &desktopProtectionOffFixture{a: f.a, slot: f.a.nodeProtection, kernel: f.kernel, profile: f.profile}
		f.a.nodeProtection.backend.recover = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
			off.calls++
			if ctx.Err() != nil || f.kernel.locked || f.kernel.target == nil || *f.kernel.target != target {
				return nil, errors.New("public explicit Off lost its exact joined native target")
			}
			owner := &desktopProtectionOffFixtureOwner{fixture: off, target: target, armed: true}
			off.owners = append(off.owners, owner)
			f.kernel.locked = true
			return owner, nil
		}
		connected := httptest.NewRecorder()
		f.a.connect(connected, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
		if connected.Code != http.StatusOK || len(f.children) != 1 {
			t.Fatal("fixture public connection failed", connected.Code, connected.Body.String())
		}
		child := f.children[0]
		source := append([]byte(nil), child.launch.ownedNode.source...)
		child.mu.Lock()
		child.closeErr = errors.New("fixture retained native Job has not joined")
		child.mu.Unlock()
		failed := httptest.NewRecorder()
		f.a.disconnect(failed, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
		retained, retainedOK := desktopNodeOwners.Load(f.a)
		if failed.Code < 400 || !retainedOK || retained != child.launch || f.a.cmd != nil && f.a.cmd != child.launch.command ||
			f.a.nodeProtection.active != child.launch.ownedNode.attempt || f.a.state.Phase != "failed" ||
			f.kernel.target == nil || !f.kernel.locked || !bytes.Equal(child.launch.ownedNode.source, source) {
			t.Fatal("public Disconnect discarded a failed native join or its private recovery source", failed.Code, failed.Body.String())
		}
		if _, err := os.Stat(child.launch.directory); err != nil {
			t.Fatal("failed native close removed its owned runtime workspace", err)
		}
		child.mu.Lock()
		child.closeErr = nil
		child.mu.Unlock()
		joined := httptest.NewRecorder()
		f.a.disconnect(joined, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
		if joined.Code != http.StatusOK || f.a.cmd != nil || f.a.nodeProtection.active != nil || f.kernel.locked || f.kernel.target == nil ||
			f.a.guardDesktopOwnedNodeTransition(&desktopNodeLaunch{}) == nil {
			t.Fatal("joined public Disconnect erased Always protection or admitted an ordinary successor", joined.Code, joined.Body.String())
		}
		value := httptest.NewRecorder()
		f.a.profileProtectionSettings(value, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
		var captured profileProtectionSettings
		if value.Code != http.StatusOK || json.Unmarshal(value.Body.Bytes(), &captured) != nil || captured.ProfileToken == "" {
			t.Fatal("could not capture actual public protection revision", value.Body.String())
		}
		postOff := func(token string) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]string{"profile_id": f.profile.ID, "profile_token": token, "kill_switch_policy": "off"})
			response := httptest.NewRecorder()
			f.a.profileProtectionSettings(response, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)))
			return response
		}
		off.closeFail = true
		pending := postOff(captured.ProfileToken)
		if pending.Code != http.StatusServiceUnavailable || f.a.nodeProtection == nil || f.a.nodeProtection.pendingOff() == nil ||
			f.kernel.target == nil || !f.kernel.locked || desktopOwnedNodeProtectionPolicy(f.a.profiles.Profiles[0]) != "always" || off.calls != 1 {
			t.Fatal("public Off published a preference before the original native removal owner joined", pending.Code, pending.Body.String())
		}
		blocked := httptest.NewRecorder()
		f.a.connect(blocked, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
		if blocked.Code != http.StatusConflict || len(f.children) != 1 || f.a.state.Connected {
			t.Fatal("public Connect escaped the pending explicit Off transaction", blocked.Code, blocked.Body.String())
		}
		var retry profileProtectionSettings
		if json.Unmarshal(pending.Body.Bytes(), &retry) != nil || retry.ProfileToken == "" {
			t.Fatal("failed Off lost its reviewable exact retry token")
		}
		off.closeFail = false
		finished := postOff(retry.ProfileToken)
		if finished.Code != http.StatusOK || f.a.nodeProtection != nil || f.kernel.target != nil || f.kernel.locked || off.calls != 1 ||
			desktopOwnedNodeProtectionPolicy(f.a.profiles.Profiles[0]) != "off" || f.a.guardDesktopOwnedNodeTransition(&desktopNodeLaunch{}) != nil {
			t.Fatal("exact public Off retry did not finish native absence before ordinary admission", finished.Code, finished.Body.String())
		}
		var saved common.RouterProfileStore
		body, err := os.ReadFile(f.a.cfg.ProfilesFile)
		if err != nil || json.Unmarshal(body, &saved) != nil || len(saved.Profiles) != 1 || desktopOwnedNodeProtectionPolicy(saved.Profiles[0]) != "off" {
			t.Fatal("public Off did not acknowledge its actual private saved result", err)
		}
	})
}

func TestDesktopNodeOrdinaryPublicationFixture(t *testing.T) {
	const marker = "--routervpn-ordinary-publication-fixture"
	for index, value := range os.Args {
		if value != marker {
			continue
		}
		if index+3 != len(os.Args) || os.Args[index+1] != "started" && os.Args[index+1] != "cleanup" {
			t.Fatal("ordinary publication fixture received an invalid captured command")
		}
		if os.Args[index+1] == "cleanup" && os.Getenv(killSwitchHoldEnv) != "1" {
			t.Fatal("ordinary cleanup lost its captured hold intent")
		}
		if err := os.WriteFile(os.Args[index+2], []byte(os.Args[index+1]), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
}

func TestDesktopNodePublicOrdinaryCancellationRetainsCapturedCleanup(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	directory := t.TempDir()
	startPath, stopPath := filepath.Join(directory, "entered"), filepath.Join(directory, "cleaned")
	arguments := []string{"-test.run=^TestDesktopNodeOrdinaryPublicationFixture$", "-test.count=1", "--", "--routervpn-ordinary-publication-fixture"}
	command := exec.Command(os.Args[0], append(append([]string(nil), arguments...), "started", startPath)...)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if body, err := os.ReadFile(startPath); err == nil && string(body) == "started" {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("actual ordinary fixture child did not enter its captured command")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const mode = "ordinary-fixture"
	a := &app{connectionContext: ctx, connectionCancel: cancel, state: state{Mode: "off", Phase: "requested"},
		modes: []common.Mode{{ID: mode, StopCommand: append([]string{os.Args[0]}, append(append([]string(nil), arguments...), "cleanup", stopPath)...)}}}
	a.cfg.ScriptsDir = directory
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	cancel()
	err := a.publishStartedDesktopNode(ctx, nil, command, "captured-node", mode, "starting", "")
	if !errors.Is(err, errConnectionOperationCancelled) || a.cmd != command || a.state.Mode != mode || a.state.Phase != "stopping" || a.state.Connected {
		t.Fatal("cancelled ordinary publication lost its exact mode cleanup identity or acknowledged a connection", err, a.state)
	}
	if err := a.stopModeWithIntent(true); err != nil {
		t.Fatal("actual ordinary Stop did not complete its captured cleanup", err)
	}
	body, err := os.ReadFile(stopPath)
	if err != nil || string(body) != "cleanup" || a.cmd != nil || a.state.Phase != "off" {
		t.Fatal("cancelled ordinary start skipped its actual mode teardown", err, a.state)
	}
}
