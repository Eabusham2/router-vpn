//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

const macOSPairedNodeNativeMarker = "fixture-paired-node-host"
const macOSPairedNodeNativeAuthority = "explicit disposable macOS paired Router PF and TUN fixture\n"

func macOSPairedNodeNativeCases() []string {
	var result []string
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "ss-v2ray"} {
		for _, layer := range []string{"off", common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			for _, policy := range []string{"off", "on-connect", "always"} {
				result = append(result, strings.Join([]string{mode, layer, policy, "connect"}, "/"))
			}
		}
	}
	for _, policy := range []string{"off", "on-connect", "always"} {
		for _, action := range []string{"home-lan-wrong-node", "resolver-failure", "wrong-key", "restore-sealed", "mtu-rollback"} {
			result = append(result, strings.Join([]string{"shadowsocks", "off", policy, action}, "/"))
		}
	}
	return result
}
func macOSPairedNodeCaseBudget(scenario string) time.Duration {
	if macOSPairedNodeAction(scenario) == "mtu-rollback" {
		return 240 * time.Second
	}
	return 105 * time.Second
}
func macOSPairedNodeNativeCaseValid(scenario string) bool {
	for _, candidate := range append(macOSPairedNodeNativeCases(), macOSPairedNaiveH2NativeCases()...) {
		if scenario == candidate {
			return true
		}
	}
	return false
}

type macOSPairedNodeNativeResult struct {
	Connected, Closed, NativeJoined, WorkspaceRetired, MTUActive   bool
	ViewSession, Profile, EffectiveSource                          string
	EffectiveMTU                                                   int
	ProcessID                                                      int
	Session, Source, Config, Transfer, Mode, Layer, Policy, NodeID string
	Ready                                                          *mobilemultihop.DesktopNodeReadyRecord
	MTU                                                            desktopNodeMTURecord
	Baseline                                                       *desktopMacOSNodeReceipt
}

func macOSPairedNodeNativeObserve(ctx context.Context, h *desktopMacOSPairedNodeHost) (macOSPairedNodeNativeResult, error) {
	var out macOSPairedNodeNativeResult
	if h == nil {
		return out, errors.New("paired native observation has no original host")
	}
	if err := h.enter(ctx); err != nil {
		return out, err
	}
	defer func() { h.gate <- struct{}{} }()
	out = macOSPairedNodeNativeResult{Closed: h.closed, NativeJoined: h.nativeRetired, WorkspaceRetired: h.workspaceRetired, Session: h.selection.Session, Source: h.selection.Source, Config: h.selection.Config, Transfer: h.transfer, Mode: h.selection.Mode, Layer: h.selection.StartLayer, Policy: h.selection.Policy, NodeID: h.selection.NodeID}
	if h.baseline != nil {
		copy := *h.baseline
		out.Baseline = &copy
	}
	if h.ready != nil {
		copy := *h.ready
		out.Ready = &copy
	}
	if h.process != nil && h.process.command != nil && h.process.command.Process != nil {
		out.ProcessID = h.process.command.Process.Pid
	}
	if h.closed {
		return out, h.parent.cleanupCurrent(ctx)
	}
	if err := h.current(ctx, true); err != nil {
		return out, err
	}
	_, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return out, err
	}
	out.MTU = live
	out.MTUActive = h.mtu != nil || live.Active
	out.Profile = h.launch.profileID
	h.parent.app.mu.Lock()
	out.Connected = h.parent.app.state.Connected && h.activated && h.proved
	if profile, found := h.parent.app.profileByIDLocked(out.Profile); found {
		out.EffectiveMTU, out.EffectiveSource = profile.EffectiveMTU, profile.EffectiveMTUSource
	}
	h.parent.app.mu.Unlock()
	out.ViewSession = sessionTrackerFor(h.parent.app).snapshot(0).ID
	return out, nil
}

// Test-only observation role inside the actual installed supervisor/controller.
// Public Connect/Disconnect and native ownership are the shipping implementation.
func macOSPairedNodeNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSPairedNodeNativeMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || string(raw) != macOSPairedNodeNativeAuthority {
		return true, errors.New("paired native test has no original disposable authority")
	}
	raw, err = readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, "fixture-paired-node-case"), 256)
	scenario := strings.TrimSpace(string(raw))
	if err != nil || !macOSPairedNodeNativeCaseValid(scenario) {
		return true, errors.New("paired native test changed finite source case")
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress, ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(macOSOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(macOSOwnedControllerRoot, "modes"), StateFile: filepath.Join(macOSOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != 1 || a.profiles.SelectedID != "installed-macos-paired-node" || a.profiles.Profiles[0].ID != a.profiles.SelectedID {
		return true, errors.New("paired native test lost original saved profile")
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return true, errors.New("paired native test lost actual shipping mode catalog")
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	var mu sync.Mutex
	var original *desktopMacOSPairedNodeHost
	capture := func() error {
		raw, ok := desktopNodeOwners.Load(a)
		if !ok {
			return nil
		}
		launch, ok := raw.(*desktopNodeLaunch)
		if !ok || launch == nil {
			return errors.New("native paired registry is untyped")
		}
		h, ok := launch.pairedNode.(*desktopMacOSPairedNodeHost)
		if !ok || h == nil || h.launch != launch || h.parent.parent != captured.parent || h.parent.session != captured.session {
			return errors.New("native paired host changed original parent")
		}
		original = h
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/connect", a.connect)
	mux.HandleFunc("/api/disconnect", a.disconnect)
	registerMTURetestRoute(mux, a)
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original parent retired", http.StatusConflict)
			return
		}
		a.mu.Lock()
		value := a.state
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.HandleFunc("/api/native-paired-observation", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := capture(); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		value, err := macOSPairedNodeNativeObserve(r.Context(), original)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.HandleFunc("/api/native-paired-failed-cleanup", func(w http.ResponseWriter, r *http.Request) {
		if macOSPairedNodeScenario(scenario).Policy != "always" ||
			(!pairedNaiveH2WrongKeyAction(macOSPairedNodeAction(scenario)) && macOSPairedNodeAction(scenario) != "resolver-failure" && macOSPairedNodeAction(scenario) != "home-lan-wrong-node") {
			http.Error(w, "not an original failed Always case", 409)
			return
		}
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original parent retired", 409)
			return
		}
		a.mu.Lock()
		inactive := !a.state.Connected && a.cmd == nil
		a.mu.Unlock()
		if _, exists := desktopNodeOwners.Load(a); exists || !inactive {
			http.Error(w, "original native owner not retired", 409)
			return
		}
		journal, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, "run", "kill-switch.json"), 1<<20)
		var fields map[string]json.RawMessage
		var selection desktopMacOSNodeSelection
		if err != nil || json.Unmarshal(journal, &fields) != nil || decodeRelayControlJSON(fields["native_node_capture"], &selection) != nil || !selection.valid() ||
			selection.ProfileID != a.profiles.SelectedID || selection.Policy != "always" || selection.NodeID != a.profiles.Profiles[0].NodeProofID || selection.Mode != macOSPairedNodeMode(scenario) {
			http.Error(w, "failed cleanup lost its original journal capture", 409)
			return
		}
		receipt, err := runDesktopMacOSNodeBaseline(r.Context(), captured, selection, "release", nil, nil)
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		_ = json.NewEncoder(w).Encode(macOSPairedNodeNativeResult{Closed: true, NativeJoined: true, Policy: selection.Policy, Baseline: receipt})
	})
	mux.HandleFunc("/api/native-paired-restore", func(w http.ResponseWriter, r *http.Request) {
		operation, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		defer finish()
		if snapshot.Plan.pairedNode == nil || snapshot.Plan.native != nil || snapshot.Plan.linux != nil {
			http.Error(w, "Speed Lab did not retain exact paired original source", 409)
			return
		}
		if err := a.speedLabSuspendPrevious(snapshot, false); err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		// Retire only this disposable test's generated copies. Successful restart
		// must replay the original sealed memory and original retained parent.
		if err := os.RemoveAll(filepath.Join(macOSOwnedControllerRoot, "generated", snapshot.State.RouterID)); err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		snapshot.Owner.cancelTest()
		if operation.Err() == nil {
			http.Error(w, "test cancellation did not retire original operation", 409)
			return
		}
		if err := a.speedLabRestoreTemporary(snapshot); err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

func macOSPairedNodeNativeAlias(t *testing.T) {
	t.Helper()
	device, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := device.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if strings.HasPrefix(address.String(), "10.77.0.1/") {
			t.Fatal("paired fixture cannot adopt existing health alias")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := macOSExternalNativeCommand(ctx, "/sbin/ifconfig", "lo0", "inet", "10.77.0.1", "netmask", "255.255.255.255", "alias"); err != nil {
		t.Fatal(err, string(output))
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if output, err := macOSExternalNativeCommand(ctx, "/sbin/ifconfig", "lo0", "inet", "10.77.0.1", "-alias"); err != nil {
			t.Error(err, string(output))
		}
	})
}
func macOSPairedNodeNativeRead(t *testing.T, ctx context.Context, client *http.Client) macOSPairedNodeNativeResult {
	t.Helper()
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-paired-observation", "")
	var value macOSPairedNodeNativeResult
	if err != nil || status != 200 || json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual paired host observation unavailable", status, err, string(raw))
	}
	return value
}

func TestMacOSRetainedPairedNodeNativePublicGraphs(t *testing.T) {
	for _, scenario := range macOSPairedNodeNativeCases() {
		t.Run(scenario, func(t *testing.T) { macOSPairedNodeNativeCaseRun(t, scenario) })
	}
}
func macOSPairedNodeNativeCaseRun(t *testing.T, scenario string) {
	t.Helper()
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	macOSPairedNodeNativeAlias(t)
	peer := macOSPairedNodeStartPeer(t, scenario)
	macOSPairedNodeInstallProfile(t, peer, scenario)
	for name, body := range map[string]string{macOSPairedNodeNativeMarker: macOSPairedNodeNativeAuthority, "fixture-paired-node-case": scenario + "\n"} {
		if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := macOSPairedNodeScenario(scenario)
	if c.Action == "home-lan-wrong-node" {
		peer.observe(t, "wrong-node")
		macOSPairedNodeDirectHealth(t, peer)
	}
	if c.Action == "resolver-failure" {
		peer.observe(t, "fail-dns")
	}
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 150 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), macOSPairedNodeCaseBudget(scenario)-5*time.Second)
	defer cancel()
	joined := false
	t.Cleanup(func() {
		if !joined {
			cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
			defer stop()
			_, _, _ = macOSExternalNativeHTTP(cleanup, client, http.MethodPost, "/api/disconnect", "{}")
			if err := connection.CloseWrite(); err != nil {
				t.Error(err)
				return
			}
			receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
			if receipt.ExitCode != 0 {
				t.Error("paired native controller failed original join", receipt.ExitCode)
			}
			joined = true
		}
	})
	macOSControllerNativeAwait(t, func() bool {
		probe, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		status, _, err := macOSExternalNativeHTTP(probe, client, http.MethodGet, "/api/status", "")
		return err == nil && status == 200
	}, "actual paired controller did not expose original public route")
	before := macOSExternalNativeTunnels(t)
	prior := peer.observe(t, "stats")
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/connect", `{"mode":"`+c.Mode+`"}`)
	negative := pairedNaiveH2WrongKeyAction(c.Action) || c.Action == "resolver-failure" || c.Action == "home-lan-wrong-node"
	if negative {
		if err != nil || status != http.StatusServiceUnavailable {
			t.Fatal("native negative did not execute actual public refusal", status, err, string(raw))
		}
		code, body, e := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var state state
		if e != nil || code != 200 || json.Unmarshal(body, &state) != nil || state.Connected {
			t.Fatal("failed private native path acquired Connected", e, string(body))
		}
		after := peer.observe(t, "stats")
		if c.Mode == "naive-h2" && pairedNaiveH2WrongKeyAction(c.Action) && !macOSPairedNaiveH2Rejected(c.Action, after) {
			t.Fatal("Naive H2 negative bypassed its actual captured authentication/TLS boundary", after)
		}
		if c.Action == "home-lan-wrong-node" && (after.DirectQueries != prior.DirectQueries || after.RouterQueries <= prior.RouterQueries) {
			t.Fatal("bound refusal used direct Home LAN proof or never queried encrypted original", prior, after)
		}
		if !maps.Equal(before, macOSExternalNativeTunnels(t)) {
			t.Fatal("failed native start did not retire original utun")
		}
		if c.Policy == "always" {
			code, body, e := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-paired-failed-cleanup", "{}")
			var retired macOSPairedNodeNativeResult
			if e != nil || code != 200 || json.Unmarshal(body, &retired) != nil {
				t.Fatal("failed Always original cleanup unreadable", code, e, string(body))
			}
			macOSPairedNodeNativeClearAlways(t, ctx, retired)
		}
		t.Log("actual paired Darwin public host verified " + scenario + ": original encrypted proof boundary, joined native PF and utun retirement")
		return
	}
	if err != nil || status != 200 {
		t.Fatal("actual installed paired public Connect failed", status, err, string(raw))
	}
	if c.Action == "mtu-rollback" {
		macOSPairedNodeNativeAwaitAuto(t, ctx, client, peer)
	}
	live := macOSPairedNodeNativeRead(t, ctx, client)
	if !live.Connected || live.Ready == nil || live.Baseline == nil || live.Policy != c.Policy || live.Mode != c.Mode || live.Layer != c.Layer || live.NodeID != peer.nodeID || live.ProcessID <= 0 || live.Ready.TransferSHA256 != live.Transfer || live.Ready.SourceSHA256 != live.Source || live.MTU.Config != live.Config || (c.Action != "mtu-rollback" && live.MTU.Reader != 1) {
		t.Fatal("public paired Connect omitted original native receipt", live)
	}
	after := peer.observe(t, "stats")
	if after.RouterQueries <= prior.RouterQueries || after.DNSQueries <= prior.DNSQueries || after.DirectQueries != prior.DirectQueries || after.RawTCP+after.RawUDP <= prior.RawTCP+prior.RawUDP {
		t.Fatal("public paired proof did not traverse actual encrypted transport and selected DNS", prior, after)
	}
	if c.Mode == "naive-h2" && (after.RawUDP != 0 || after.ProtocolRawUDP != 0 || after.ProtocolRawTCP <= 0 || after.ProtocolTLSHTTP <= 0 || after.ProtocolTCP <= prior.ProtocolTCP || after.ProtocolUDP <= prior.ProtocolUDP) {
		t.Fatal("Naive H2 proof did not traverse authenticated TLS/H2 and UoT over its exact TCP lower", prior, after)
	}
	if c.Action == "mtu-rollback" {
		macOSPairedNodeNativeMTU(t, ctx, client, peer, live)
		live = macOSPairedNodeNativeRead(t, ctx, client)
	}
	if c.Action == "restore-sealed" {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/native-paired-restore", "{}")
		if err != nil || status != 200 {
			t.Fatal("actual cancelled Speed Lab failed sealed original restoration", status, err, string(raw))
		}
		restored := macOSPairedNodeNativeRead(t, ctx, client)
		if !restored.Connected || restored.Session == live.Session || restored.ProcessID == live.ProcessID || restored.NodeID != live.NodeID || restored.Mode != live.Mode || restored.Policy != live.Policy {
			t.Fatal("Speed Lab reused historical runtime or substituted paired original", live, restored)
		}
		live = restored
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != 200 {
		t.Fatal("actual public paired Disconnect failed", status, err, string(raw))
	}
	retired := macOSPairedNodeNativeRead(t, ctx, client)
	if retired.Connected || !retired.Closed || !retired.NativeJoined || !retired.WorkspaceRetired || retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present != (c.Policy == "always") || !maps.Equal(before, macOSExternalNativeTunnels(t)) {
		t.Fatal("public paired Disconnect lost native retirement/Always boundary", retired)
	}
	if c.Policy == "always" {
		macOSPairedNodeNativeClearAlways(t, ctx, retired)
	} else {
		macOSExternalNativeRetiredKernel(t, ctx, live.Baseline.Token, before)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	joined = true
	if receipt.ExitCode != 0 {
		t.Fatal("paired controller did not join original native dependencies", receipt.ExitCode)
	}
	t.Log("actual paired Darwin public host verified " + scenario + ": original encrypted proof boundary, joined native PF and utun retirement")
}
func macOSPairedNodeNativeClearAlways(t *testing.T, ctx context.Context, retired macOSPairedNodeNativeResult) {
	t.Helper()
	if !retired.Closed || !retired.NativeJoined || retired.Policy != "always" || retired.Baseline == nil || !retired.Baseline.Baseline.Present {
		t.Fatal("fixture cleanup lacks exact retained Always proof")
	}
	raw, err := mobiletor.EncodeDesktopDarwinPFBaselineRequest(mobiletor.DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []mobiletor.DesktopDarwinPFBaselineProof{{Present: true, RulesSHA256: retired.Baseline.Baseline.Rules}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := mobiletor.RunDesktopDarwinPFBaseline(ctx, raw, true)
	if err != nil {
		t.Fatal("disposable original Always cleanup failed", err, string(output))
	}
	var proof mobiletor.DesktopDarwinPFBaselineResult
	if decodeRelayControlJSON(output, &proof) != nil || proof.Target.Present {
		t.Fatal("Always fixture cleanup did not prove exact native absence")
	}
	if err := os.Remove(filepath.Join(macOSOwnedControllerRoot, "run", "kill-switch.json")); err != nil {
		t.Fatal(err)
	}
}
