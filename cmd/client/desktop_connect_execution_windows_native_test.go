//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowscontroller"
	"testing"
	"time"
)

func TestWindowsInstalledCONNECTExecution(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		return
	}
	if len(args) != 2 || os.Getenv("ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE") != "1" {
		t.Fatal("Windows execution requires original opted-in installed case")
	}
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("actual elevated Windows owner absent", err)
	}
	root, scenario := args[0], args[1]
	if !filepath.IsAbs(root) {
		t.Fatal("original installed root absent")
	}
	if _, _, _, _, _, err := windowsCONNECTExecutionScenario(scenario); err != nil {
		t.Fatal(err)
	}
	t.Run(scenario, func(t *testing.T) { windowsCONNECTExecutionNativeCase(t, root, scenario) })
}
func windowsCONNECTExecutionNativeCase(t *testing.T, root, scenario string) {
	t.Helper()
	_, _, requested, winner, fault, _ := windowsCONNECTExecutionScenario(scenario)
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	var peer *windowsCONNECTExecutionPeer
	var closeController func(context.Context) error
	joined := false
	join := func(ctx context.Context) error {
		if closeController != nil {
			if err := closeController(ctx); err != nil {
				return err
			}
		}
		if err := peer.close(ctx); err != nil {
			return err
		}
		joined = true
		return nil
	}
	// Register before either process starts. A failed join cannot release aliases.
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var err error
		if peer != nil && peer.aliases != nil {
			err = peer.aliases.Close(cleanup, join)
		} else {
			err = join(cleanup)
		}
		if err != nil {
			t.Error("original execution cleanup failed", err)
		}
	})
	peer = windowsCONNECTExecutionStartPeer(t, ctx, scenario, &peer)
	windowsSOCKSTrust(t, peer.first.PublicCA)
	if peer.protocol == "https-connect" {
		windowsSOCKSTrust(t, peer.first.ConnectCA)
	}
	profiles, assets := windowsCONNECTExecutionSources(t, scenario, peer)
	for _, directory := range []string{"client", "modes", "runtime"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for id, variants := range assets {
		for mode, files := range variants {
			directory := filepath.Join(root, "generated", id, mode)
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for name, raw := range files {
				if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	windowsPrefixWrite(t, filepath.Join(root, "routers.json"), profiles)
	windowsPrefixWrite(t, filepath.Join(root, "client.json"), map[string]any{"listen": linuxOwnedControllerAddress, "modes_file": filepath.Join(root, "modes.json"), "scripts_dir": filepath.Join(root, "modes"), "state_file": filepath.Join(root, "state.json"), "profiles_file": filepath.Join(root, "routers.json")})
	catalog := []byte(`[{"id":"wg","name":"WireGuard","command":["./run-platform.sh","run-mode.sh","wg"],"check_command":["./check-mode.sh","wg"],"stop_command":["./stop-mode-platform.sh"]}]`)
	for name, raw := range map[string][]byte{"modes.json": catalog, "logical-modes.json": []byte("[]"), "client/native-wireguard-windows.ps1": []byte("# immutable unused adapter\n"), "client/native-windows-mode.ps1": []byte("# immutable unused adapter\n"), windowsCONNECTExecutionMarker: []byte(scenario)} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, _ := windowsCONNECTExecutionLaunch(t, root, &closeController)
	call := func(method, path string, body []byte) controllertransport.Response {
		t.Helper()
		if err := peer.aliases.Current(ctx); err != nil {
			t.Fatal(err)
		}
		response, err := client.Request(ctx, method, path, body, 1<<20)
		if err != nil {
			t.Fatal("original protected Windows request", err)
		}
		return response
	}
	source := call("GET", "/api/native-connect-execution-source", nil)
	var captured map[string]string
	if source.Status != 200 || json.Unmarshal(source.Body, &captured) != nil || captured["local_source"] == "" {
		t.Fatal("original typed Local source absent", source.Status, string(source.Body))
	}
	configured, err := peer.exchange(ctx, map[string]string{"local_source": captured["local_source"], "winner": winner})
	sourceHash := sha256.Sum256([]byte(captured["local_source"]))
	var configuredHash string
	if err != nil || string(configured["ready"]) != "true" || json.Unmarshal(configured["source_sha256"], &configuredHash) != nil || configuredHash != hex.EncodeToString(sourceHash[:]) {
		t.Fatal("original relay Manager source capture failed", err)
	}
	if fault == "wrong-public" {
		peer.stats(t, ctx, "wrong-middle-public")
	}
	if fault == "failed-dns" {
		peer.stats(t, ctx, "fail-dns")
	}
	request := call("GET", "/api/native-ordered-request", nil)
	if request.Status != 200 {
		t.Fatal("original public requested selection absent", request.Status, string(request.Body))
	}
	response := call("POST", "/api/multihop/connect", request.Body)
	negative := fault != "" && fault != "replaced-source" && fault != "held-cleanup"
	if negative && response.Status == 200 || !negative && response.Status != 200 {
		t.Fatal("actual public execution crossed its proof boundary", response.Status, string(response.Body))
	}
	if fault == "tls-name" {
		peer.stats(t, ctx, "tls-refused")
	}
	var before windowsCONNECTExecutionObservation
	comparisonTrials, restoreLaunches := 0, uint64(0)
	if !negative {
		observed := call("GET", "/api/native-connect-execution-observation", nil)
		if observed.Status != 200 || json.Unmarshal(observed.Body, &before) != nil || !before.PublicConnect || !before.Connected || before.Requested != requested || before.Winner != winner || before.Source == "" || before.PID <= 0 {
			t.Fatal("original Windows execution proof absent", observed.Status, string(observed.Body))
		}
		windowsCONNECTExecutionRequireMeasurements(t, before.Ready.Progress.Comparison, winner, requested == "auto")
		comparisonTrials = len(before.Ready.Progress.Comparison.Measurements)
	}
	if fault == "replaced-source" {
		response = call("POST", "/api/native-connect-execution-replace", []byte("{}"))
		if response.Status != 200 {
			t.Fatal("replacement control failed")
		}
		response = call("GET", "/api/native-connect-execution-observation", nil)
		if response.Status == 200 {
			t.Fatal("foreign credential retained original live proof")
		}
	} else if fault == "" {
		_, launchesBefore, _, _ := peer.stats(t, ctx, "stats")
		response = call("POST", "/api/native-connect-execution-restore", []byte("{}"))
		if response.Status != 200 {
			t.Fatal("actual Last restoration failed", response.Status, string(response.Body))
		}
		response = call("GET", "/api/native-connect-execution-observation", nil)
		var after windowsCONNECTExecutionObservation
		if response.Status != 200 || json.Unmarshal(response.Body, &after) != nil || !after.Restored || after.PID == before.PID || after.Ready.Identity == before.Ready.Identity || after.Winner != before.Winner || after.Ready.Progress.Comparison.Target != before.Ready.Progress.Comparison.Target || after.Ready.Progress.Comparison.Winner == nil || before.Ready.Progress.Comparison.Winner == nil || *after.Ready.Progress.Comparison.Winner != *before.Ready.Progress.Comparison.Winner {
			t.Fatal("Last restoration replaced original chosen path", response.Status, string(response.Body))
		}
		windowsCONNECTExecutionRequireMeasurements(t, after.Ready.Progress.Comparison, winner, false)
		_, launchesAfter, _, _ := peer.stats(t, ctx, "stats")
		if launchesAfter < launchesBefore {
			t.Fatal("original launch counter regressed")
		}
		restoreLaunches = launchesAfter - launchesBefore
		expected := uint64(0)
		if winner == "server" {
			expected = 1
		}
		if restoreLaunches != expected {
			t.Fatal("Last reran discovery or replaced original worker", restoreLaunches)
		}
	}
	if fault == "held-cleanup" {
		response = call("POST", "/api/native-connect-execution-cleanup-retry", []byte("{}"))
		var refusal struct {
			Refused bool `json:"refused"`
			Same    bool `json:"same_owner"`
			Joined  bool `json:"joined"`
		}
		if response.Status != 200 || json.Unmarshal(response.Body, &refusal) != nil || !refusal.Refused || !refusal.Same || refusal.Joined {
			t.Fatal("original held journal cleanup lost its retry owner", response.Status, string(response.Body))
		}
		held := errors.New("original controller and relay remain unjoined")
		if err := peer.aliases.Close(ctx, func(context.Context) error { return held }); !errors.Is(err, held) {
			t.Fatal("alias retirement crossed failed original join", err)
		}
		if err := peer.aliases.Current(ctx); err != nil {
			t.Fatal("failed original join removed aliases", err)
		}
	}
	response = call("POST", "/api/disconnect", []byte("{}"))
	if response.Status != 200 {
		t.Fatal("original public Disconnect failed", response.Status, string(response.Body))
	}
	response = call("GET", "/api/native-connect-execution-retired", nil)
	var retired map[string]bool
	if response.Status != 200 || json.Unmarshal(response.Body, &retired) != nil || len(retired) != 4 || !retired["native_joined"] || !retired["journal_settled"] || !retired["wfp_absent"] || !retired["tun_absent"] {
		t.Fatal("original Windows native cleanup unproved", response.Status, string(response.Body))
	}
	observed, launches, workersJoined, layers := peer.stats(t, ctx, "stats")
	if !workersJoined || launches == 0 || len(observed.Prefixes) != 1 || observed.Prefixes[0].RawUDP == 0 || observed.Prefixes[0].TCP == 0 || observed.Prefixes[0].ProofQueries == 0 || observed.Prefixes[0].AuthRefusals != 0 || observed.OpenStreams == nil || *observed.OpenStreams != 0 || observed.Middle.RawTCP == 0 || observed.Middle.RawUDP != 0 || observed.Middle.UDP != 0 || observed.Final.FinalRawUDP != 0 || observed.Final.DirectQueries != 0 {
		t.Fatal("original encrypted prefix/CONNECT/worker cleanup counters absent")
	}
	switch fault {
	case "wrong-auth":
		if observed.AuthRefusals == 0 || observed.TLSRefusals != 0 || observed.Middle.TCP != 0 || observed.Middle.PublicQueries != 0 || observed.Final.RouterQueries != 0 {
			t.Fatal("wrong original Basic credential bypassed refusal")
		}
	case "tls-name":
		if observed.TLSRefusals == 0 || observed.AuthRefusals != 0 || observed.Middle.TCP != 0 || observed.Middle.PublicQueries != 0 || observed.Final.RouterQueries != 0 {
			t.Fatal("wrong original TLS authority bypassed refusal")
		}
	case "wrong-public":
		if observed.Middle.TCP == 0 || observed.Middle.PublicQueries == 0 || observed.Final.RouterQueries != 0 {
			t.Fatal("wrong public identity did not reach original authenticated middle")
		}
	case "wrong-final":
		if observed.Final.FinalRawTCP == 0 || observed.Final.FinalTCP != 0 || observed.Final.RouterQueries != 0 {
			t.Fatal("wrong final key did not fail at original encrypted final")
		}
	default:
		if observed.Middle.TCP == 0 || observed.Middle.PublicQueries == 0 || observed.Final.FinalRawTCP == 0 || observed.Final.RouterQueries == 0 || observed.Final.DNSQueries == 0 || observed.AuthRefusals != 0 || observed.TLSRefusals != 0 || observed.TargetRefusals != 0 {
			t.Fatal("actual selected encrypted proof/DNS omitted")
		}
	}
	var layerPackets, layerCiphertext int64
	var layerAuth uint32
	if layers.Entry == "off" {
		if layers.EntryTransport != nil {
			t.Fatal("Off borrowed layer owner")
		}
	} else {
		layer := layers.EntryTransport
		if layer == nil || peer.layers.EntryTransport == nil || layer.Address != peer.layers.EntryTransport.Address || layer.Method != "2022-blake3-aes-256-gcm" || layer.PhysicalUDP == 0 || layer.Packets == 0 || layer.AuthUDP != 0 {
			t.Fatal("original entry layer did not carry encrypted packets")
		}
		layerPackets, layerCiphertext, layerAuth = layer.Packets, layer.PhysicalUDP, layer.AuthUDP
	}
	if err := peer.aliases.Close(ctx, join); err != nil || !joined {
		t.Fatal("original controller/Manager/alias cleanup did not join", err)
	}
	raw, err := json.Marshal(map[string]any{"case": scenario, "launches": launches, "restore_launches": restoreLaunches, "comparison_trials": comparisonTrials, "entry_raw_udp": observed.Prefixes[0].RawUDP, "entry_tcp": observed.Prefixes[0].TCP, "entry_proofs": observed.Prefixes[0].ProofQueries, "middle_raw_tcp": observed.Middle.RawTCP, "middle_tcp": observed.Middle.TCP, "middle_public": observed.Middle.PublicQueries, "final_raw_tcp": observed.Final.FinalRawTCP, "final_tcp": observed.Final.FinalTCP, "final_proofs": observed.Final.RouterQueries, "dns": observed.Final.DNSQueries, "middle_raw_udp": observed.Middle.RawUDP, "final_raw_udp": observed.Final.FinalRawUDP, "auth_refusals": observed.AuthRefusals, "tls_refusals": observed.TLSRefusals, "open_streams": *observed.OpenStreams, "entry_layer": layers.Entry, "entry_layer_packets": layerPackets, "entry_layer_ciphertext": layerCiphertext, "entry_layer_auth": layerAuth, "native_joined": true, "journal_settled": true, "wfp_absent": true, "tun_absent": true, "aliases_removed": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("WINDOWS_CONNECT_EXECUTION_COUNTERS %s", raw)
	t.Logf("WINDOWS_CONNECT_EXECUTION_RECEIPT case=%s requested=%s winner=%s negative=%t restored=%t cleanup_retry=%t native_joined=true relay_joined=true aliases_retired=true", scenario, requested, winner, negative, fault == "", fault == "held-cleanup")
}
