//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/nativecomposite"
	"router-vpn/internal/windowscontroller"
)

var windowsCONNECTHostCases = []string{
	"http-wg-connect", "http-awg-fast-connect", "http-awg-strong-connect",
	"https-wg-connect", "https-awg-fast-connect", "https-awg-strong-connect",
	"https-wg-wrong-middle-key", "http-wg-wrong-middle-public",
	"https-wg-tls-name", "https-wg-tls-trust", "http-wg-final-dns-failure",
	"https-wg-final-node-failure", "https-wg-final-key", "https-wg-middle-source",
}

func windowsCONNECTCase(scenario string) (protocol, mode, action string, found bool) {
	for _, name := range windowsCONNECTHostCases {
		if name != scenario {
			continue
		}
		transport, remaining, _ := strings.Cut(name, "-")
		protocol = transport + "-connect"
		for _, candidate := range []struct{ prefix, mode string }{{"wg-", "wg"}, {"awg-fast-", "awg2-fast"}, {"awg-strong-", "awg2-strong"}} {
			if strings.HasPrefix(remaining, candidate.prefix) {
				return protocol, candidate.mode, strings.TrimPrefix(remaining, candidate.prefix), true
			}
		}
	}
	return "", "", "", false
}

func windowsCONNECTInstalledSources(t *testing.T, peer *windowsPrefixPeer, protocol, password, serverName, fault string) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	if len(peer.requests) != 1 || password == "" || (protocol != "http-connect" && protocol != "https-connect") {
		t.Fatal("installed CONNECT source lost original independent first and authenticated middle")
	}
	store, assets := windowsPrefixInstalledSources(t, peer, "")
	proxy := &common.ExternalHTTPConnectConfig{Host: "10.79.0.1", Port: 1080, Username: "captured-native-user", Password: password}
	middle := common.RouterProfile{ID: "installed-original-connect-middle", Name: "Original imported CONNECT middle", NodeKind: "external", Endpoint: "10.79.0.1",
		External: &common.ExternalNodeConfig{Protocol: protocol, ExpectedPublicIP: "203.0.113.88"},
		DNSMode:  "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if protocol == "https-connect" {
		if serverName == "" {
			t.Fatal("HTTPS CONNECT lost captured TLS identity")
		}
		proxy.TLSServerName = serverName
		middle.External.HTTPSConnect = proxy
	} else {
		middle.External.HTTPConnect = proxy
	}
	if fault == "wrong-middle-key" {
		proxy.Password += "-wrong"
	}
	if fault == "tls-name" {
		proxy.TLSServerName = "wrong-captured-proxy.invalid"
	}
	if err := common.NormalizeRouterProfile(&middle); err != nil {
		t.Fatal(err)
	}
	if len(store.Profiles) != 2 || len(assets) != 2 {
		t.Fatal("CONNECT fixture changed original paired source inventory")
	}
	first, final := store.Profiles[0], store.Profiles[1]
	final.MultihopNodes = []common.MultihopNodeSelection{{ID: first.ID, Mode: peer.requests[0].Mode}, {ID: middle.ID, Mode: protocol}, {ID: final.ID, Mode: "shadowsocks"}}
	if err := common.NormalizeRouterProfile(&final); err != nil {
		t.Fatal(err)
	}
	raw := assets[final.ID]["shadowsocks"]["sing-box.json"]
	var graph map[string]any
	if json.Unmarshal(raw, &graph) != nil {
		t.Fatal("CONNECT lost original final source")
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok || len(outbounds) != 1 {
		t.Fatal("CONNECT final source changed its outbound inventory")
	}
	out, ok := outbounds[0].(map[string]any)
	if !ok || len(out) != 6 || out["type"] != "shadowsocks" || out["password"] != peer.password || out["server"] != "10.77.0.1" || out["server_port"] != float64(8388) {
		t.Fatal("CONNECT lost captured final encrypted carrier")
	}
	if fault == "final-key" {
		out["password"] = peer.requests[0].PreSharedKey
		var err error
		raw, err = json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		assets[final.ID]["shadowsocks"]["sing-box.json"] = raw
	}
	// Preserve the original six-field source. Only the separately captured
	// receiver declaration permits the compiler to derive private UoT-v2.
	configHash, keyHash := sha256.Sum256(raw), sha256.Sum256([]byte(out["password"].(string)))
	declaration, err := json.Marshal(map[string]any{"schema": 1, "node_id": final.NodeProofID,
		"configured_image": nativecomposite.SSServiceImage, "uot_version": 2, "endpoint": out["server"], "port": out["server_port"], "method": out["method"],
		"source_sha256": hex.EncodeToString(configHash[:]), "key_sha256": hex.EncodeToString(keyHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := nativecomposite.ValidateSSServiceCompanion(raw, declaration, final.NodeProofID); err != nil {
		t.Fatal("CONNECT fixture lost exact final service authority", err)
	}
	assets[final.ID]["shadowsocks"][nativecomposite.SSServiceAsset] = declaration
	store.Profiles = []common.RouterProfile{first, middle, final}
	return store, assets
}

func TestWindowsInstalledCONNECTNodeChain(t *testing.T) {
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("typed installed native gate requires actual elevated Windows", err)
	}
	root := os.Getenv("ROUTERVPN_WINDOWS_PREFIX_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("typed gate lost original completed native bundle")
	}
	if err := ensurePrivateRuntimeDirectory(root); err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"RouterVPN.exe", "router-vpn-client.exe"} {
		input, err := os.Open(image)
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		if err := errors.Join(copyErr, input.Close(), output.Close()); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range windowsCONNECTHostCases {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(filepath.Join(root, "RouterVPN.exe"), "-test.v", "-test.run=^TestWindowsCONNECTLauncher$", "-test.count=1", "-test.timeout=240s", "--", root, scenario)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("typed installed %s: %v\n%s", scenario, err, output)
			}
			witness := "verified installed Windows typed CONNECT full path and joined retirement: " + scenario
			if strings.Count(string(output), witness) != 1 {
				t.Fatal("typed installed case omitted unique original native receipt", string(output))
			}
			t.Log(witness)
		})
	}
}

func TestWindowsCONNECTLauncher(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 2 {
		t.Fatal("typed launcher lost original finite case")
	}
	root, scenario := arguments[0], arguments[1]
	protocol, mode, action, ok := windowsCONNECTCase(scenario)
	if !ok {
		t.Fatal("unknown installed CONNECT scenario")
	}
	peer, password, connectCA, serverName, observe := windowsCONNECTPeerStart(t, mode, protocol)
	windowsSOCKSTrust(t, peer.reply.PublicCA)
	if protocol == "https-connect" && action != "tls-trust" {
		windowsSOCKSTrust(t, connectCA)
	}
	profiles, assets := windowsCONNECTInstalledSources(t, peer, protocol, password, serverName, action)
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
	for name, raw := range map[string][]byte{"modes.json": catalog, "logical-modes.json": []byte("[]"), "client/native-wireguard-windows.ps1": []byte("# immutable unused adapter\n"), "client/native-windows-mode.ps1": []byte("# immutable unused adapter\n")} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	switch action {
	case "wrong-middle-public":
		observe("wrong-middle-public")
	case "final-dns-failure":
		observe("fail-dns")
	case "final-node-failure":
		observe("wrong-node")
	}
	client, closeController := windowsPrefixLaunch(t, root)
	defer closeController()
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	call := func(method, path string, body []byte) controllertransport.Response {
		t.Helper()
		response, err := client.Request(ctx, method, path, body, 1<<20)
		if err != nil {
			t.Fatal("original typed protected TLS request", err)
		}
		return response
	}
	request := call("GET", "/api/native-connect/request", nil)
	if request.Status != 200 {
		t.Fatal("typed request capture", request.Status, string(request.Body))
	}
	response := call("POST", "/api/native-connect/connect", request.Body)
	negative := action != "connect" && action != "middle-source"
	if negative && response.Status == 200 || !negative && response.Status != 200 {
		t.Fatal("typed Connect crossed intended proof boundary", response.Status, string(response.Body))
	}
	if action == "tls-name" || action == "tls-trust" {
		observe("tls-refused")
	}
	var ready windowsCONNECTInspection
	if !negative {
		response = call("GET", "/api/native-connect/inspect", nil)
		if response.Status != 200 || json.Unmarshal(response.Body, &ready) != nil || !ready.Connected || !ready.OriginalSources || ready.MeasurementRows != 3 || ready.Proof == nil || ready.Proof.Kind != "routervpn-node-chain-connect-ready-v1" {
			t.Fatal("typed actual proof/measurement", response.Status, string(response.Body))
		}
	}
	if !negative {
		beforeFifty := observe("stats")
		receipts, err := desktopOrderedLatencyNativeRoundTrip(ctx, func(callCtx context.Context, method, path string, body []byte) (int, []byte, error) {
			response, err := client.Request(callCtx, method, path, body, 1<<20)
			return response.Status, response.Body, err
		})
		if err != nil || len(receipts) != 3 {
			t.Fatal("installed Windows ordered fifty", err)
		}
		afterFifty := observe("stats")
		if len(beforeFifty.Prefixes) != 1 || len(afterFifty.Prefixes) != 1 || afterFifty.Prefixes[0].ProofQueries < beforeFifty.Prefixes[0].ProofQueries+50 || afterFifty.Middle.PublicQueries < beforeFifty.Middle.PublicQueries+50 || afterFifty.Final.RouterQueries < beforeFifty.Final.RouterQueries+50 || afterFifty.Final.DirectQueries != 0 {
			t.Fatal("ordered fifty omitted independently routed original prefix responses", beforeFifty, afterFifty)
		}
	}
	before := observe("stats")
	if len(before.Prefixes) != 1 || before.Prefixes[0].Mode != mode || before.Prefixes[0].RawUDP == 0 || before.Prefixes[0].ProofQueries == 0 || before.Middle.Method != protocol {
		t.Fatal("typed path did not reach original independently encrypted first", before)
	}
	if before.Protocol != protocol || before.FinalUOTVersion != 2 || before.Middle.RawUDP != 0 || before.Middle.UDP != 0 || before.Final.FinalRawUDP != 0 || before.Prefixes[0].UDP != 0 || before.Final.DirectQueries != 0 {
		t.Fatal("CONNECT acquired a packet relay or bypassed the original final UoT-v2 owner", before)
	}
	switch action {
	case "wrong-middle-key":
		if before.Middle.RawTCP == 0 || before.AuthRefusals == 0 || before.Middle.TCP != 0 || before.Middle.UDP != 0 || before.Middle.PublicQueries != 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT credential crossed original authentication boundary", before)
		}
	case "tls-name", "tls-trust":
		if before.Middle.RawTCP == 0 || before.TLSRefusals == 0 || before.Middle.TCP != 0 || before.Middle.PublicQueries != 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT TLS identity crossed original verification boundary", before)
		}
	case "final-key":
		if before.Middle.TCP == 0 || before.Middle.PublicQueries == 0 || before.Final.FinalRawTCP == 0 || before.Final.FinalTCP != 0 || before.Final.FinalUDP != 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong final Shadowsocks key crossed original encryption boundary", before)
		}
	case "wrong-middle-public":
		if before.Middle.TCP == 0 || before.Middle.PublicQueries == 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT public identity did not fail at routed middle proof", before)
		}
	case "final-dns-failure":
		if before.Final.DNSQueries == 0 {
			t.Fatal("DNS failure did not reach original selected final resolver", before)
		}
	case "final-node-failure":
		if before.Final.RouterQueries == 0 {
			t.Fatal("final identity refusal did not reach original paired final", before)
		}
	default:
		if before.Middle.RawTCP == 0 || before.Middle.TCP == 0 || before.Middle.PublicQueries == 0 || before.Middle.DownloadBytes < 8<<20 || before.Middle.UploadBytes < 8<<20 || before.Final.DNSQueries == 0 || before.Final.RouterQueries == 0 || before.Final.FinalPublicQueries == 0 || before.Final.FinalTCP == 0 || before.Final.FinalUDP == 0 || before.Final.DirectQueries != 0 || before.Prefixes[0].TCP == 0 || before.Prefixes[0].AuthRefusals != 0 || before.AuthRefusals != 0 || before.TargetRefusals != 0 || before.TLSRefusals != 0 {
			t.Fatal("typed full path omitted original middle/final traffic, proof or complete benchmark", before)
		}
	}
	if action == "middle-source" {
		response = call("POST", "/api/native-connect/middle-source", nil)
		if response.Status != 204 {
			t.Fatal("original middle replacement", response.Status, string(response.Body))
		}
		response = call("GET", "/api/native-connect/inspect", nil)
		if response.Status == 200 {
			t.Fatal("foreign middle credential retained current typed proof")
		}
	}
	if !negative {
		response = call("POST", "/api/disconnect", []byte(`{}`))
		if response.Status != 200 {
			t.Fatal("typed original disconnect", response.Status, string(response.Body))
		}
	}
	response = call("GET", "/api/native-connect/inspect?retired=1", nil)
	var retired windowsCONNECTInspection
	if response.Status != 200 || json.Unmarshal(response.Body, &retired) != nil || retired.Connected || !retired.NativeJoined || !retired.JournalSettled || !retired.WFPAbsent || !retired.TUNAbsent || action != "middle-source" && !retired.OriginalSources {
		t.Fatal("typed original native retirement", response.Status, string(response.Body))
	}
	after := observe("stats")
	if after.OpenStreams == nil || *after.OpenStreams != 0 {
		t.Fatal("typed original native retirement retained authenticated CONNECT streams", after.OpenStreams)
	}
	closeController()
	t.Log("verified installed Windows typed CONNECT full path and joined retirement:", scenario)
}
