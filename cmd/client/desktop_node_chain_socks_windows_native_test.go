//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"router-vpn/internal/windowscontroller"
)

var windowsSOCKSHostCases = []string{"wg-connect", "awg-fast-connect", "awg-strong-connect", "wg-wrong-middle-key", "wg-wrong-middle-public", "wg-final-dns-failure", "wg-final-node-failure", "wg-middle-source"}

func windowsSOCKSInstalledSources(t *testing.T, peer *windowsPrefixPeer, password, fault string) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	if len(peer.requests) != 1 || password == "" {
		t.Fatal("typed installed source lost original independent first and middle")
	}
	store, assets := windowsPrefixInstalledSources(t, peer, "")
	middle := common.RouterProfile{ID: "installed-original-socks-middle", Name: "Original imported SOCKS middle", NodeKind: "external", Endpoint: "10.79.0.1",
		External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.88", SOCKS5: &common.ExternalSOCKS5Config{Host: "10.79.0.1", Port: 1080, Username: "captured-native-user", Password: password}},
		DNSMode:  "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if fault == "wrong-middle-key" {
		middle.External.SOCKS5.Password += "-wrong"
	}
	if err := common.NormalizeRouterProfile(&middle); err != nil {
		t.Fatal(err)
	}
	if len(store.Profiles) != 2 || len(assets) != 2 {
		t.Fatal("typed fixture changed original paired source inventory")
	}
	first, final := store.Profiles[0], store.Profiles[1]
	final.MultihopNodes = []common.MultihopNodeSelection{{ID: first.ID, Mode: peer.requests[0].Mode}, {ID: middle.ID, Mode: "socks5"}, {ID: final.ID, Mode: "shadowsocks"}}
	if err := common.NormalizeRouterProfile(&final); err != nil {
		t.Fatal(err)
	}
	store.Profiles = []common.RouterProfile{first, middle, final}
	return store, assets
}

func windowsSOCKSTrust(t *testing.T, ca string) {
	t.Helper()
	block, rest := pem.Decode([]byte(ca))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("peer lost its unique original CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		t.Fatal("peer supplied invalid original CA", err)
	}
	digest := sha1.Sum(cert.Raw)
	thumb := strings.ToUpper(hex.EncodeToString(digest[:]))
	script := "if (Test-Path -LiteralPath 'Cert:\\CurrentUser\\Root\\" + thumb + "') { exit 77 }"
	if output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("original random peer CA already exists or store cannot be read: %v %s", err, output)
	}
	file := filepath.Join(t.TempDir(), "original-peer-ca.pem")
	if err := os.WriteFile(file, []byte(ca), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("certutil.exe", "-user", "-addstore", "Root", file).CombinedOutput(); err != nil {
		t.Fatalf("original native peer CA install: %v %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("certutil.exe", "-user", "-delstore", "Root", thumb).CombinedOutput(); err != nil {
			t.Errorf("original native peer CA cleanup: %v %s", err, output)
		}
	})
}

func TestWindowsInstalledSOCKSNodeChain(t *testing.T) {
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
	for _, scenario := range windowsSOCKSHostCases {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(filepath.Join(root, "RouterVPN.exe"), "-test.v", "-test.run=^TestWindowsSOCKSLauncher$", "-test.count=1", "-test.timeout=240s", "--", root, scenario)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("typed installed %s: %v\n%s", scenario, err, output)
			}
			witness := "verified installed Windows typed SOCKS full path and joined retirement: " + scenario
			if strings.Count(string(output), witness) != 1 {
				t.Fatal("typed installed case omitted unique original native receipt", string(output))
			}
			t.Log(witness)
		})
	}
}

func TestWindowsSOCKSLauncher(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 2 {
		t.Fatal("typed launcher lost original finite case")
	}
	root, scenario := arguments[0], arguments[1]
	mode, action := "", ""
	for _, name := range windowsSOCKSHostCases {
		if name == scenario {
			mode = "wg"
			action = strings.TrimPrefix(scenario, "wg-")
			if strings.HasPrefix(scenario, "awg-fast-") {
				mode = "awg2-fast"
				action = "connect"
			}
			if strings.HasPrefix(scenario, "awg-strong-") {
				mode = "awg2-strong"
				action = "connect"
			}
		}
	}
	if mode == "" {
		t.Fatal("unknown typed installed scenario")
	}
	peer, password, observe := windowsSOCKSPeerStart(t, mode)
	windowsSOCKSTrust(t, peer.reply.PublicCA)
	profiles, assets := windowsSOCKSInstalledSources(t, peer, password, action)
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
	request := call("GET", "/api/native-socks/request", nil)
	if request.Status != 200 {
		t.Fatal("typed request capture", request.Status, string(request.Body))
	}
	response := call("POST", "/api/native-socks/connect", request.Body)
	negative := action != "connect" && action != "middle-source"
	if negative && response.Status == 200 || !negative && response.Status != 200 {
		t.Fatal("typed Connect crossed intended proof boundary", response.Status, string(response.Body))
	}
	var ready windowsSOCKSInspection
	if !negative {
		response = call("GET", "/api/native-socks/inspect", nil)
		if response.Status != 200 || json.Unmarshal(response.Body, &ready) != nil || !ready.Connected || !ready.OriginalSources || ready.MeasurementRows != 3 || ready.Proof == nil || ready.Proof.Kind != "routervpn-node-chain-socks-ready-v1" {
			t.Fatal("typed actual proof/measurement", response.Status, string(response.Body))
		}
	}
	before := observe("stats")
	if len(before.Prefixes) != 1 || before.Prefixes[0].Mode != mode || before.Prefixes[0].RawUDP == 0 || before.Prefixes[0].ProofQueries == 0 || before.Middle.Method != "socks5" {
		t.Fatal("typed path did not reach original independently encrypted first", before)
	}
	switch action {
	case "wrong-middle-key":
		if before.Middle.RawTCP+before.Middle.RawUDP == 0 || before.Middle.TCP != 0 || before.Middle.UDP != 0 || before.Middle.PublicQueries != 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong SOCKS credential crossed original authentication boundary", before)
		}
	case "wrong-middle-public":
		if before.Middle.TCP == 0 || before.Middle.PublicQueries == 0 || before.Final.RouterQueries != 0 {
			t.Fatal("wrong SOCKS public identity did not fail at routed middle proof", before)
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
		if before.Middle.RawTCP == 0 || before.Middle.RawUDP == 0 || before.Middle.TCP == 0 || before.Middle.UDP == 0 || before.Middle.PublicQueries == 0 || before.Middle.DownloadBytes < 8<<20 || before.Middle.UploadBytes < 8<<20 || before.Final.DNSQueries == 0 || before.Final.RouterQueries == 0 || before.Final.FinalPublicQueries == 0 || before.Final.FinalTCP == 0 || before.Final.FinalUDP == 0 || before.Final.DirectQueries != 0 || before.Prefixes[0].TCP == 0 || before.Prefixes[0].UDP == 0 || before.Prefixes[0].AuthRefusals != 0 {
			t.Fatal("typed full path omitted original middle/final traffic, proof or complete benchmark", before)
		}
	}
	if action == "middle-source" {
		response = call("POST", "/api/native-socks/middle-source", nil)
		if response.Status != 204 {
			t.Fatal("original middle replacement", response.Status, string(response.Body))
		}
		response = call("GET", "/api/native-socks/inspect", nil)
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
	response = call("GET", "/api/native-socks/inspect?retired=1", nil)
	var retired windowsSOCKSInspection
	if response.Status != 200 || json.Unmarshal(response.Body, &retired) != nil || retired.Connected || !retired.NativeJoined || !retired.JournalSettled || !retired.WFPAbsent || !retired.TUNAbsent || action != "middle-source" && !retired.OriginalSources {
		t.Fatal("typed original native retirement", response.Status, string(response.Body))
	}
	after := observe("stats")
	if after.Associations == nil || *after.Associations != 0 {
		t.Fatal("typed original native retirement retained remote SOCKS association", after.Associations)
	}
	closeController()
	t.Log("verified installed Windows typed SOCKS full path and joined retirement:", scenario)
}
