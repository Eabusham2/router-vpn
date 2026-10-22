package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopAWGRequest() externalProfileCreateRequest {
	q := createRequestFor("wireguard")
	q.Protocol, q.WGPrivateKey, q.WGPeerPublicKey = "amneziawg", testWGKey('p'), testWGKey('q')
	q.Server, q.WGMTU, q.WGKeepalive = "203.0.113.60", 1280, 17
	q.WGAddresses = []string{"10.66.0.2/32", "fd66::2/128"}
	q.AWGParameters = map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	return q
}

func desktopAWGProfile(t *testing.T) common.RouterProfile {
	t.Helper()
	p, err := externalProfileFromCreateRequest(desktopAWGRequest())
	if err != nil {
		t.Fatal(err)
	}
	p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	p.IPv6Mode, p.HomeLANAccess, p.MTUPolicy, p.EffectiveMTU = "off", false, "auto", 9000
	return p
}

func TestDesktopAmneziaCapabilityEndpointsAgree(t *testing.T) {
	var a app
	var previous []string
	for _, handler := range []http.HandlerFunc{platformStandardExitCapabilitiesHandler, a.externalProfileCapabilities} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
		var body struct {
			Entries []string `json:"external_entry_protocols"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatal("capability response is invalid")
		}
		if !slices.Contains(body.Entries, "amneziawg") || (previous != nil && !reflect.DeepEqual(body.Entries, previous)) {
			t.Fatal("desktop capability surfaces disagree with the implemented AmneziaWG entry")
		}
		previous = body.Entries
	}
	profile := desktopAWGProfile(t)
	entry, kind, err := standardExitEntry([]common.RouterProfile{profile}, profile, standardExitConnectRequest{EntryID: profile.ID})
	if err != nil || kind != "external" || entry.External.AmneziaWG == nil {
		t.Fatalf("advertised AmneziaWG entry cannot be selected: %v", err)
	}
}

func TestDesktopAmneziaCreationPreservesExactNativePeer(t *testing.T) {
	q := desktopAWGRequest()
	profile, err := externalProfileFromCreateRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	q.AWGParameters["s4"] = "0"
	if profile.External.AmneziaWG.Parameters["s4"] != "32" {
		t.Fatal("creation retained a mutable parameter alias")
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.External.AmneziaWG.Parameters["s4"] = "0"
	if exit.AWGParameters["s4"] != "32" || exit.WGKeepalive != 17 {
		t.Fatal("translation changed the captured peer")
	}
	for _, detour := range []string{"", "external-entry"} {
		endpoint, err := desktopAmneziaEndpoint(exit, detour)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(endpoint)
		parsed, err := mobilemultihop.AmneziaRuntimeConfig(string(encoded))
		if err != nil || parsed.TransportPadding != 32 {
			t.Fatalf("native endpoint differs: %v", err)
		}
		if endpoint["type"] != mobilemultihop.AmneziaType || !reflect.DeepEqual(endpoint["amnezia"], exit.AWGParameters) {
			t.Fatal("AWG was relabeled or its parameters changed")
		}
		endpoint["amnezia"].(map[string]string)["s4"] = "64"
		if exit.AWGParameters["s4"] != "32" {
			t.Fatal("native graph retained mutable saved parameters")
		}
	}
	for _, change := range []func(*externalProfileCreateRequest){
		func(q *externalProfileCreateRequest) { q.Protocol = "wireguard" },
		func(q *externalProfileCreateRequest) { delete(q.AWGParameters, "h4") },
		func(q *externalProfileCreateRequest) { q.AWGParameters["s4"] = "9999" },
		func(q *externalProfileCreateRequest) { q.AWGParameters["junk"] = "1" },
		func(q *externalProfileCreateRequest) { q.WGKeepalive = 65536 },
		func(q *externalProfileCreateRequest) { q.WGKeepalive = -1 },
	} {
		bad := desktopAWGRequest()
		change(&bad)
		if _, err := externalProfileFromCreateRequest(bad); err == nil {
			t.Fatal("invalid or substituted AmneziaWG peer accepted")
		}
	}
}

func desktopNativeCheck(t *testing.T, path string) {
	t.Helper()
	bundle := os.Getenv("ROUTERVPN_AWG_DESKTOP_BUNDLE")
	if bundle == "" {
		return
	}
	name := "sing-box-amnezia"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output, err := exec.Command(filepath.Join(bundle, name), "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("pinned native CLI rejected shipping desktop graph: %v %s", err, output)
	}
}

func desktopReadGraph(t *testing.T, directory string) map[string]any {
	t.Helper()
	path := filepath.Join(directory, "sing-box.json")
	desktopNativeCheck(t, path)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if err := json.Unmarshal(encoded, &graph); err != nil {
		t.Fatal(err)
	}
	if graph["route"].(map[string]any)["final"] != "custom-exit" {
		t.Fatal("desktop final route escaped the captured exit")
	}
	dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if dns["type"] != "tcp" || dns["server"] != "9.9.9.9" || dns["server_port"] != float64(5353) || dns["detour"] != "custom-exit" {
		t.Fatal("desktop DNS lost its exact routed resolver")
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if tun["mtu"] != float64(1280) || tun["strict_route"] != true {
		t.Fatal("historical MTU replaced the current owned TUN")
	}
	rules := graph["route"].(map[string]any)["rules"].([]any)
	if len(rules) < 3 {
		t.Fatal("LAN/IPv6-Off policy was lost")
	}
	return graph
}

func desktopAWGPrivateTestRoot(t *testing.T) string {
	t.Helper()
	// macOS exposes its temporary directory through the system /var symlink.
	// Resolve only the root just created for this test; the shipping private
	// store must continue rejecting symlinked roots and runtime subdirectories.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDesktopAmneziaPreparedDirectAndImportedGraphs(t *testing.T) {
	profile := desktopAWGProfile(t)
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	directory, _, err := prepareDirectStandardExit(desktopAWGPrivateTestRoot(t), profile, exit)
	if err != nil {
		t.Fatal(err)
	}
	desktopReadGraph(t, directory)
	for _, protocol := range []string{"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			entry := validTestStandardExit(protocol)
			if protocol == "shadowsocks" {
				entry.Secret = testWGKey('s')
			}
			if protocol == "amneziawg" {
				entry = exit
				entry.AWGParameters = maps.Clone(exit.AWGParameters)
				entry.WGPrivateKey = testWGKey('x')
				entry.WGMTU = 1500
			}
			entry.ID = "entry-" + protocol
			if protocol == "wireguard" {
				entry.WGMTU = 1500
				entry.WGAllowedIPs = []string{"0.0.0.0/0", "::/0"}
			}
			entryProfile, err := desktopExternalCapture(profile, entry)
			if err != nil {
				t.Fatal(err)
			}
			entryProfile.MTUPolicy = "auto"
			directory, _, err := prepareExternalEntryStandardExit(desktopAWGPrivateTestRoot(t), profile, entryProfile, exit)
			if protocol == "http-connect" || protocol == "https-connect" {
				if err == nil {
					t.Fatal("TCP-only entry accepted native AWG UDP")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			graph := desktopReadGraph(t, directory)
			var found bool
			for _, raw := range graph["endpoints"].([]any) {
				out := raw.(map[string]any)
				if out["tag"] == "custom-exit" {
					found = out["type"] == mobilemultihop.AmneziaType && out["detour"] == "external-entry"
				}
			}
			if !found {
				t.Fatal("captured AWG exit missing its entry detour")
			}
		})
	}
	entryProfile := desktopAWGProfile(t)
	entryProfile.ID = "native-awg-entry"
	entryProfile.External.AmneziaWG.MTU = 1500
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run("awg-entry-to-"+protocol, func(t *testing.T) {
			exit := validTestStandardExit(protocol)
			if protocol == "shadowsocks" {
				exit.Secret = testWGKey('s')
			}
			if protocol == "wireguard" {
				exit.WGMTU = 1280
				exit.WGAllowedIPs = []string{"0.0.0.0/0", "::/0"}
			}
			directory, _, err := prepareExternalEntryStandardExit(desktopAWGPrivateTestRoot(t), profile, entryProfile, exit)
			if err != nil {
				t.Fatal(err)
			}
			desktopReadGraph(t, directory)
		})
	}
	profile.MTUPolicy, profile.ManualMTU = "fixed", 1450
	root := desktopAWGPrivateTestRoot(t)
	if _, _, err := prepareExternalEntryStandardExit(root, profile, entryProfile, exit); err == nil {
		t.Fatal("oversized fixed nested AWG MTU accepted")
	}
	if files, _ := os.ReadDir(root); len(files) != 0 {
		t.Fatal("invalid fixed MTU staged private runtime files")
	}
}

func TestDesktopAmneziaEnvironmentRemovesStaleEngineCapture(t *testing.T) {
	env := desktopStandardEngineEnvironment([]string{"HOMEVPN_STANDARD_ENGINE=amnezia", "homevpn_amnezia_controller=stale", "HOMEVPN_AMNEZIA_PACKAGE=stale", "KEPT=1"}, false)
	if !reflect.DeepEqual(env, []string{"KEPT=1", "HOMEVPN_STANDARD_ENGINE=stock"}) {
		t.Fatalf("stale capture survived: %v", env)
	}
	env = desktopStandardEngineEnvironment(env, true)
	count := 0
	for _, v := range env {
		if v == "HOMEVPN_STANDARD_ENGINE=amnezia" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("native graph lacks exactly one captured engine")
	}
}

func TestDesktopAmneziaBundleIntegrityAndRelocation(t *testing.T) {
	source := os.Getenv("ROUTERVPN_AWG_DESKTOP_BUNDLE")
	if source == "" {
		t.Skip("native desktop gate supplies the actual pinned CLI bundle")
	}
	root := filepath.Join(t.TempDir(), "relocated package")
	destination := filepath.Join(root, "runtime", "amnezia")
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(source, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, file.Name()), raw, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := verifyBundledAmnezia(root)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(binary) != destination {
		t.Fatal("verification escaped the relocated package")
	}
	receiptPath := filepath.Join(destination, "AMNEZIA-RUNTIME.json")
	original, _ := os.ReadFile(receiptPath)
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["target"] = "other/device" },
		func(m map[string]any) { m["amnezia_version"] = "unknown" },
		func(m map[string]any) { m["amnezia_sum"] = "bad" },
		func(m map[string]any) { m["sha256"] = strings.Repeat("0", 64) },
		func(m map[string]any) { m["policy_sha256"] = strings.Repeat("0", 64) },
		func(m map[string]any) { m["unexpected_owner"] = true },
	} {
		var m map[string]any
		_ = json.Unmarshal(original, &m)
		mutate(m)
		raw, _ := json.Marshal(m)
		_ = os.WriteFile(receiptPath, raw, 0600)
		if _, err := verifyBundledAmnezia(root); err == nil {
			t.Fatal("altered native runtime receipt accepted")
		}
	}
	_ = os.WriteFile(receiptPath, original, 0600)
	raw, _ := os.ReadFile(binary)
	before := sha256.Sum256(raw)
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(binary, raw, 0700)
	if _, err := verifyBundledAmnezia(root); err == nil {
		t.Fatal("changed native engine bytes accepted")
	}
	raw[len(raw)-1] ^= 1
	if after := sha256.Sum256(raw); !bytes.Equal(before[:], after[:]) {
		t.Fatal("test restore did not match original bytes")
	}
	_ = os.WriteFile(binary, raw, 0700)
	if _, err := verifyBundledAmnezia(root); err != nil {
		t.Fatal(err)
	}
}
