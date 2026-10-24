package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestNativeStartLayerAUTOUsesAllCapturedCompositionFamilies(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	dir := filepath.Join(root, "runtime", "native")
	if err := os.MkdirAll(dir, 0700); err != nil { t.Fatal(err) }
	// Presence chooses the complete runtime path. This deliberately incomplete
	// marker must never pass the separate runtime verification before Connect.
	if err := os.WriteFile(filepath.Join(dir, "NATIVE-RUNTIME.json"), []byte(`{}`), 0600); err != nil { t.Fatal(err) }
	if _, err := verifyBundledNative(root); err == nil { t.Fatal("capability marker became verified executable evidence") }
	a := &app{}
	count := 0
	for id := range readModeIDsForProfileTest(t, filepath.Join("..", "..", "configs", "client", "modes.json")) {
		a.modes = append(a.modes, testMode(id, "wireguard"))
		if !mobilemultihop.NodeProfileMode(id) { continue }
		count++
		for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			profile := common.RouterProfile{StartLayer: layer, AutoRequireEncrypted: true}
			if ok, reason := modeMeetsAutoRequirements(testMode(id, "wireguard"), profile); !ok { t.Fatalf("native %s/%s incorrectly excluded: %s", id, layer, reason) }
		}
	}
	if count != 19 { t.Fatalf("native mode matrix changed: %d", count) }
	r := httptest.NewRecorder()
	a.startLayerCapabilities(r, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	var body struct { Modes []string `json:"supported_raw_modes"` }
	if json.Unmarshal(r.Body.Bytes(), &body) != nil || len(body.Modes) != count { t.Fatal("native capability catalog omitted a supported family") }
	seen := map[string]bool{}
	for _, mode := range body.Modes { if seen[mode] || !mobilemultihop.NodeProfileMode(mode) { t.Fatal("duplicate or unsupported native layer mode", mode) }; seen[mode] = true }
	if ok, _ := modeMeetsAutoRequirements(testMode("unknown", "wireguard"), common.RouterProfile{StartLayer: common.StartLayerAES256GCM}); ok { t.Fatal("unknown native composition accepted") }
	if err := os.Remove(filepath.Join(dir, "NATIVE-RUNTIME.json")); err != nil { t.Fatal(err) }
	if ok, _ := modeMeetsAutoRequirements(testMode("wg", "wireguard"), common.RouterProfile{StartLayer: common.StartLayerAES256GCM}); ok { t.Fatal("missing native payload silently retained native-only composition") }
}

func TestNativeWhiteningSatisfiesOnlyItsActualObfuscationRequirement(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	dir := filepath.Join(root, "runtime", "native")
	if err := os.MkdirAll(dir, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, "NATIVE-RUNTIME.json"), []byte(`{}`), 0600); err != nil { t.Fatal(err) }
	profile := common.RouterProfile{StartLayer: common.StartLayerAES256GCMXOR, AutoRequireEncrypted: true, AutoRequireObfuscation: true}
	if ok, reason := modeMeetsAutoRequirements(testMode("wg", "wireguard"), profile); !ok { t.Fatal("authenticated whitening did not satisfy captured obfuscation", reason) }
	profile.StartLayer = common.StartLayerAES256GCM
	if ok, _ := modeMeetsAutoRequirements(testMode("wg", "wireguard"), profile); ok { t.Fatal("AES alone was classified as whitening") }
	profile.StartLayer = common.StartLayerAES256GCMXOR
	if ok, _ := modeMeetsAutoRequirements(testMode("wg", "plaintext"), profile); ok { t.Fatal("outer whitening replaced the required encrypted inner path") }
}

func TestExternalStartLayerCapabilityPreservesProvisionAndRequiresLiveOwner(t *testing.T) {
	p := desktopLayerProfile(t, "shadowsocks", common.StartLayerAES256GCMXOR)
	a := &app{profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}}, state: state{Mode: "external-shadowsocks", RuntimeMode: "external-shadowsocks", RouterID: p.ID, Connected: true, Phase: "connected"}}
	r := httptest.NewRecorder()
	a.startLayerCapabilities(r, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	var body map[string]any
	if json.Unmarshal(r.Body.Bytes(), &body) != nil || body["selected_node_supported"] != true || body["selected_start_layer"] != common.StartLayerAES256GCMXOR || body["current_runtime_layer_active"] != false { t.Fatal("external provisioning was lost or selected preferences became live proof", body) }
	if strings.Contains(r.Body.String(), testWGKey('l')) || strings.Contains(r.Body.String(), "10.77.0.1:8787") { t.Fatal("capability response exposed private provision") }
	a.profiles.Profiles[0].External.StartLayer.Mode = common.StartLayerAES256GCM
	r = httptest.NewRecorder()
	a.startLayerCapabilities(r, httptest.NewRequest(http.MethodGet, "/api/start-layer/capabilities", nil))
	if json.Unmarshal(r.Body.Bytes(), &body) != nil || body["selected_node_supported"] != false { t.Fatal("mismatched provision advertised as usable") }
}
