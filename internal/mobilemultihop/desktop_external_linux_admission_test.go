package mobilemultihop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Optional exported captures let the shipping child-body test exercise exactly
// these constructor-validated policies, rather than an invented metadata stub.
func TestDesktopExternalLinuxControlledAdmission(t *testing.T) {
	type fixture struct {
		Source  string
		Capture string
		Target  string
		Allowed bool
	}
	fixtures := map[string]fixture{}
	for _, entry := range []string{"", "wireguard", "shadowsocks", "socks5", "http-connect", "router-wg"} {
		for _, final := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2", "wireguard", "socks5"} {
			for _, target := range []string{"linux", "darwin", "windows"} {
				name := target + "-" + entry + "-" + final
				t.Run(name, func(t *testing.T) {
					graph, capture := externalTestFixture(t, final, entry)
					capture["profile"].(map[string]any)["kill_switch_policy"] = "always"
					original, compileErr := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
					if compileErr != nil {
						if entry != "http-connect" || (final != "wireguard" && final != "hysteria2") {
							t.Fatal(compileErr)
						}
						return
					}
					policy, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, target)
					allowed := target == "linux" && (entry == "" || (entry == "wireguard" || entry == "shadowsocks") && (final == "shadowsocks" || final == "http-connect" || final == "https-connect" || final == "hysteria2"))
					if allowed && (err != nil || policy.ValidateLinuxControlledAdmission() != nil) {
						t.Fatal("retained Linux composition rejected by its child", err)
					}
					if !allowed && err == nil && policy.ValidateLinuxControlledAdmission() == nil {
						t.Fatal("unadmitted composition acquired Linux child ownership")
					}
					if err == nil {
						fixtures[name] = fixture{externalTestJSON(t, graph), externalTestJSON(t, capture), target, allowed}
						altered := *policy
						altered.metadata.ConfigSHA256 = altered.metadata.SourceSHA256
						if altered.ValidateLinuxControlledAdmission() == nil {
							t.Fatal("foreign metadata admitted")
						}
					}
				})
			}
		}
	}
	for _, entryMode := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, finalMode := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			graph, capture := desktopSSEntryInput(t, desktopSS2022Methods[1], desktopSS2022Methods[2])
			profile, entry := capture["profile"].(map[string]any), capture["entry"].(map[string]any)
			profile["kill_switch_policy"] = "always"
			if entryMode != "" {
				externalTestAddLayer(entry, entryMode, "198.51.100.20", "10.94.0.1", "i")
			}
			if finalMode != "" {
				externalTestAddLayer(profile, finalMode, "203.0.113.20", "10.93.0.1", "e")
			}
			original := externalDesktopCompile(t, graph, capture)
			policy, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "linux")
			if err != nil || policy.ValidateLinuxControlledAdmission() != nil {
				t.Fatal("captured independent SS layers lost child admission", err)
			}
			fixtures["linux-ss-layers-"+entryMode+"-"+finalMode] = fixture{externalTestJSON(t, graph), externalTestJSON(t, capture), "linux", true}
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		graph, capture := desktopExternalOpenVPNEntryInput(t, network, "shadowsocks")
		fixtures["linux-openvpn-"+network+"-shadowsocks"] = fixture{externalTestJSON(t, graph), externalTestJSON(t, capture), "linux", true}
	}
	if (*DesktopExternalPolicy)(nil).ValidateLinuxControlledAdmission() == nil {
		t.Fatal("nil policy admitted")
	}
	if directory := os.Getenv("ROUTERVPN_LINUX_EXTERNAL_ADMISSION_FIXTURES"); directory != "" {
		body, err := json.Marshal(fixtures)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, "captures.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
