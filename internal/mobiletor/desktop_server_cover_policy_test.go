package mobiletor

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDesktopServerTorPaddingPreservesSavedAndCanonicalPolicy(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		for _, mode := range []string{"tor", "tor-bridge"} {
			for _, enabled := range []bool{false, true} {
				for _, rate := range []int{0, 32, 64, 192} {
					t.Run(fmt.Sprintf("%s/%s/%t/%d", target, mode, enabled, rate), func(t *testing.T) {
						entry, _ := desktopEntryFixture(t, "shadowsocks", "aes-256-gcm+xor-whitening", nil)
						profile := desktopEntryExit(entry)
						profile["multihop_execution"], profile["multihop_exit_mode"] = "server", mode
						if mode == "tor" {
							profile["external"] = map[string]any{"protocol": "tor"}
						}
						profile["daita_enabled"], profile["daita_rate_kbps"] = enabled, rate
						source := torHostEncode(t, profile)
						if err := ValidateDesktopBridgeProfile(source); err != nil {
							t.Fatal("saved Server cover selection rejected", err)
						}
						selected, err := SelectDesktopBridgeDNS(source, entry.Profile(), false)
						if err != nil {
							t.Fatal("selected DNS discarded Server cover intent", err)
						}
						capture, err := NewDesktopServerTorCapture(source, desktopSession, desktopIsolation, target, filepath.Join(t.TempDir(), "owned"), entry)
						if err != nil {
							t.Fatal(err)
						}
						policy := capture.Policy()
						want := TorPaddingPolicy{Enabled: enabled, RateKbps: rate}
						if enabled && rate == 0 {
							want.RateKbps = PaddingDefaultRateKbps
						}
						if policy.Profile() != source || policy.ServerPolicy().Padding() != want || policy.ServerPolicy().DNS() != selected || policy.Metadata().DNS != selected {
							t.Fatal("Server capture replaced selected padding or DNS")
						}
						decoded, err := DecodeDesktopBridgeCapture(source, capture.JSON(), capture.RuntimeDir())
						if err != nil || !reflect.DeepEqual(capture, decoded) {
							t.Fatal("saved cover lost exact native reconstruction", err)
						}
						graph, _ := profileObject(policy.Config(), 4<<20)
						leaf := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
						if leaf["type"] != ServerTorClientType || leaf["server_source"] != policy.ServerPolicy().Source() || leaf["entry_profile"] != entry.Profile() {
							t.Fatal("compiled graph did not bind selected Server cover to private entry")
						}
						profile["daita_rate_kbps"] = 96
						replacement, err := DecodeDesktopBridgeCapture(torHostEncode(t, profile), capture.JSON(), capture.RuntimeDir())
						if err != nil || replacement.Digests().SourceSHA256 == capture.Digests().SourceSHA256 || replacement.Digests().ConfigSHA256 == capture.Digests().ConfigSHA256 || replacement.Digests().ProfileSHA256 == capture.Digests().ProfileSHA256 || replacement.Policy().ServerPolicy().SourceSHA256() == policy.ServerPolicy().SourceSHA256() || policy.ServerPolicy().Padding() != want {
							t.Fatal("different saved cover retained old source authority or mutated original", err)
						}
					})
				}
			}
		}
	}
}

func TestDesktopServerTorPaddingCannotGrantLocalOrForeignEntryAuthority(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
	for _, execution := range []string{"", "local", "compare", "server"} {
		profile := desktopEntryExit(entry)
		profile["multihop_execution"], profile["daita_enabled"], profile["daita_rate_kbps"] = execution, true, 64
		source := torHostEncode(t, profile)
		local, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, "linux", entry)
		if execution == "" || execution == "local" {
			if err != nil || local.Metadata().Padding != (TorPaddingPolicy{Enabled: true, RateKbps: 64}) || local.Metadata().Execution != "" || local.ServerPolicy() != nil {
				t.Fatal("captured Local cover acquired another execution owner", err)
			}
		} else if err == nil {
			t.Fatal("Local factory admitted Server or Compare execution")
		}
		if _, err := NewDesktopServerTorPolicy(source, desktopSession, desktopIsolation, "linux", nil); err == nil {
			t.Fatal("saved cover granted missing entry authority")
		}
		if execution != "server" {
			if _, err := NewDesktopServerTorPolicy(source, desktopSession, desktopIsolation, "linux", entry); err == nil {
				t.Fatal("Server padding silently changed execution")
			}
		}
	}
	for name, change := range map[string]func(map[string]any){
		"typed-enabled": func(p map[string]any) { p["daita_enabled"] = "true" },
		"fractional":    func(p map[string]any) { p["daita_rate_kbps"] = 64.5 },
		"over-budget":   func(p map[string]any) { p["daita_rate_kbps"] = 193 },
		"negative":      func(p map[string]any) { p["daita_rate_kbps"] = -1 },
		"entry":         func(p map[string]any) { p["multihop_entry_id"] = "another-private-entry" },
		"exit":          func(p map[string]any) { p["multihop_exit_id"] = "another-exit" },
	} {
		t.Run(name, func(t *testing.T) {
			profile := desktopEntryExit(entry)
			profile["multihop_execution"], profile["daita_enabled"], profile["daita_rate_kbps"] = "server", true, 64
			change(profile)
			if _, err := NewDesktopServerTorPolicy(torHostEncode(t, profile), desktopSession, desktopIsolation, "linux", entry); err == nil {
				t.Fatal("malformed or foreign policy became a running Server graph")
			}
		})
	}
}
