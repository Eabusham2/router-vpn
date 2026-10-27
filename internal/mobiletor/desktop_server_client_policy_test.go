package mobiletor

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDesktopServerTorPolicyKeepsCompleteDeviceAndPrivateEntryPolicy(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "shadowsocks", "naive-h2"} {
		for _, target := range []string{"windows", "darwin", "linux"} {
			for _, dnsMode := range []string{"custom", "home"} {
				t.Run(mode+"/"+target+"/"+dnsMode, func(t *testing.T) {
					entry, _ := desktopEntryFixture(t, mode, "aes-256-gcm+xor-whitening", nil)
					profile := desktopEntryExit(entry)
					profile["dns_mode"], profile["dns_protocol"], profile["dns_host"] = dnsMode, "tls", "9.9.9.9"
					profile["dns_port"], profile["dns_server_name"] = 8853, "selected.example"
					profile["ipv6_mode"], profile["home_lan_access"] = "off", false
					if dnsMode == "home" {
						profile["dns_host"] = "10.80.0.53"
					}
					local, err := NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, profile), desktopSession, desktopIsolation, target, entry)
					if err != nil {
						t.Fatal(err)
					}
					profile["multihop_execution"] = "server"
					source := torHostEncode(t, profile)
					if err := ValidateDesktopBridgeProfile(source); err != nil {
						t.Fatal("saved Server validation", err)
					}
					policy, err := NewDesktopServerTorPolicy(source, desktopSession, desktopIsolation, target, entry)
					if err != nil {
						t.Fatal(err)
					}
					meta := policy.Metadata()
					if policy.Profile() != source || meta.Execution != "server" || meta.SocksPort != 0 || policy.ServerPolicy() == nil || meta.ServerSourceSHA256 != policy.ServerPolicy().SourceSHA256() || meta.ServerDNSPolicySHA256 != policy.ServerPolicy().DNSPolicySHA256() || meta.SourceSHA256 == local.SourceSHA256() {
						t.Fatal("Server authority or source identity was lost")
					}
					selected, err := SelectDesktopBridgeDNS(source, entry.Profile(), false)
					if err != nil || selected != meta.DNS || selected != policy.ServerPolicy().DNS() {
						t.Fatal("selected client/server DNS differs", err)
					}
					before, after := local.Metadata(), meta
					before.SourceSHA256, after.SourceSHA256 = "", ""
					before.ConfigSHA256, after.ConfigSHA256 = "", ""
					before.SocksPort, after.SocksPort = 0, 0
					before.BootstrapDNSTag = ""
					after.Execution, after.ServerSourceSHA256, after.ServerDNSPolicySHA256 = "", "", ""
					if before != after {
						t.Fatal("device or entry policy changed during Server compilation")
					}
					graph, _ := profileObject(policy.Config(), 4<<20)
					outbound := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
					if outbound["type"] != ServerTorClientType || outbound["entry_tag"] != entry.Tag() || outbound["entry_profile"] != entry.Profile() || outbound["server_source"] != policy.ServerPolicy().Source() || outbound["server"] != nil || outbound["server_port"] != nil {
						t.Fatal("final native path retained local SOCKS or lost the captured entry")
					}
					if _, err := NewDesktopBridgePolicyWithPredecessor(source, desktopSession, desktopIsolation, target, entry); err == nil {
						t.Fatal("local factory accepted Server")
					}
				})
			}
		}
	}
}

func TestDesktopServerTorCaptureCannotBecomeLocalOrAdoptAnotherEntry(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
	profile := desktopEntryExit(entry)
	profile["multihop_execution"] = "server"
	source := torHostEncode(t, profile)
	input, err := NewDesktopServerTorCapture(source, desktopSession, desktopIsolation, "linux", filepath.Join(t.TempDir(), "owned-server"), entry)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDesktopBridgeCapture(source, input.JSON(), input.RuntimeDir())
	if err != nil || !reflect.DeepEqual(decoded, input) || input.Torrc() != "\n" || input.Defaults() != "\n" || input.Capture().Schema != 2 || input.Capture().TorBinary != "" {
		t.Fatal("Server reconstruction acquired local process input", err)
	}
	for name, edit := range map[string]func(map[string]any){
		"local schema":  func(p map[string]any) { p["schema"] = 1 },
		"executable":    func(p map[string]any) { p["tor_binary"] = filepath.Join(t.TempDir(), "tor") },
		"missing entry": func(p map[string]any) { delete(p, "predecessor") },
		"wrong entry": func(p map[string]any) {
			p["predecessor"].(map[string]any)["profile"].(map[string]any)["id"] = "another-private-router"
		},
	} {
		t.Run(name, func(t *testing.T) {
			capture, _ := profileObject(input.JSON(), DesktopBridgeCaptureLimit)
			edit(capture)
			if _, err := DecodeDesktopBridgeCapture(source, torHostEncode(t, capture), input.RuntimeDir()); err == nil {
				t.Fatal("foreign Server capture admitted")
			}
		})
	}
	for _, execution := range []string{"local", "auto", "compare", ""} {
		profile["multihop_execution"] = execution
		if _, err := NewDesktopServerTorPolicy(torHostEncode(t, profile), desktopSession, desktopIsolation, "linux", entry); err == nil {
			t.Fatal("Server factory accepted another execution", execution)
		}
		if _, err := DecodeDesktopBridgeCapture(torHostEncode(t, profile), input.JSON(), input.RuntimeDir()); err == nil {
			t.Fatal("Server capture discarded execution", execution)
		}
	}
}

func TestDesktopServerTorCanonicalDNSKeepsHomeDefaultAndExplicitEncryptedTransport(t *testing.T) {
	entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
	for _, mode := range []string{"", "dot", "doh"} {
		t.Run("saved="+mode, func(t *testing.T) {
			profile := desktopEntryExit(entry)
			profile["multihop_execution"], profile["dns_mode"] = "server", mode
			wantMode, wantTransport, wantHost := "custom", "tls", "9.9.9.9"
			profile["dns_host"], profile["dns_port"], profile["dns_protocol"] = wantHost, 853, "udp"
			profile["dns_server_name"] = "selected.example"
			if mode == "" {
				wantMode, wantTransport, wantHost = "home", "udp", "10.80.0.53"
				delete(profile, "dns_host")
				delete(profile, "dns_port")
				delete(profile, "dns_protocol")
				delete(profile, "dns_server_name")
			} else if mode == "doh" {
				wantTransport = "https"
				profile["dns_port"], profile["dns_path"] = 443, "/selected-dns"
			}
			source := torHostEncode(t, profile)
			policy, err := NewDesktopServerTorPolicy(source, desktopSession, desktopIsolation, "linux", entry)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := SelectDesktopBridgeDNS(source, entry.Profile(), false)
			if err != nil || policy.Profile() != source || selected != policy.Metadata().DNS || selected != policy.ServerPolicy().DNS() || selected.Mode != wantMode || selected.Transport != wantTransport || selected.Address != wantHost {
				t.Fatal("saved DNS default or alias changed the actual resolver", selected, err)
			}
		})
	}
}
