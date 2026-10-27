package mobiletor

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const serverTorNode = "1111111111111111111111111111111111111111111111111111111111111111"

func serverTorSource(mode string) map[string]any {
	source := map[string]any{"schema": 1, "id": "operator-tor", "entry_node_id": serverTorNode, "mode": mode,
		"dns": map[string]any{"mode": "home"}, "adguard_ipv4": "192.168.50.133", "adguard_ipv6": "fd50::133"}
	if mode == "tor-bridge" {
		source["tor_bridge"] = map[string]any{"transport": "obfs4", "bridges": []string{obfs4Bridge}}
	}
	return source
}

func serverTorPolicy(t *testing.T, source map[string]any) *ServerTorPolicy {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewServerTorPolicy(string(raw), serverTorNode)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServerTorPolicyBindsExactNoTUNDNSAndImmutableSource(t *testing.T) {
	policies := []map[string]any{
		{"mode": "home"}, {"mode": "home", "transport": "tcp", "address": "fd50::133"},
		{"mode": "home", "transport": "tls", "server_name": "dns.home.example", "port": 8853},
		{"mode": "home", "transport": "https", "server_name": "dns.home.example", "path": "/private-query"},
		{"mode": "home", "transport": "h3", "server_name": "dns.home.example"},
		{"mode": "custom", "transport": "tcp", "address": "9.9.9.9"},
		{"mode": "custom", "transport": "tls", "address": "9.9.9.9", "server_name": "dns.quad9.net"},
		{"mode": "custom", "transport": "https", "address": "9.9.9.9", "server_name": "dns.quad9.net", "path": "/dns-query"},
		{"mode": "rescue"},
	}
	for _, mode := range []string{"tor", "tor-bridge"} {
		for _, dns := range policies {
			t.Run(mode+"/"+dns["mode"].(string)+"/"+profileString(dns, "transport"), func(t *testing.T) {
				source := serverTorSource(mode)
				source["dns"] = dns
				if dns["mode"] != "home" {
					delete(source, "adguard_ipv4")
					delete(source, "adguard_ipv6")
				}
				p := serverTorPolicy(t, source)
				if p.ID() != "operator-tor" || p.EntryNodeID() != serverTorNode || p.Mode() != mode || !desktopHex(p.SourceSHA256(), 32) || !desktopHex(p.DNSPolicySHA256(), 32) {
					t.Fatal("source lost its independent captured identities")
				}
				replayed, err := NewServerTorPolicy(p.Source(), serverTorNode)
				if err != nil || replayed.Source() != p.Source() || replayed.SourceSHA256() != p.SourceSHA256() || replayed.DNSPolicySHA256() != p.DNSPolicySHA256() {
					t.Fatal("normalized private source did not reproduce", err)
				}
				source["mode"] = "replacement"
				if p.Mode() != mode {
					t.Fatal("policy retained mutable caller source")
				}
				if mode == "tor-bridge" {
					plan, err := p.Plan()
					if err != nil || len(plan.Bridges) != 1 {
						t.Fatal("captured plan missing", err)
					}
					plan.Bridges[0].Line = "replacement"
					next, err := p.Plan()
					if err != nil || next.Bridges[0].Line != obfs4Bridge {
						t.Fatal("exported plan changed immutable source")
					}
				} else if _, err := p.Plan(); err == nil {
					t.Fatal("plain Tor acquired a bridge plan")
				}
				raw, err := p.NativeConfig(19950, strings.Repeat("2", 64), strings.Repeat("3", 64))
				if err != nil {
					t.Fatal(err)
				}
				graph, err := profileObject(raw, 64<<10)
				if err != nil || len(graph) != 4 || graph["inbounds"] != nil || graph["endpoints"] != nil || graph["services"] != nil {
					t.Fatal("server source acquired a TUN or an unowned listener", err)
				}
				outbounds := graph["outbounds"].([]any)
				if len(outbounds) != 2 || outbounds[0].(map[string]any)["tag"] != ServerTorUnderlayTag || outbounds[1].(map[string]any)["tag"] != ProfileOutboundTag || outbounds[1].(map[string]any)["network"] != "tcp" {
					t.Fatal("server graph changed the exact TCP Tor path")
				}
				servers := graph["dns"].(map[string]any)["servers"].([]any)
				bootstrap, selected := servers[0].(map[string]any), servers[1].(map[string]any)
				want := ProfileOutboundTag
				if p.DNS().Mode == "home" {
					want = ServerTorUnderlayTag
				}
				if bootstrap["tag"] != bootstrapDNS || bootstrap["detour"] != ServerTorUnderlayTag || selected["tag"] != profileDNS || selected["detour"] != want || bootstrap["server"] != p.DNS().Address || selected["server"] != p.DNS().Address {
					t.Fatal("selected or bootstrap DNS substituted another policy")
				}
				if strings.Contains(raw, "tun") || strings.Contains(raw, "default_interface") || strings.Contains(raw, "exec") || strings.Contains(raw, "Proof") {
					t.Fatal("no-TUN source acquired unrelated authority")
				}
				if binary := os.Getenv("ROUTERVPN_SERVER_TOR_NATIVE_CLI"); binary != "" {
					path := filepath.Join(t.TempDir(), "server-no-tun.json")
					if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					if output, err := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput(); err != nil {
						t.Fatalf("actual native no-TUN parser rejected the captured graph: %v: %s", err, output)
					}
				}
			})
		}
	}
}

func TestServerTorSourceRejectsUploadsBorrowedAuthorityAndResolverSubstitution(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong-entry":       func(p map[string]any) { p["entry_node_id"] = strings.Repeat("2", 64) },
		"schema-null":       func(p map[string]any) { p["schema"] = nil },
		"schema-fraction":   func(p map[string]any) { p["schema"] = 1.5 },
		"unsafe-id":         func(p map[string]any) { p["id"] = "../other" },
		"torrc":             func(p map[string]any) { p["torrc"] = "SocksPort 0.0.0.0:9050" },
		"binary":            func(p map[string]any) { p["executable"] = "/tmp/tor" },
		"borrowed-token":    func(p map[string]any) { p["api_token"] = "private-other-node" },
		"uploaded-proof":    func(p map[string]any) { p["is_tor"] = true },
		"uploaded-graph":    func(p map[string]any) { p["config"] = map[string]any{"inbounds": []any{}} },
		"fixed-exit":        func(p map[string]any) { p["expected_public_ip"] = "8.8.8.8" },
		"missing-home":      func(p map[string]any) { delete(p, "adguard_ipv4"); delete(p, "adguard_ipv6") },
		"public-home":       func(p map[string]any) { p["adguard_ipv4"] = "8.8.8.8" },
		"null-home":         func(p map[string]any) { p["adguard_ipv4"] = nil },
		"foreign-home":      func(p map[string]any) { p["dns"].(map[string]any)["address"] = "192.168.1.53" },
		"host-bootstrap":    func(p map[string]any) { p["dns"].(map[string]any)["bootstrap"] = "system" },
		"dns-null":          func(p map[string]any) { p["dns"] = nil },
		"wrong-dns-type":    func(p map[string]any) { p["dns"].(map[string]any)["port"] = "53" },
		"dns-negative-port": func(p map[string]any) { p["dns"].(map[string]any)["port"] = -1 },
		"dns-ignored-path":  func(p map[string]any) { p["dns"].(map[string]any)["path"] = "/ignored" },
		"bridge-in-plain":   func(p map[string]any) { p["tor_bridge"] = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			source := serverTorSource("tor")
			change(source)
			raw, _ := json.Marshal(source)
			if _, err := NewServerTorPolicy(string(raw), serverTorNode); err == nil || strings.Contains(err.Error(), "private-other-node") {
				t.Fatal("invalid source acquired private server authority or leaked credentials")
			}
		})
	}
	p := serverTorPolicy(t, serverTorSource("tor"))
	for _, source := range []string{`{"schema":1,"schema":1}`, p.Source() + `{}`, strings.Repeat(" ", 64<<10) + p.Source()} {
		if _, err := NewServerTorPolicy(source, serverTorNode); err == nil {
			t.Fatal("duplicate, trailing or oversized source admitted")
		}
	}
	for _, port := range []int{0, 1023, 65536} {
		if _, err := p.NativeConfig(port, strings.Repeat("2", 64), strings.Repeat("3", 64)); err == nil {
			t.Fatal("invalid SOCKS port admitted")
		}
	}
	if _, err := p.NativeConfig(19950, strings.Repeat("2", 64), strings.Repeat("2", 64)); err == nil {
		t.Fatal("shared SOCKS isolation credentials admitted")
	}
}

func TestServerTorDigestsKeepSourceDNSAndEntryAuthoritiesSeparate(t *testing.T) {
	plain := serverTorPolicy(t, serverTorSource("tor"))
	bridge := serverTorPolicy(t, serverTorSource("tor-bridge"))
	if plain.SourceSHA256() == bridge.SourceSHA256() || plain.DNSPolicySHA256() != bridge.DNSPolicySHA256() {
		t.Fatal("mode and selected DNS identities were conflated")
	}
	source := serverTorSource("tor")
	source["dns"].(map[string]any)["transport"] = "tcp"
	changed := serverTorPolicy(t, source)
	if changed.DNSPolicySHA256() == plain.DNSPolicySHA256() || changed.SourceSHA256() == plain.SourceSHA256() {
		t.Fatal("selected DNS transport did not invalidate source and DNS captures")
	}
	source["entry_node_id"] = strings.Repeat("2", 64)
	raw, _ := json.Marshal(source)
	other, err := NewServerTorPolicy(string(raw), strings.Repeat("2", 64))
	if err != nil || other.SourceSHA256() == changed.SourceSHA256() || other.DNSPolicySHA256() == changed.DNSPolicySHA256() {
		t.Fatal("relinking the Home DNS entry retained its old authority", err)
	}
}
