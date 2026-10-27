package mobiletor

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
)

func desktopPlainProfile() map[string]any {
	p := desktopProfile()
	p["external"] = map[string]any{"protocol": "tor"}
	p["kill_switch_policy"], p["kill_switch"] = "off", false
	return p
}

func TestDesktopPlainPolicyPreservesModeAcrossLocalServerAndCapture(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		for _, execution := range []string{"direct", "local", "server"} {
			for _, dns := range []string{"tcp", "dot", "doh"} {
				t.Run(target+"/"+execution+"/"+dns, func(t *testing.T) {
					p := desktopPlainProfile()
					p["dns_protocol"], p["dns_server_name"], p["dns_path"] = dns, "chosen.example", "/private-query"
					p["mtu_policy"], p["manual_mtu"], p["effective_mtu"] = "fixed", 1488, 9000
					var entry *DesktopPredecessor
					if execution != "direct" {
						entry, _ = desktopEntryFixture(t, "shadowsocks", "", nil)
						p["multihop_enabled"], p["multihop_entry_id"], p["multihop_exit_id"] = true, entry.ID(), p["id"]
						p["multihop_entry_mode"], p["multihop_exit_mode"], p["multihop_execution"] = entry.Mode(), "tor", execution
						p["kill_switch_policy"], p["kill_switch"] = "always", true
					}
					source := torHostEncode(t, p)
					var inputs *DesktopBridgeInputs
					var err error
					dir, binary := filepath.Join(t.TempDir(), "captured"), filepath.Join(t.TempDir(), "tor")
					if execution == "server" {
						inputs, err = NewDesktopServerTorCapture(source, desktopSession, desktopIsolation, target, dir, entry)
					} else if entry != nil {
						inputs, err = NewDesktopBridgeCaptureWithPredecessor(source, desktopSession, desktopIsolation, target, binary, dir, entry)
					} else {
						inputs, err = NewDesktopBridgeCapture(source, desktopSession, desktopIsolation, target, binary, dir)
					}
					if err != nil {
						t.Fatal(err)
					}
					policy := inputs.Policy()
					if policy.Mode() != "tor" || policy.Profile() != source || policy.Metadata().ConfiguredMTU != 1488 || policy.Metadata().DNS.Address != "9.9.9.9" {
						t.Fatal("plain Tor discarded source, selected DNS or requested MTU")
					}
					if _, err := policy.Plan(); err == nil {
						t.Fatal("plain Tor acquired a bridge transport plan")
					}
					if execution == "server" {
						if policy.ServerPolicy() == nil || policy.ServerPolicy().Mode() != "tor" || strings.Contains(policy.ServerPolicy().Source(), "tor_bridge") || inputs.Capture().TorBinary != "" || inputs.Torrc() != "\n" {
							t.Fatal("plain Server source became bridge or local process")
						}
					} else if policy.ServerPolicy() != nil || policy.Metadata().SocksPort != common.ExternalTorDefaultSocksPort || inputs.Capture().TorBinary != binary {
						t.Fatal("plain Local lost its captured standalone process")
					}
					restored, err := DecodeDesktopBridgeCapture(source, inputs.JSON(), dir)
					if err != nil || restored.Digests() != inputs.Digests() || restored.Policy().Mode() != "tor" {
						t.Fatal("plain capture changed on independent reconstruction", err)
					}
				})
			}
		}
	}
}

func TestDesktopPlainRejectsBridgeDowngradeAndUnownedProtection(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"bridge-downgrade": func(p map[string]any) {
			p["external"].(map[string]any)["tor_bridge"] = map[string]any{"transport": "obfs4", "bridges": []string{obfs4Bridge}}
		},
		"fixed-exit":    func(p map[string]any) { p["external"].(map[string]any)["expected_public_ip"] = "203.0.113.44" },
		"strict-direct": func(p map[string]any) { p["kill_switch_policy"] = "always" },
		"direct-server": func(p map[string]any) { p["multihop_execution"] = "server" },
		"unowned-projection": func(p map[string]any) {
			p["desktop_physical_egress"] = []any{map[string]any{"host": "203.0.113.44", "port": 443, "network": "tcp"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopPlainProfile()
			edit(p)
			if _, err := NewDesktopBridgePolicy(torHostEncode(t, p), desktopSession, desktopIsolation, "linux"); err == nil {
				t.Fatal("plain Tor admitted unowned policy")
			}
		})
	}
	for _, execution := range []string{"local", "server"} {
		entry, _ := desktopEntryFixture(t, "shadowsocks", "", nil)
		p := desktopEntryExit(entry)
		p["external"] = map[string]any{"protocol": "tor"}
		p["multihop_execution"] = execution // retain wrong bridge exit identity
		var err error
		if execution == "server" {
			_, err = NewDesktopServerTorPolicy(torHostEncode(t, p), desktopSession, desktopIsolation, "linux", entry)
		} else {
			_, err = NewDesktopBridgePolicyWithPredecessor(torHostEncode(t, p), desktopSession, desktopIsolation, "linux", entry)
		}
		if err == nil {
			t.Fatal("plain Tor borrowed a bridge exit selection")
		}
	}
}

// Exercise the real authenticated control protocol and real owned local proxy.
// The fixture's lower dialer never opens public-network sockets.
func TestDesktopPlainSessionRequiresExactLiveGuardReadback(t *testing.T) {
	for _, mutation := range []string{"none", "changed-proxy", "stopped-proxy", "bridge-plugin"} {
		t.Run(mutation, func(t *testing.T) {
			proxy, err := StartTCPProxy(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no public test dial") })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := proxy.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			address, username, password, err := proxy.binding()
			if err != nil {
				t.Fatal(err)
			}
			socks := "127.0.0.1:" + strconv.Itoa(common.ExternalTorDefaultSocksPort)
			expected := withEmptyProxies(map[string][]string{"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {socks + " IsolateSOCKSAuth"}, "UseBridges": {"0"}, "Bridge": {""}, "ClientTransportPlugin": {""}})
			expected["Socks5Proxy"], expected["Socks5ProxyUsername"], expected["Socks5ProxyPassword"] = []string{address}, []string{username}, []string{password}
			command := "SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort=" + torQuote(socks+" IsolateSOCKSAuth") + " UseBridges=0 Socks5Proxy=" + torQuote(address) + " Socks5ProxyUsername=" + torQuote(username) + " Socks5ProxyPassword=" + torQuote(password)
			var configured, enabled, mutate atomic.Bool
			var controlAddress atomic.Value
			wire := newDesktopControlFixture(t, func(cmd, reply string, _ int) string {
				switch {
				case cmd == command:
					configured.Store(true)
					return "250 OK\r\n"
				case cmd == "SETCONF DisableNetwork=0":
					enabled.Store(true)
					return "250 OK\r\n"
				case cmd == "SIGNAL RELOAD":
					return "250 OK\r\n"
				case cmd == clearConfiguration:
					configured.Store(false)
					enabled.Store(false)
					return "250 OK\r\n"
				case cmd == "SIGNAL CLEARDNSCACHE":
					return "250 OK\r\n"
				case cmd == "GETCONF "+configurationKeys && configured.Load():
					var out strings.Builder
					for _, key := range strings.Fields(configurationKeys) {
						values := expected[key]
						if key == "DisableNetwork" && enabled.Load() {
							values = []string{"0"}
						}
						if mutate.Load() && mutation == "changed-proxy" && key == "Socks5Proxy" {
							values = []string{"127.0.0.1:17777"}
						}
						if mutate.Load() && mutation == "bridge-plugin" && key == "ClientTransportPlugin" {
							values = []string{"obfs4 socks5 127.0.0.1:18443"}
						}
						for _, value := range values {
							out.WriteString("250-" + key + "=" + value + "\r\n")
						}
					}
					return out.String() + "250 OK\r\n"
				case strings.HasPrefix(cmd, "GETINFO net/listeners/or "):
					var out strings.Builder
					for _, key := range strings.Fields(strings.TrimPrefix(cmd, "GETINFO ")) {
						value := ""
						if key == "net/listeners/control" {
							value = strconv.Quote(controlAddress.Load().(string))
						}
						if key == "net/listeners/socks" && enabled.Load() {
							value = strconv.Quote(socks)
						}
						out.WriteString("250-" + key + "=" + value + "\r\n")
					}
					return out.String() + "250 OK\r\n"
				case cmd == "GETINFO status/bootstrap-phase status/circuit-established net/listeners/socks":
					return bootstrapReply("100", "1", strconv.Quote(socks))
				}
				return reply
			})
			controlAddress.Store(wire.address)
			owner, err := NewDesktopControl(context.Background(), wire.connection, wire.cookie, wire.pid)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close() })
			session, err := NewDesktopBridgeSession(owner, desktopPolicy(t, desktopPlainProfile(), "linux"))
			if err != nil {
				t.Fatal(err)
			}
			before := len(wire.snapshot())
			if session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}) == nil || session.ConfigurePlain(context.Background(), nil) == nil || len(wire.snapshot()) != before {
				t.Fatal("plain Tor accepted missing or bridge guard ownership")
			}
			if err := session.ConfigurePlain(context.Background(), proxy); err != nil {
				t.Fatal(err)
			}
			if err := session.EnableNetwork(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := session.Verify(context.Background()); err != nil || !session.Current() {
				t.Fatal("plain Tor did not prove captured control", err)
			}
			if mutation == "none" {
				if err := session.Quiesce(context.Background()); err != nil || session.Current() {
					t.Fatal("plain Tor did not drain", err)
				}
				return
			}
			mutate.Store(true)
			if mutation == "stopped-proxy" {
				if err := proxy.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := session.Verify(context.Background()); err == nil || session.Current() {
				t.Fatal("plain Tor retained changed or stopped guard")
			}
		})
	}
}
