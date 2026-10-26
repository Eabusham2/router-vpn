package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// This executes the exact desktop-captured entry/exit graph. The only physical
// substitutions map the paired test nodes into loopback; the client cannot
// reach the echo socket without its encrypted entry and independent SS exit.
// Server uses the real authenticated lease compiler and its fixed UDP adapter.
func TestNativeEntryMultihopProxyEncryptedLoopback(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI")
	if binary == "" {
		t.Skip("complete shipping native runtime supplied by the package gate")
	}
	for _, mode := range []string{"shadowsocks", "hysteria2", "naive-h2", "naive-h3"} {
		t.Run(mode, func(t *testing.T) {
			root, selected := nativeEntryMultihopFixture(t, mode, "off")
			selected.Entry.DAITAEnabled, selected.Exit.DAITAEnabled = false, false
			selected.Entry.DNSMode, selected.Entry.DNSProtocol, selected.Entry.DNSHost, selected.Entry.DNSPort, selected.Entry.DNSServerName, selected.Entry.DNSPath = "home", "", "", 0, "", ""
			cert, private := nativeMultihopTrafficCertificate(t)
			entryKey, exitKey := nativeEntryTrafficAESKey('e'), nativeEntryTrafficAESKey('x')
			path := filepath.Join(root, "generated", selected.Entry.ID, mode, "sing-box.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			source := retainedGraph(t, raw)
			outbound := source["outbounds"].([]any)[0].(map[string]any)
			if mode == "shadowsocks" {
				outbound["password"] = entryKey
			} else {
				outbound["tls"].(map[string]any)["certificate"] = []string{cert}
			}
			raw, _ = json.Marshal(source)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			path = filepath.Join(root, "generated", selected.Exit.ID, "shadowsocks", "sing-box.json")
			raw, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			source = retainedGraph(t, raw)
			source["outbounds"].([]any)[0].(map[string]any)["password"] = exitKey
			raw, _ = json.Marshal(source)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			selected.Control = common.CloneRouterProfile(selected.Entry)
			selected, err = captureNativeMultihopSelection(context.Background(), root, selected, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			tcpEcho, udpEcho := nativeMultihopTrafficEcho(t)
			exitPort := nativeMultihopTrafficPort(t, "tcp")
			nativeMultihopTrafficProcess(t, binary, map[string]any{
				"inbounds":  []any{map[string]any{"type": "shadowsocks", "tag": "paired-exit", "listen": "127.0.0.1", "listen_port": exitPort, "method": mobilemultihop.NativeStartLayerMethod, "password": exitKey}},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "echo-only"}},
				"route": map[string]any{"rules": []any{
					map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "network": "tcp", "port": tcpEcho, "action": "route", "outbound": "echo-only"},
					map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "network": "udp", "port": udpEcho, "action": "route", "outbound": "echo-only"},
					map[string]any{"action": "reject"},
				}},
			}, 0)
			leasePort := 26257 // Within the captured production lease range; separate from other native gates.
			for _, execution := range []string{"local", "server"} {
				t.Run(execution, func(t *testing.T) {
					var descriptor *desktopExecutionDescriptor
					if execution == "server" {
						request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selected.Entry.NodeProofID, ExitID: selected.Exit.ID, ExitMode: "shadowsocks"}
						lease := multihoprelay.Lease{Request: request, NodeID: selected.Entry.NodeProofID, ExitNodeID: selected.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
						descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
						paired := multihoprelay.Exit{ID: selected.Exit.ID, Mode: "shadowsocks", NodeID: selected.Exit.NodeProofID, DNS: selected.Exit.AdGuardIPv4, Transport: map[string]any{"type": "shadowsocks", "server": selected.Exit.Endpoint, "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": exitKey}}
						data, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
						if err != nil {
							t.Fatal(err)
						}
						server := retainedGraph(t, data)
						backend := nativeMultihopTrafficPort(t, "tcp")
						in := server["inbounds"].([]any)[0].(map[string]any)
						in["listen"], in["listen_port"] = "127.0.0.1", backend
						server["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
						remote := server["outbounds"].([]any)[0].(map[string]any)
						if remote["type"] != "shadowsocks" || remote["server"] != selected.Exit.Endpoint || remote["password"] != exitKey {
							t.Fatal("lease dropped its independent exit encryption")
						}
						remote["server"], remote["server_port"] = "127.0.0.1", exitPort
						nativeMultihopTrafficProcess(t, binary, server, 0)
						nativeMultihopPrivateSOCKSAdapter(t, leasePort, leasePort+1, backend)
					}
					launch, err := compileRetainedNativeMultihopLaunch(selected, descriptor)
					if err != nil {
						t.Fatal(err)
					}
					faults := []string{"none", "wrong-entry-secret", "restored-entry"}
					if execution == "server" {
						faults = append(faults, "wrong-lease-password", "restored-lease")
					}
					for _, fault := range faults {
						t.Run(fault, func(t *testing.T) {
							entryPort := nativeMultihopTrafficPort(t, "tcp")
							inbound := map[string]any{"tag": "paired-entry", "listen": "127.0.0.1", "listen_port": entryPort}
							switch mode {
							case "shadowsocks":
								inbound["type"], inbound["method"], inbound["password"] = "shadowsocks", mobilemultihop.NativeStartLayerMethod, entryKey
							case "hysteria2":
								inbound["type"], inbound["users"], inbound["obfs"] = "hysteria2", []any{map[string]any{"password": "captured-hysteria-password"}}, map[string]any{"type": "salamander", "password": "captured-obfuscation"}
							default:
								inbound["type"], inbound["users"] = "naive", []any{map[string]any{"username": "captured-naive-user", "password": "captured-naive-password"}}
							}
							if mode != "shadowsocks" {
								inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{cert}, "key": []string{private}}
							}
							nativeMultihopTrafficProcess(t, binary, map[string]any{
								"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"type": "direct", "tag": "paired-only"}},
								"route": map[string]any{"rules": []any{
									map[string]any{"ip_cidr": []string{selected.Exit.Endpoint + "/32"}, "port": 8388, "action": "route", "outbound": "paired-only", "override_address": "127.0.0.1", "override_port": exitPort},
									map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "paired-only", "override_address": "127.0.0.1"},
									map[string]any{"action": "reject"},
								}},
							}, 0)
							graph := retainedGraph(t, launch.config)
							clientPort := nativeMultihopTrafficPort(t, "tcp")
							graph["inbounds"] = []any{map[string]any{"type": "socks", "tag": "fixture-traffic", "listen": "127.0.0.1", "listen_port": clientPort}}
							graph["route"].(map[string]any)["auto_detect_interface"] = false
							for _, row := range graph["outbounds"].([]any) {
								out := row.(map[string]any)
								if out["tag"] == "entry-wg" {
									if out["server"] != selected.Entry.Endpoint {
										t.Fatal("entry source was not captured from its selected node")
									}
									out["server"], out["server_port"] = "127.0.0.1", entryPort
									if fault == "wrong-entry-secret" {
										out["password"] = "wrong-entry-secret"
										if mode == "shadowsocks" {
											out["password"] = nativeEntryTrafficAESKey('z')
										}
									}
								}
								if out["tag"] == "proxy" {
									if out["detour"] != "entry-wg" {
										t.Fatal("exit bypassed the captured native entry")
									}
									if fault == "wrong-lease-password" {
										out["password"] = "wrong-lease-password"
									}
								}
							}
							nativeMultihopTrafficProcess(t, binary, graph, 0)
							for _, network := range []string{"tcp", "udp"} {
								target := tcpEcho
								if network == "udp" {
									target = udpEcho
								}
								negative := strings.HasPrefix(fault, "wrong-")
								timeout := 8 * time.Second
								if negative {
									timeout = 2 * time.Second
								}
								err := nativeMultihopTrafficExchangeTo(clientPort, target, network, [4]byte{127, 0, 0, 1}, timeout)
								if negative && err == nil || !negative && err != nil {
									t.Fatal("actual captured entry path", mode, execution, fault, network, err)
								}
							}
						})
					}
				})
			}
		})
	}
}
