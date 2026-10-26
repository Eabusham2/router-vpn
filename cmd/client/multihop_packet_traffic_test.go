package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

// Runs the actual captured Local graph and the finalized Server graph through
// two encrypted packet peers. The Server exit uses the production relay Build
// and independent client key. Loopback adapters replace only physical sockets,
// the system-TUN input and the relay's private bind/source address; no host
// interface, route, private router, public network or user credential is used.
func TestNativeMultihopWGWireGuardEncryptedLoopback(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI")
	if binary == "" {
		t.Skip("complete native runtime supplied by the package gate")
	}
	adapters, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	loopback := ""
	for _, adapter := range adapters {
		if adapter.Flags&net.FlagLoopback != 0 {
			loopback = adapter.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("loopback adapter unavailable")
	}
	root, selection := nativeMultihopCapturedFixture(t, "wg", "off")
	selection.Entry.DAITAEnabled, selection.Exit.DAITAEnabled = false, false
	selection.Entry.DNSMode, selection.Entry.DNSProtocol, selection.Entry.DNSHost, selection.Entry.DNSPort, selection.Entry.DNSServerName, selection.Entry.DNSPath = "home", "", "", 0, "", ""
	key := func() *ecdh.PrivateKey {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	entryServer, exitServer, localExit, serverExit := key(), key(), key(), key()
	encoded := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	entryPrivate, _ := base64.StdEncoding.DecodeString(testWGKey('p'))
	entryClient, _ := ecdh.X25519().NewPrivateKey(entryPrivate)
	for _, node := range []string{"entry", "exit"} {
		for _, name := range []string{"wg.conf", "wg-socks.conf"} {
			path := filepath.Join(root, "generated", node, "wg", name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if node == "entry" {
				raw = bytes.ReplaceAll(raw, []byte(testWGKey('q')), []byte(encoded(entryServer.PublicKey().Bytes())))
			} else {
				raw = bytes.ReplaceAll(raw, []byte(testWGKey('r')), []byte(encoded(exitServer.PublicKey().Bytes())))
				raw = bytes.ReplaceAll(raw, []byte(testWGKey('p')), []byte(encoded(localExit.Bytes())))
				raw = bytes.ReplaceAll(raw, []byte("10.77.0."), []byte("10.88.0."))
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if name == "wg.conf" {
				id, err := nodeProofIDFromWGConfig(raw)
				if err != nil {
					t.Fatal(err)
				}
				if node == "entry" {
					selection.Entry.NodeProofID = id
				} else {
					selection.Exit.NodeProofID = id
				}
			}
		}
	}
	selection.Control, selection.ExitMode = cloneRouterProfile(selection.Entry), "wg"
	selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{"wg"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tcpEcho, udpEcho := nativeMultihopTrafficEcho(t)
	exitPort, entryPort := nativeMultihopTrafficPort(t, "udp"), nativeMultihopTrafficPort(t, "udp")
	nativeMultihopTrafficProcess(t, binary, map[string]any{
		"endpoints": []any{map[string]any{"type": "wireguard", "tag": "exit-server", "system": false, "bind_interface": loopback, "address": []string{"10.88.0.1/24"}, "listen_port": exitPort, "private_key": encoded(exitServer.Bytes()), "peers": []any{
			map[string]any{"public_key": encoded(localExit.PublicKey().Bytes()), "allowed_ips": []string{"10.88.0.2/32"}},
			map[string]any{"public_key": encoded(serverExit.PublicKey().Bytes()), "allowed_ips": []string{"10.88.0.3/32"}},
		}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "echo-only"}},
		"route": map[string]any{"rules": []any{
			map[string]any{"ip_cidr": []string{"192.0.2.99/32"}, "network": "tcp", "port": tcpEcho, "action": "route", "outbound": "echo-only", "override_address": "127.0.0.1"},
			map[string]any{"ip_cidr": []string{"192.0.2.99/32"}, "network": "udp", "port": udpEcho, "action": "route", "outbound": "echo-only", "override_address": "127.0.0.1"},
			map[string]any{"action": "reject"},
		}},
	}, 0)
	leasePort := 26241
	nativeMultihopTrafficProcess(t, binary, map[string]any{
		"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": encoded(entryServer.Bytes()), "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "owned-exit-only"}},
		"route": map[string]any{"rules": []any{
			map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "udp", "port": 51820, "action": "route", "outbound": "owned-exit-only", "override_address": "127.0.0.1", "override_port": exitPort},
			map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "owned-exit-only", "override_address": "127.0.0.1"},
			map[string]any{"action": "reject"},
		}},
	}, 0)
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			var descriptor *desktopExecutionDescriptor
			var serverConfig map[string]any
			if execution == "server" {
				request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: "wg", ExpectedPacketPublicKey: encoded(serverExit.PublicKey().Bytes())}
				lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
				descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
				paired := multihoprelay.Exit{ID: selection.Exit.ID, Mode: "wg", NodeID: selection.Exit.NodeProofID, DNS: "10.88.0.53", Transport: map[string]any{"type": "wireguard", "private_key": encoded(serverExit.Bytes()), "address": []string{"10.88.0.3/32"}, "mtu": 1360, "peers": []any{map[string]any{"address": selection.Exit.Endpoint, "port": 51820, "public_key": encoded(exitServer.PublicKey().Bytes()), "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}}
				raw, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
				if err != nil {
					t.Fatal(err)
				}
				serverConfig = retainedGraph(t, raw)
				serverConfig["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
				serverConfig["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
				endpoint := serverConfig["endpoints"].([]any)[0].(map[string]any)
				endpoint["bind_interface"] = loopback
				peer := endpoint["peers"].([]any)[0].(map[string]any)
				peer["address"], peer["port"] = "127.0.0.1", exitPort
			}
			launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			faults := []string{"none", "wrong-exit-key", "restored-key"}
			if execution == "server" {
				faults = append(faults, "wrong-lease-password")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					graph := retainedGraph(t, launch.config)
					clientPort := nativeMultihopTrafficPort(t, "tcp")
					graph["inbounds"] = []any{map[string]any{"type": "socks", "tag": "fixture-traffic", "listen": "127.0.0.1", "listen_port": clientPort}}
					graph["route"].(map[string]any)["auto_detect_interface"] = false
					packetExit := false
					for _, item := range graph["endpoints"].([]any) {
						endpoint := item.(map[string]any)
						peer := endpoint["peers"].([]any)[0].(map[string]any)
						if endpoint["tag"] == "entry-wg" {
							endpoint["bind_interface"] = loopback
							peer["address"], peer["port"] = "127.0.0.1", entryPort
						} else if endpoint["tag"] == "proxy" {
							packetExit = true
							if endpoint["type"] != "wireguard" || endpoint["detour"] != "entry-wg" || peer["address"] != selection.Exit.Endpoint {
								t.Fatal("captured packet exit or actual entry detour was replaced")
							}
							if fault == "wrong-exit-key" {
								peer["public_key"] = encoded(entryServer.PublicKey().Bytes())
							}
						}
					}
					if packetExit != (execution == "local") {
						t.Fatal("Server retained a competing local packet peer")
					}
					if fault == "wrong-lease-password" {
						for _, item := range graph["outbounds"].([]any) {
							out := item.(map[string]any)
							if out["tag"] == "proxy" {
								out["password"] = "not-the-owned-native-relay-password"
							}
						}
					}
					if execution == "server" {
						// Deep copy because the negative case must not alter restore.
						server := cloneNativePacketTrafficGraph(t, serverConfig)
						backendPort := nativeMultihopTrafficPort(t, "tcp")
						server["inbounds"].([]any)[0].(map[string]any)["listen_port"] = backendPort
						if fault == "wrong-exit-key" {
							server["endpoints"].([]any)[0].(map[string]any)["peers"].([]any)[0].(map[string]any)["public_key"] = encoded(entryServer.PublicKey().Bytes())
						}
						nativeMultihopTrafficProcess(t, binary, server, backendPort)
						nativeMultihopPrivateSOCKSAdapter(t, leasePort, leasePort+1, backendPort)
					}
					nativeMultihopTrafficProcess(t, binary, graph, clientPort)
					for _, network := range []string{"tcp", "udp"} {
						port := tcpEcho
						if network == "udp" {
							port = udpEcho
						}
						// The exit may start before its entry is ready and WireGuard
						// then performs its real 5s handshake retry. Keep an explicit
						// bound that covers that retry, without changing production.
						err := nativeMultihopTrafficExchangeTo(clientPort, port, network, [4]byte{192, 0, 2, 99}, 12*time.Second)
						negative := fault == "wrong-exit-key" || fault == "wrong-lease-password"
						if negative && err == nil || !negative && err != nil {
							t.Fatal("real packet entry/exit exchange", execution, fault, network, err)
						}
					}
				})
			}
		})
	}
}

func cloneNativePacketTrafficGraph(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return retainedGraph(t, raw)
}
