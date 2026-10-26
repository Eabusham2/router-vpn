package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativecomposite"
)

// This separate mandatory bundle group uses fresh reference-node assets in
// the actual desktop capture/Local/Server compilers, then runs their graph in
// the sealed engine. No OS TUN, router, Internet endpoint or user key is used.
func TestNativeCompositeDesktopEncryptedLoopback(t *testing.T) {
	binary, reference, awg := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"), os.Getenv("ROUTERVPN_COMPOSITE_REFERENCE_CLI"), os.Getenv("ROUTERVPN_AWG_REFERENCE_CLI")
	if binary == "" {
		t.Skip("complete shipping native runtime supplied by package gate")
	}
	if reference == "" || awg == "" || os.Getenv("ROUTER_VPN_XRAY_TEST_BINARY") == "" {
		t.Fatal("native package gate must supply its exact isolated composite and AWG peers")
	}
	for _, pair := range [][2]string{{"wg", "ss-v2ray"}, {"awg2-fast", "split"}, {"awg2-strong", "max"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) { nativeCompositeDesktopTraffic(t, binary, reference, awg, pair[0], pair[1]) })
	}
}

func nativeCompositeDesktopTraffic(t *testing.T, binary, reference, awg, entryMode, exitMode string) {
	t.Helper()
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
		t.Fatal("native composite fixture requires loopback")
	}
	root, selection := nativeMultihopCapturedFixture(t, entryMode, "off")
	selection.Entry.DAITAEnabled, selection.Exit.DAITAEnabled = false, false
	selection.Entry.DNSMode, selection.Entry.DNSProtocol, selection.Entry.DNSHost, selection.Entry.DNSPort, selection.Entry.DNSServerName, selection.Entry.DNSPath = "home", "", "", 0, "", ""
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := base64.StdEncoding.DecodeString(testWGKey('p'))
	entryClient, err := ecdh.X25519().NewPrivateKey(private)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	full, split := "wg.conf", "wg-socks.conf"
	if entryMode != "wg" {
		full, split = "awg.conf", "awg-socks.conf"
	}
	for _, name := range []string{full, split} {
		path := filepath.Join(root, "generated", "entry", entryMode, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(raw), testWGKey('q'), base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()))
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if entryMode == "wg" && name == full {
			selection.Entry.NodeProofID, err = nodeProofIDFromWGConfig([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	tcpEcho, udpEcho := nativeMultihopTrafficEcho(t)
	tcpTarget, udpTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpEcho)), net.JoinHostPort("127.0.0.1", strconv.Itoa(udpEcho))
	peer := nativeCompositeReferenceProcess(t, reference, selection.Exit.NodeProofID, exitMode, selection.Exit.Endpoint, map[string]string{tcpTarget: tcpTarget, udpTarget: udpTarget})
	for name, raw := range peer.Assets {
		decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil || len(decoded) == 0 || len(decoded) > 4<<20 || filepath.Base(name) != name {
			t.Fatal("reference emitted an invalid captured asset")
		}
		if err := os.WriteFile(filepath.Join(root, "generated", "exit", exitMode, name), decoded, 0600); err != nil {
			t.Fatal(err)
		}
		clear(decoded)
	}
	selection.Control, selection.ExitMode = cloneRouterProfile(selection.Entry), exitMode
	selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{exitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	captured := retainedGraph(t, []byte(selection.Native.configs[exitMode]))
	plan, err := nativecomposite.Extract(captured, exitMode, selection.Exit.NodeProofID, "", "proxy", mobilemultihop.CompositeExitPrefix, "entry-wg")
	if err != nil {
		t.Fatal(err)
	}
	leasePort := 26241
	// These physical-only fixture adapters permit the two exact captured exit
	// sockets, or the single strict AWG entry peer; the transport itself remains
	// native and encrypted. No arbitrary host, DNS or direct route is exposed.
	physical := func(t *testing.T, rules []any) int {
		port := nativeMultihopTrafficPort(t, "tcp")
		rules = append(rules, map[string]any{"action": "reject"})
		nativeMultihopTrafficProcess(t, binary, map[string]any{"inbounds": []any{map[string]any{"type": "socks", "tag": "physical", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}}, "route": map[string]any{"rules": rules}}, port)
		return port
	}
	exitPhysical := physical(t, []any{
		map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "tcp", "port": peer.TCPPort, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"},
		map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "udp", "port": peer.UDPPort, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"},
	})
	// Each trial owns a fresh encrypted entry server and its forwarding
	// sockets. A late packet from a retired trial cannot roam the reused test
	// key into a replacement client and consume its SOCKS association.
	startEntry := func(t *testing.T) (int, int) {
		entryPort := 0
		if entryMode == "wg" {
			entryPort = nativeMultihopTrafficPort(t, "udp")
			nativeMultihopTrafficProcess(t, binary, map[string]any{
				"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": base64.StdEncoding.EncodeToString(serverKey.Bytes()), "peers": []any{map[string]any{"public_key": base64.StdEncoding.EncodeToString(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}}},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}},
				"route": map[string]any{"rules": []any{
					map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "tcp", "port": peer.TCPPort, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"},
					map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "udp", "port": peer.UDPPort, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"},
					map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"},
					map[string]any{"action": "reject"},
				}},
			}, 0)
		} else {
			var endpoint map[string]any
			for _, raw := range captured["endpoints"].([]any) {
				value := raw.(map[string]any)
				if value["tag"] == "entry-wg" {
					endpoint = value
				}
			}
			forwards := []any{
				map[string]any{"network": "tcp", "address": selection.Exit.Endpoint, "port": peer.TCPPort, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(peer.TCPPort))},
				map[string]any{"network": "udp", "address": selection.Exit.Endpoint, "port": peer.UDPPort, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(peer.UDPPort))},
			}
			for _, host := range []string{"10.77.0.1", "127.0.0.1"} {
				for _, lane := range []struct {
					network string
					port    int
				}{{"tcp", leasePort}, {"udp", leasePort + 1}} {
					forwards = append(forwards, map[string]any{"network": lane.network, "address": host, "port": lane.port, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(lane.port))})
				}
			}
			entryPort = nativeAmneziaReferenceProcess(t, awg, map[string]any{"private_key": base64.StdEncoding.EncodeToString(serverKey.Bytes()), "addresses": []string{"10.77.0.1/24"}, "parameters": endpoint["amnezia"], "peers": []any{map[string]any{"public_key": base64.StdEncoding.EncodeToString(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}, "forward": forwards})
		}
		entryPhysical := 0
		if entryMode != "wg" {
			entryPhysical = physical(t, []any{map[string]any{"ip_cidr": []string{selection.Entry.Endpoint + "/32"}, "network": "udp", "port": 51820, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": entryPort}})
		}
		return entryPort, entryPhysical
	}
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			var descriptor *desktopExecutionDescriptor
			var serverConfig map[string]any
			if execution == "server" {
				request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: exitMode}
				lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
				descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
				paired := multihoprelay.Exit{ID: selection.Exit.ID, Mode: exitMode, NodeID: selection.Exit.NodeProofID, DNS: selection.Exit.AdGuardIPv4, Transport: plan}
				raw, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
				if err != nil {
					t.Fatal(err)
				}
				serverConfig = retainedGraph(t, raw)
				if _, err := nativecomposite.Extract(serverConfig, exitMode, selection.Exit.NodeProofID, "", "exit", multihoprelay.CompositePrefix, ""); err != nil {
					t.Fatal(err)
				}
				serverConfig["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
				serverConfig["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
				for _, raw := range serverConfig["outbounds"].([]any) {
					out := raw.(map[string]any)
					if out["tag"] == multihoprelay.CompositePrefix+"tcp" || out["tag"] == multihoprelay.CompositePrefix+"udp" {
						out["detour"] = "fixture-exit-sockets"
					}
				}
				serverConfig["outbounds"] = append(serverConfig["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-exit-sockets", "server": "127.0.0.1", "server_port": exitPhysical, "version": "5"})
			}
			launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			faults := []string{"none", "wrong-tcp-secret", "wrong-udp-secret", "restored-secrets"}
			if execution == "server" {
				faults = append(faults, "wrong-lease-password", "restored-lease")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					entryPort, entryPhysical := startEntry(t)
					graph := retainedGraph(t, launch.config)
					clientPort := nativeMultihopTrafficPort(t, "tcp")
					graph["inbounds"] = []any{map[string]any{"type": "socks", "tag": "fixture-traffic", "listen": "127.0.0.1", "listen_port": clientPort}}
					graph["route"].(map[string]any)["auto_detect_interface"] = false
					for _, raw := range graph["endpoints"].([]any) {
						endpoint := raw.(map[string]any)
						if endpoint["tag"] != "entry-wg" {
							t.Fatal("composite invented a packet exit")
						}
						if entryMode == "wg" {
							endpoint["bind_interface"] = loopback
							peer := endpoint["peers"].([]any)[0].(map[string]any)
							peer["address"], peer["port"] = "127.0.0.1", entryPort
						} else {
							endpoint["detour"] = "fixture-entry-socket"
							graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-entry-socket", "server": "127.0.0.1", "server_port": entryPhysical, "version": "5"})
						}
					}
					mutate := func(value map[string]any, prefix string) {
						for _, raw := range value["outbounds"].([]any) {
							out := raw.(map[string]any)
							if fault == "wrong-udp-secret" && out["tag"] == prefix+"udp" {
								out["password"] = "wrong-owned-node-udp-secret"
							}
							if fault == "wrong-tcp-secret" && out["tag"] == prefix+"tcp" {
								if exitMode == "ss-v2ray" {
									out["password"] = testWGKey('y')
								} else {
									doc := retainedGraph(t, []byte(out["config_json"].(string)))
									doc["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["id"] = "22222222-2222-4222-8222-222222222222"
									encoded, _ := json.Marshal(doc)
									out["config_json"] = string(encoded)
								}
							}
						}
					}
					if execution == "server" {
						server := cloneNativePacketTrafficGraph(t, serverConfig)
						mutate(server, multihoprelay.CompositePrefix)
						backendPort := nativeMultihopTrafficPort(t, "tcp")
						server["inbounds"].([]any)[0].(map[string]any)["listen_port"] = backendPort
						nativeMultihopTrafficProcess(t, binary, server, backendPort)
						nativeMultihopPrivateSOCKSAdapter(t, leasePort, leasePort+1, backendPort)
						if fault == "wrong-lease-password" {
							for _, raw := range graph["outbounds"].([]any) {
								out := raw.(map[string]any)
								if out["tag"] == "proxy" {
									out["password"] = "wrong-owned-lease"
								}
							}
						}
					} else {
						mutate(graph, mobilemultihop.CompositeExitPrefix)
					}
					nativeMultihopTrafficProcess(t, binary, graph, clientPort)
					for _, network := range []string{"tcp", "udp"} {
						target := tcpEcho
						if network == "udp" {
							target = udpEcho
						}
						negative := fault == "wrong-lease-password" || fault == "wrong-"+network+"-secret"
						timeout := 8 * time.Second
						if negative {
							timeout = 3 * time.Second
						}
						err := nativeMultihopTrafficExchangeTo(clientPort, target, network, [4]byte{127, 0, 0, 1}, timeout)
						if negative && err == nil || !negative && err != nil {
							t.Fatal("actual desktop composite encrypted lane", execution, fault, network, err)
						}
					}
				})
			}
		})
	}
}

type nativeCompositeReferenceReady struct {
	Ready   bool              `json:"ready"`
	Mode    string            `json:"mode"`
	NodeID  string            `json:"node_id"`
	TCPPort int               `json:"tcp_port"`
	UDPPort int               `json:"udp_port"`
	Assets  map[string]string `json:"assets"`
}

func nativeCompositeReferenceProcess(t *testing.T, binary, nodeID, mode, host string, targets map[string]string) nativeCompositeReferenceReady {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "peer.json")
	encoded, _ := json.Marshal(map[string]any{"mode": mode, "node_id": nodeID, "host": host, "targets": targets})
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestDesktopCompositeReferencePeer$", "-test.timeout=180s")
	command.Env = append(os.Environ(), "ROUTERVPN_COMPOSITE_REFERENCE_CONFIG="+path)
	command.Stderr = io.Discard
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		input.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	readFinished := make(chan struct{})
	ready := make(chan nativeCompositeReferenceReady, 1)
	readFailure := make(chan error, 1)
	go func() {
		defer close(readFinished)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		seen := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "ROUTERVPN_COMPOSITE_REFERENCE ") {
				var value nativeCompositeReferenceReady
				decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "ROUTERVPN_COMPOSITE_REFERENCE ")))
				decoder.DisallowUnknownFields()
				if seen || decoder.Decode(&value) != nil {
					readFailure <- errors.New("ambiguous composite reference readiness")
					return
				}
				seen = true
				ready <- value
			}
		}
		if err := scanner.Err(); err != nil {
			readFailure <- errors.New("composite reference owner pipe failed")
		}
	}()
	go func() { <-readFinished; done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("composite reference failed its encrypted-lane or joined-shutdown checks", err)
			}
		case <-time.After(8 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("composite reference did not join its owned native peers")
		}
		<-readFinished
		select {
		case err := <-readFailure:
			t.Error(err)
		default:
		}
	})
	select {
	case value := <-ready:
		if !value.Ready || value.Mode != mode || value.NodeID != nodeID || value.TCPPort < 1 || value.TCPPort > 65535 || value.UDPPort < 1 || value.UDPPort > 65535 || len(value.Assets) != 3 {
			t.Fatal("composite reference did not produce its exact captured node")
		}
		return value
	case err := <-readFailure:
		t.Fatal(err)
	case <-readFinished:
		t.Fatal("composite reference exited before its owned readiness record")
	case <-time.After(10 * time.Second):
		t.Fatal("composite reference readiness timed out")
	}
	return nativeCompositeReferenceReady{}
}
