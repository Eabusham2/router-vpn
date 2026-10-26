package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
)

// Separate mandatory native-bundle group: keep the existing native test budget
// while exercising actual independent AWG peers. No production AWG listener is
// enabled. Its test-only reference allows precisely the captured echo/forward
// sockets and joins every owned device and handler on stdin EOF.
func TestNativeAmneziaMultihopEncryptedLoopback(t *testing.T) {
	binary, reference := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"), os.Getenv("ROUTERVPN_AWG_REFERENCE_CLI")
	if binary == "" {
		t.Skip("complete shipping native runtime supplied by package gate")
	}
	if reference == "" {
		t.Fatal("native package gate must supply its isolated AWG peer")
	}
	for index, pair := range [][2]string{{"wg", "awg2-fast"}, {"awg2-fast", "awg2-strong"}, {"awg2-strong", "awg2-fast"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) { nativeAmneziaMultihopTraffic(t, binary, reference, pair[0], pair[1], index) })
	}
}

func nativeAmneziaMultihopTraffic(t *testing.T, binary, reference, entryMode, exitMode string, index int) {
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
		t.Fatal("loopback adapter unavailable")
	}
	root, selection := nativeMultihopCapturedFixture(t, entryMode, "off")
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
	entryPSK, exitPSK := testWGKey('h'), testWGKey('k')
	for _, node := range []string{"entry", "exit"} {
		mode, full, split := entryMode, "wg.conf", "wg-socks.conf"
		if node == "exit" {
			mode = exitMode
		}
		if mode != "wg" {
			full, split = "awg.conf", "awg-socks.conf"
		}
		for _, name := range []string{full, split} {
			path := filepath.Join(root, "generated", node, mode, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text, psk := string(raw), entryPSK
			if node == "entry" {
				text = strings.ReplaceAll(text, testWGKey('q'), encoded(entryServer.PublicKey().Bytes()))
			} else {
				text = strings.NewReplacer(testWGKey('w'), encoded(exitServer.PublicKey().Bytes()), testWGKey('v'), encoded(localExit.Bytes())).Replace(text)
				psk = exitPSK
			}
			text = strings.Replace(text, "[Peer]\n", "[Peer]\nPresharedKey = "+psk+"\n", 1)
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			// AWG's transport key is independent of the stable paired WG
			// node proof identity. Never replace that identity with AWG's key.
			if node == "entry" && mode == "wg" && name == full {
				selection.Entry.NodeProofID, err = nodeProofIDFromWGConfig([]byte(text))
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	selection.Control, selection.ExitMode = cloneRouterProfile(selection.Entry), exitMode
	selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{exitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	captured := retainedGraph(t, []byte(selection.Native.configs[exitMode]))
	var entryEndpoint, exitEndpoint map[string]any
	for _, raw := range captured["endpoints"].([]any) {
		endpoint := raw.(map[string]any)
		if endpoint["tag"] == "entry-wg" {
			entryEndpoint = endpoint
		}
		if endpoint["tag"] == "proxy" {
			exitEndpoint = endpoint
		}
	}
	if exitEndpoint["type"] != mobilemultihop.AmneziaType || selection.Native.localPacketPublic[exitMode] != encoded(localExit.PublicKey().Bytes()) {
		t.Fatal("captured AWG protocol or private peer identity changed")
	}
	tcpEcho, udpEcho := nativeMultihopTrafficPort(t, "tcp"), nativeMultihopTrafficPort(t, "udp")
	exitPort := nativeAmneziaReferenceProcess(t, reference, map[string]any{
		"private_key": encoded(exitServer.Bytes()), "addresses": []string{"10.88.0.1/24"}, "parameters": exitEndpoint["amnezia"],
		"peers": []any{
			map[string]any{"public_key": encoded(localExit.PublicKey().Bytes()), "pre_shared_key": exitPSK, "allowed_ips": []string{"10.88.0.2/32"}},
			map[string]any{"public_key": encoded(serverExit.PublicKey().Bytes()), "pre_shared_key": exitPSK, "allowed_ips": []string{"10.88.0.3/32"}},
		},
		"echo": []any{map[string]any{"network": "tcp", "address": "192.0.2.99", "port": tcpEcho}, map[string]any{"network": "udp", "address": "192.0.2.99", "port": udpEcho}},
	})
	leasePort, entryPort := 26241, 0
	if entryMode == "wg" {
		entryPort = nativeMultihopTrafficPort(t, "udp")
		nativeMultihopTrafficProcess(t, binary, map[string]any{
			"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": encoded(entryServer.Bytes()), "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "pre_shared_key": entryPSK, "allowed_ips": []string{"10.77.0.2/32"}}}}},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "owned-exit-only"}},
			"route": map[string]any{"rules": []any{
				map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "udp", "port": 51820, "action": "route", "outbound": "owned-exit-only", "override_address": "127.0.0.1", "override_port": exitPort},
				map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "owned-exit-only", "override_address": "127.0.0.1"},
				map[string]any{"action": "reject"},
			}},
		}, 0)
	} else {
		forwards := []any{map[string]any{"network": "udp", "address": selection.Exit.Endpoint, "port": 51820, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(exitPort))}}
		for _, address := range []string{"10.77.0.1", "127.0.0.1"} {
			for _, lane := range []struct {
				network string
				port    int
			}{{"tcp", leasePort}, {"udp", leasePort + 1}} {
				forwards = append(forwards, map[string]any{"network": lane.network, "address": address, "port": lane.port, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(lane.port))})
			}
		}
		entryPort = nativeAmneziaReferenceProcess(t, reference, map[string]any{
			"private_key": encoded(entryServer.Bytes()), "addresses": []string{"10.77.0.1/24"}, "parameters": entryEndpoint["amnezia"],
			"peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "pre_shared_key": entryPSK, "allowed_ips": []string{"10.77.0.2/32"}}}, "forward": forwards,
		})
	}
	// Keep strict captured unicast peer addresses intact. These isolated
	// SOCKS lanes map only their exact physical sockets to the reference;
	// they cannot resolve names or forward any unrelated destination.
	physical := func(address string, port int) int {
		listener := nativeMultihopTrafficPort(t, "tcp")
		nativeMultihopTrafficProcess(t, binary, map[string]any{
			"inbounds":  []any{map[string]any{"type": "socks", "tag": "physical", "listen": "127.0.0.1", "listen_port": listener}},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}},
			"route": map[string]any{"rules": []any{
				map[string]any{"ip_cidr": []string{address + "/32"}, "network": "udp", "port": 51820, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": port},
				map[string]any{"action": "reject"},
			}},
		}, listener)
		return listener
	}
	exitPhysical := physical(selection.Exit.Endpoint, exitPort)
	entryPhysical := 0
	if entryMode != "wg" {
		entryPhysical = physical(selection.Entry.Endpoint, entryPort)
	}
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			var descriptor *desktopExecutionDescriptor
			var serverConfig map[string]any
			if execution == "server" {
				request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: exitMode, ExpectedPacketPublicKey: encoded(serverExit.PublicKey().Bytes())}
				lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
				descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
				paired := multihoprelay.Exit{ID: selection.Exit.ID, Mode: exitMode, NodeID: selection.Exit.NodeProofID, DNS: "10.88.0.53", Transport: map[string]any{"type": mobilemultihop.AmneziaType, "amnezia": exitEndpoint["amnezia"], "private_key": encoded(serverExit.Bytes()), "address": []string{"10.88.0.3/32"}, "mtu": 1280, "peers": []any{map[string]any{"address": selection.Exit.Endpoint, "port": 51820, "public_key": encoded(exitServer.PublicKey().Bytes()), "pre_shared_key": exitPSK, "persistent_keepalive_interval": 25, "allowed_ips": []string{"0.0.0.0/0", "::/0"}}}}}
				raw, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
				if err != nil {
					t.Fatal(err)
				}
				serverConfig = retainedGraph(t, raw)
				serverConfig["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
				serverConfig["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
				endpoint := serverConfig["endpoints"].([]any)[0].(map[string]any)
				endpoint["detour"] = "fixture-exit-socket"
				serverConfig["outbounds"] = append(serverConfig["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-exit-socket", "server": "127.0.0.1", "server_port": exitPhysical, "version": "5"})
			}
			launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			faults := []string{"none"}
			if index < 2 {
				faults = append(faults, "wrong-exit-key", "restored-key")
			}
			if index == 2 && execution == "server" {
				faults = append(faults, "wrong-lease-password", "restored-key")
			}
			if index == 1 && execution == "local" {
				faults = append(faults, "wrong-S4", "restored-parameters")
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
							if entryMode == "wg" {
								endpoint["bind_interface"] = loopback
								peer["address"], peer["port"] = "127.0.0.1", entryPort
							} else {
								endpoint["detour"] = "fixture-entry-socket"
								graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-entry-socket", "server": "127.0.0.1", "server_port": entryPhysical, "version": "5"})
							}
						} else if endpoint["tag"] == "proxy" {
							packetExit = true
							if endpoint["type"] != mobilemultihop.AmneziaType || endpoint["detour"] != "entry-wg" || peer["address"] != selection.Exit.Endpoint || peer["pre_shared_key"] != exitPSK {
								t.Fatal("captured packet exit or actual entry detour was replaced")
							}
							if fault == "wrong-exit-key" {
								peer["public_key"] = encoded(entryServer.PublicKey().Bytes())
							}
							if fault == "wrong-S4" {
								endpoint["amnezia"].(map[string]any)["s4"] = "48"
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
					negative := strings.HasPrefix(fault, "wrong-")
					networks := []string{"tcp", "udp"}
					if negative {
						networks = []string{"tcp"}
					}
					for _, network := range networks {
						port := tcpEcho
						if network == "udp" {
							port = udpEcho
						}
						// The exit may start before its entry is ready and AWG
						// then performs its real 5s handshake retry. Keep an explicit
						// bound that covers that retry, without changing production.
						err := nativeMultihopTrafficExchangeTo(clientPort, port, network, [4]byte{192, 0, 2, 99}, 12*time.Second)
						if negative && err == nil || !negative && err != nil {
							t.Fatal("real AWG packet entry/exit exchange", execution, fault, network, err)
						}
					}
				})
			}
		})
	}
}

func nativeAmneziaReferenceProcess(t *testing.T, binary string, config map[string]any) int {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "reference.json")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "reference.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "--config", path, "--shutdown-stdin")
	command.Stderr = log
	input, err := command.StdinPipe()
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		_ = log.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("AWG reference failed to join owned shutdown", err)
			}
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("AWG reference failed to close its owned device and handlers")
		}
		_ = log.Close()
		if t.Failed() {
			body, _ := os.ReadFile(logPath)
			t.Log(string(body))
		}
	})
	type readiness struct {
		Listen string `json:"listen"`
		Ready  bool   `json:"ready"`
	}
	ready := make(chan readiness, 1)
	go func() {
		var value readiness
		_ = json.NewDecoder(bufio.NewReader(output)).Decode(&value)
		ready <- value
	}()
	select {
	case value := <-ready:
		address, err := netip.ParseAddrPort(value.Listen)
		if err != nil || !value.Ready || address.Addr() != netip.MustParseAddr("127.0.0.1") || address.Port() == 0 {
			t.Fatal("reference did not bind an owned loopback packet socket", value)
		}
		return int(address.Port())
	case <-time.After(5 * time.Second):
		t.Fatal("AWG reference readiness timed out")
		return 0
	}
}
