package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// The native bundle runs TLS and QUIC as separate bounded groups. Every trial
// imports genuine keys into the shipping capture and executes the resulting
// Local graph or independently keyed Server lease. Only physical loopback
// sockets, the OS TUN and the private listener bind are adapted by this fixture.
func TestNativeMAXDesktopEncryptedLoopback(t *testing.T) {
	binary, reference, awg := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"), os.Getenv("ROUTERVPN_PQ_REFERENCE_CLI"), os.Getenv("ROUTERVPN_AWG_REFERENCE_CLI")
	if binary == "" {
		t.Skip("complete shipping native engine supplied by the package gate")
	}
	xray := os.Getenv("ROUTER_VPN_XRAY_TEST_BINARY")
	if reference == "" || awg == "" || xray == "" || os.Getenv("ROUTERVPN_PQ_TEST_KEYS") == "" {
		t.Fatal("complete MAX gate requires its genuine PQ/AWG keys and exact isolated Xray peer")
	}
	for _, family := range []string{"tls", "quic"} {
		t.Run(family, func(t *testing.T) {
			for _, base := range []string{"wg", "awg"} {
				mode := "max-" + family + "-" + base
				t.Run(mode, func(t *testing.T) {
					for _, execution := range []string{"local", "server"} {
						t.Run(execution, func(t *testing.T) {
							faults := []string{"none"}
							if family == "tls" && base == "wg" {
								if execution == "local" {
									faults = append(faults, "wrong-outer", "wrong-private-ss", "wrong-middle", "wrong-pq-peer")
								} else {
									faults = append(faults, "wrong-lease-password")
								}
							}
							for _, fault := range faults {
								t.Run(fault, func(t *testing.T) {
									entry := "wg"
									if base == "awg" {
										entry = "awg2-strong"
									} else if family == "quic" {
										entry = "awg2-fast"
									}
									nativeMAXDesktopTraffic(t, binary, reference, awg, xray, entry, mode, execution, fault)
								})
							}
						})
					}
				})
			}
		})
	}
}

func nativeMAXDesktopTraffic(t *testing.T, binary, reference, awg, xray, entryMode, mode, execution, fault string) {
	t.Helper()
	loopback := ""
	adapters, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range adapters {
		if adapter.Flags&net.FlagLoopback != 0 {
			loopback = adapter.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("complete MAX fixture requires the owned loopback interface")
	}
	root, selection := nativeMultihopCapturedFixture(t, entryMode, "off")
	selection.Entry.DAITAEnabled, selection.Exit.DAITAEnabled = false, false
	selection.Entry.DNSMode, selection.Entry.DNSProtocol, selection.Entry.DNSHost, selection.Entry.DNSPort, selection.Entry.DNSServerName, selection.Entry.DNSPath = "home", "", "", 0, "", ""
	key := func() *ecdh.PrivateKey {
		value, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	encoded := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	entryServer, localExit, serverExit := key(), key(), key()
	entryPrivate, _ := base64.StdEncoding.DecodeString(testWGKey('p'))
	entryClient, _ := ecdh.X25519().NewPrivateKey(entryPrivate)
	clear(entryPrivate)
	clientPublic, pqClient := localExit.PublicKey(), "client"
	if execution == "server" {
		clientPublic, pqClient = serverExit.PublicKey(), "other"
	}
	baseMode := multihoprelay.MAXBaseMode(mode)
	peer := nativePQReferenceProcess(t, reference, baseMode, encoded(clientPublic.Bytes()), pqClient)
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
		value := strings.ReplaceAll(string(raw), testWGKey('q'), encoded(entryServer.PublicKey().Bytes()))
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if entryMode == "wg" && name == full {
			selection.Entry.NodeProofID, err = nodeProofIDFromWGConfig([]byte(value))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	basePort := 51820
	full, split = "wg.conf", "wg-socks.conf"
	if baseMode == "awg2-pq" {
		full, split, basePort = "awg.conf", "awg-socks.conf", 585
	}
	packet := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.78.0.2/24\nDNS = %s\nMTU = 1420\n", encoded(localExit.Bytes()), selection.Exit.AdGuardIPv4)
	parameters := make([]string, 0, len(peer.ready.Parameters))
	for name := range peer.ready.Parameters {
		parameters = append(parameters, name)
	}
	sort.Strings(parameters)
	for _, name := range parameters {
		packet += strings.ToUpper(name[:1]) + name[1:] + " = " + peer.ready.Parameters[name] + "\n"
	}
	packet += fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:51830\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", peer.ready.PacketPublic)
	if baseMode == "wg-pq" {
		// A WG-based MAX peer is the same canonical public identity used by
		// this node's ordinary WG profile. Keep that paired source coherent
		// while the MAX builder owns its private loopback relay endpoint.
		stable := strings.Replace(packet, "Endpoint = 127.0.0.1:51830", "Endpoint = "+selection.Exit.Endpoint+":51820", 1)
		for _, name := range []string{"wg.conf", "wg-socks.conf"} {
			if err := os.WriteFile(filepath.Join(root, "generated", "exit", "wg", name), []byte(stable), 0600); err != nil {
				t.Fatal(err)
			}
		}
		selection.Exit.NodeProofID, err = nodeProofIDFromWGConfig([]byte(stable))
		if err != nil {
			t.Fatal(err)
		}
	}
	assets := nativeMultihopMAXAssets(t, selection.Exit, mode)
	assets[full], assets[split] = []byte(packet), []byte(packet)
	tool := "wg"
	if baseMode == "awg2-pq" {
		tool = "awg"
	}
	assets["rosenpass.env"] = []byte("ROSENPASS_TOOL=" + tool + "\nROSENPASS_INTERFACE=" + tool + "\nROSENPASS_WG_PEER=" + peer.ready.PacketPublic + "\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n")
	assets["rosenpass-client-secret"], assets["rosenpass-client-public"], assets["rosenpass-server-public"] = nativePQDesktopKey(t, "client", "secret"), nativePQDesktopKey(t, "client", "public"), nativePQDesktopKey(t, "server", "public")
	middlePort := nativeMultihopTrafficPort(t, "tcp")
	middleKey := testWGKey('s')
	packetPort := peer.ready.PacketPort
	var handshakeGate *nativeWGFirstHandshakeGate
	if mode == "max-quic-wg" && execution == "local" && fault == "none" {
		// Reproduce a lost initial authenticated WG response without changing
		// its PQ key, encrypted payload, packet owner or production deadline.
		handshakeGate = nativeMultihopDelayFirstWGHandshake(t, packetPort, 5*time.Second)
		packetPort = handshakeGate.port
	}
	middleRules := []any{}
	for from, to := range map[int]int{basePort: packetPort, 51822: peer.ready.PQPort} {
		middleRules = append(middleRules, map[string]any{"network": "udp", "ip_cidr": []string{"10.88.0.1/32"}, "port": from, "action": "route", "outbound": "captured-packet-peer", "override_address": "127.0.0.1", "override_port": to})
	}
	middleRules = append(middleRules, map[string]any{"action": "reject"})
	nativeMultihopTrafficProcess(t, binary, map[string]any{"inbounds": []any{map[string]any{"type": "shadowsocks", "tag": "captured-middle", "listen": "127.0.0.1", "listen_port": middlePort, "method": mobilemultihop.NativeStartLayerMethod, "password": middleKey}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-packet-peer"}}, "route": map[string]any{"rules": middleRules}}, middlePort)
	outerPort, publicPort, outerNetwork := 0, 24443, "tcp"
	var tlsPeer *nativeMAXTLSReference
	var outerPackets func() int64
	if strings.HasPrefix(mode, "max-tls-") {
		tlsPeer = nativeMAXTLSReferenceProcess(t, xray, selection.Exit.Endpoint, "10.88.0.1:8388", middlePort)
		outerPort, outerPackets = tlsPeer.OuterPort, tlsPeer.Packets
		assets["outer-xray.json"] = tlsPeer.Assets["outer-xray.json"]
	} else {
		outerPort, publicPort, outerNetwork = nativeMultihopTrafficPort(t, "udp"), 8443, "udp"
		certificate, private := nativeMultihopTrafficCertificate(t)
		bridge, packets := nativeMAXTLSUDPBridge(t, middlePort)
		outerPackets = packets
		_, bridgePort, err := net.SplitHostPort(bridge)
		if err != nil {
			t.Fatal(err)
		}
		port, _ := strconv.Atoi(bridgePort)
		password := "owned-complete-max-" + encoded(serverExit.PublicKey().Bytes())
		nativeMultihopTrafficProcess(t, binary, map[string]any{"inbounds": []any{map[string]any{"type": "hysteria2", "tag": "captured-outer", "listen": "127.0.0.1", "listen_port": outerPort, "users": []any{map[string]any{"name": "captured-max", "password": password}}, "tls": map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{private}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-middle-only"}}, "route": map[string]any{"rules": []any{map[string]any{"network": "udp", "ip_cidr": []string{"10.88.0.1/32"}, "port": 8388, "action": "route", "outbound": "captured-middle-only", "override_address": "127.0.0.1", "override_port": port}, map[string]any{"action": "reject"}}}}, 0)
		assets["cert.pem"] = []byte(certificate)
		middle := retainedGraph(t, assets["middle-sing-box.json"])
		middle["outbounds"].([]any)[0].(map[string]any)["password"] = password
		assets["middle-sing-box.json"], _ = json.Marshal(middle)
	}
	for name, raw := range assets {
		if err := os.WriteFile(filepath.Join(root, "generated", "exit", mode, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection.Control, selection.ExitMode = cloneRouterProfile(selection.Entry), mode
	selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	captured := retainedGraph(t, []byte(selection.Native.configs[mode]))
	var entryEndpoint, exitEndpoint map[string]any
	for _, raw := range captured["endpoints"].([]any) {
		value := raw.(map[string]any)
		if value["tag"] == "entry-wg" {
			entryEndpoint = value
		} else if value["tag"] == "proxy" {
			exitEndpoint = value
		}
	}
	localPQ := sha256.Sum256(assets["rosenpass-client-public"])
	if selection.Native.localPacketPublic[mode] != encoded(localExit.PublicKey().Bytes()) || selection.Native.localPQIdentity[mode] != hex.EncodeToString(localPQ[:]) || exitEndpoint["type"] != mobilemultihop.PQType || exitEndpoint["mode"] != baseMode {
		t.Fatal("complete MAX capture changed packet/KEM identity or mandatory PQ family")
	}
	leasePort := 26241
	physical := func(address, network string, from, to int) int {
		listener := nativeMultihopTrafficPort(t, "tcp")
		nativeMultihopTrafficProcess(t, binary, map[string]any{"inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": listener}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}}, "route": map[string]any{"rules": []any{map[string]any{"ip_cidr": []string{address + "/32"}, "network": network, "port": from, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": to}, map[string]any{"action": "reject"}}}}, listener)
		return listener
	}
	entryPort, entryPhysical := 0, 0
	if entryMode == "wg" {
		entryPort = nativeMultihopTrafficPort(t, "udp")
		rules := []any{map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": outerNetwork, "port": publicPort, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": outerPort}, map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"}, map[string]any{"action": "reject"}}
		nativeMultihopTrafficProcess(t, binary, map[string]any{"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": encoded(entryServer.Bytes()), "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}}, "route": map[string]any{"rules": rules}}, 0)
	} else {
		forwards := []any{map[string]any{"network": outerNetwork, "address": selection.Exit.Endpoint, "port": publicPort, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(outerPort))}}
		for _, host := range []string{"10.77.0.1", "127.0.0.1"} {
			for _, lane := range []struct {
				network string
				port    int
			}{{"tcp", leasePort}, {"udp", leasePort + 1}} {
				forwards = append(forwards, map[string]any{"network": lane.network, "address": host, "port": lane.port, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(lane.port))})
			}
		}
		entryPort = nativeAmneziaReferenceProcess(t, awg, map[string]any{"private_key": encoded(entryServer.Bytes()), "addresses": []string{"10.77.0.1/24"}, "parameters": entryEndpoint["amnezia"], "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}, "forward": forwards})
		entryPhysical = physical(selection.Entry.Endpoint, "udp", 51820, entryPort)
	}
	var descriptor *desktopExecutionDescriptor
	var serverConfig map[string]any
	if execution == "server" {
		otherPublic := nativePQDesktopKey(t, "other", "public")
		identity := sha256.Sum256(otherPublic)
		if identity == localPQ || serverExit.PublicKey().Equal(localExit.PublicKey()) {
			t.Fatal("Server reused a Local MAX classical or PQ identity")
		}
		request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: mode, ExpectedPacketPublicKey: encoded(serverExit.PublicKey().Bytes()), ExpectedPQClientIdentity: hex.EncodeToString(identity[:])}
		lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
		descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
		var children []any
		for _, raw := range captured["outbounds"].([]any) {
			value := raw.(map[string]any)
			if strings.HasPrefix(value["tag"].(string), mobilemultihop.MAXExitPrefix) {
				children = append(children, value)
			}
		}
		names := multihoprelay.MAXTags{Root: "proxy", Middle: mobilemultihop.MAXExitPrefix + "ss", Outer: mobilemultihop.MAXExitPrefix + "outer", Start: mobilemultihop.MAXExitPrefix + "start"}
		base, outputs, err := multihoprelay.RelabelMAXChain(exitEndpoint, children, mode, selection.Exit.NodeProofID, "", names, multihoprelay.MAXRelayTags(), "entry-wg", "")
		if err != nil {
			t.Fatal(err)
		}
		base["private_key"] = encoded(serverExit.Bytes())
		pq := base["pq"].(map[string]any)
		pq["secret"], pq["public"] = encoded(nativePQDesktopKey(t, "other", "secret")), encoded(otherPublic)
		paired := multihoprelay.Exit{ID: selection.Exit.ID, Mode: mode, NodeID: selection.Exit.NodeProofID, DNS: selection.Exit.AdGuardIPv4, Transport: map[string]any{"endpoint": base, "outbounds": outputs}}
		raw, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
		if err != nil {
			t.Fatal("independently paired complete MAX lease rejected", err)
		}
		serverConfig = retainedGraph(t, raw)
		serverConfig["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
		serverConfig["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
		for _, raw := range serverConfig["outbounds"].([]any) {
			value := raw.(map[string]any)
			if value["tag"] == multihoprelay.MAXRelayTags().Outer {
				value["detour"] = "fixture-exit-socket"
			}
		}
		serverConfig["outbounds"] = append(serverConfig["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-exit-socket", "server": "127.0.0.1", "server_port": physical(selection.Exit.Endpoint, outerNetwork, publicPort, outerPort), "version": "5", "udp_over_tcp": map[string]any{"enabled": true, "version": 2}})
	}
	launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	graph := retainedGraph(t, launch.config)
	clientPort := nativeMultihopTrafficPort(t, "tcp")
	graph["inbounds"] = []any{map[string]any{"type": "socks", "tag": "fixture-traffic", "listen": "127.0.0.1", "listen_port": clientPort}}
	graph["route"].(map[string]any)["auto_detect_interface"] = false
	packetExit := false
	for _, raw := range graph["endpoints"].([]any) {
		endpoint := raw.(map[string]any)
		if endpoint["tag"] == "entry-wg" {
			if entryMode == "wg" {
				endpoint["bind_interface"] = loopback
				endpoint["peers"].([]any)[0].(map[string]any)["address"] = "127.0.0.1"
				endpoint["peers"].([]any)[0].(map[string]any)["port"] = entryPort
			} else {
				endpoint["detour"] = "fixture-entry-socket"
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-entry-socket", "server": "127.0.0.1", "server_port": entryPhysical, "version": "5"})
			}
		} else if endpoint["tag"] == "proxy" {
			packetExit = true
			if endpoint["type"] != mobilemultihop.PQType || endpoint["detour"] != mobilemultihop.MAXExitPrefix+"ss" {
				t.Fatal("Local bypassed its mandatory MAX PQ/middle owner")
			}
		}
	}
	if packetExit != (execution == "local") {
		t.Fatal("Server retained a competing Local MAX packet owner")
	}
	var invalid map[string]any
	invalidPort := clientPort
	if fault != "none" && fault != "wrong-lease-password" {
		invalid = cloneNativePacketTrafficGraph(t, graph)
		if execution == "server" {
			invalid = cloneNativePacketTrafficGraph(t, serverConfig)
		}
		for _, raw := range invalid["outbounds"].([]any) {
			out := raw.(map[string]any)
			tag, _ := out["tag"].(string)
			if strings.HasSuffix(tag, "max-ss") {
				if fault == "wrong-private-ss" {
					out["server_port"] = float64(8387)
				}
				if fault == "wrong-middle" {
					out["password"] = testWGKey('t')
				}
			}
			if fault == "wrong-outer" && out["type"] == "routervpn-xray" {
				xrayGraph := retainedGraph(t, []byte(out["config_json"].(string)))
				xrayGraph["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["id"] = "22222222-2222-4222-8222-222222222222"
				body, _ := json.Marshal(xrayGraph)
				out["config_json"] = string(body)
			}
		}
		if fault == "wrong-pq-peer" {
			wrong := "other"
			if execution == "server" {
				wrong = "client"
			}
			for _, raw := range invalid["endpoints"].([]any) {
				endpoint := raw.(map[string]any)
				if endpoint["type"] == mobilemultihop.PQType {
					endpoint["pq"].(map[string]any)["peer"] = encoded(nativePQDesktopKey(t, wrong, "public"))
				}
			}
		}
	}
	if execution == "server" {
		backendPort := nativeMultihopTrafficPort(t, "tcp")
		serverConfig["inbounds"].([]any)[0].(map[string]any)["listen_port"] = backendPort
		if invalid != nil {
			invalid["inbounds"].([]any)[0].(map[string]any)["listen_port"], invalidPort = backendPort, backendPort
		}
		if invalid != nil {
			nativeMAXUnprovedProcess(t, binary, invalid, invalidPort, peer, tlsPeer, outerPackets, fault)
		}
		nativeMultihopTrafficProcess(t, binary, serverConfig, backendPort)
		nativeMultihopPrivateSOCKSAdapter(t, leasePort, leasePort+1, backendPort)
		if fault == "wrong-lease-password" {
			for _, raw := range graph["outbounds"].([]any) {
				out := raw.(map[string]any)
				if out["tag"] == "proxy" {
					out["password"] = "not-the-owned-max-lease"
				}
			}
		}
	} else if invalid != nil {
		nativeMAXUnprovedProcess(t, binary, invalid, invalidPort, peer, tlsPeer, outerPackets, fault)
	}
	nativeMultihopTrafficProcess(t, binary, graph, clientPort)
	if fault == "wrong-lease-password" {
		for _, network := range []string{"tcp", "udp"} {
			if nativeMultihopTrafficExchangeTo(clientPort, 9999, network, [4]byte{10, 78, 0, 1}, 400*time.Millisecond) == nil {
				t.Fatal("wrong independently owned lease credential carried MAX traffic", network)
			}
		}
		return
	}
	// A listening SOCKS port and negotiated PQ key do not prove that the
	// nested packet handshake has completed. Exercise the complete captured
	// encrypted path first, as the application does with its node proof.
	// Keep every following payload exchange's four-second deadline intact.
	nativeMultihopAwaitEncryptedPath(t, clientPort, 9999, [4]byte{10, 78, 0, 1})
	if handshakeGate != nil {
		handshakeGate.requireObservedRetry(t)
	}
	var previous nativePQReferenceRecord
	for epoch := 0; epoch < 2; epoch++ {
		if epoch != 0 {
			peer.command(t, "rekey")
		}
		for _, network := range []string{"tcp", "udp"} {
			if err := nativeMultihopTrafficExchangeMarked(clientPort, 9999, network, [4]byte{10, 78, 0, 1}, 4*time.Second, []byte("routervpn-complete-max-authenticated-data-")); err != nil {
				t.Fatal("complete MAX did not carry encrypted traffic", epoch, network, err)
			}
		}
		current := peer.command(t, "snapshot")
		if current.Updates < int64(epoch+1) || current.Handshake <= previous.Handshake || current.Packets == 0 || current.Plaintext || outerPackets() == 0 {
			t.Fatal("MAX bypassed its mandatory KEM/packet/middle/outer chain or failed authenticated rekey", current.Updates, current.Handshake, current.Packets, outerPackets())
		}
		previous = current
	}
}

func nativeMAXUnprovedProcess(t *testing.T, binary string, graph map[string]any, port int, peer *nativePQReference, outer *nativeMAXTLSReference, packets func() int64, fault string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "native.json")
	raw, _ := json.Marshal(graph)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-D", directory, "-c", path)
	command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("failed MAX owner did not join")
			}
		}
	})
	witness := false
	for until := time.Now().Add(4 * time.Second); time.Now().Before(until); {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 20*time.Millisecond); err == nil {
			c.Close()
			t.Fatal("unproved MAX exposed its application listener")
		}
		switch fault {
		case "wrong-outer":
			witness = outer != nil && outer.RejectedUUID("22222222-2222-4222-8222-222222222222")
		case "wrong-private-ss":
			witness = outer != nil && outer.BlockedUDP("10.88.0.1:8387")
		case "wrong-middle":
			witness = packets() != 0
		case "wrong-pq-peer":
			witness = peer.command(t, "snapshot").Received != 0
		default:
			t.Fatal("unowned MAX negative case")
		}
		select {
		case err := <-done:
			joined = true
			if err == nil {
				t.Fatal("invalid MAX owner exited successfully")
			}
			until = time.Now()
		default:
			time.Sleep(10 * time.Millisecond)
		}
		if witness {
			break
		}
	}
	if !witness {
		t.Fatal("negative MAX trial did not reach its exact owned authentication or route rejection", fault)
	}
	status := peer.command(t, "snapshot")
	if status.Updates != 0 || status.Handshake != 0 || status.Packets != 0 {
		t.Fatal("unproved MAX advanced its mandatory PQ/packet owner", fault)
	}
	if !joined {
		if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			joined = true
			if err == nil {
				t.Fatal("invalid MAX owner exited successfully")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("failed MAX trial did not join before exact captured restoration")
		}
	}
}
