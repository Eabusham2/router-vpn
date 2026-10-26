package main

import (
	"bufio"
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

// A separate mandatory native-bundle group. Actual generated packet and KEM
// assets enter the desktop capture and Local/Server compilers. Only loopback
// physical sockets, the system TUN input and the private relay bind are adapted;
// mandatory PQ negotiation, peer keys, encryption and lease authentication stay
// in the production engine. Each trial owns fresh native reference peers.
func TestNativePQDesktopEncryptedLoopback(t *testing.T) {
	binary, reference, awg := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"), os.Getenv("ROUTERVPN_PQ_REFERENCE_CLI"), os.Getenv("ROUTERVPN_AWG_REFERENCE_CLI")
	if binary == "" {
		t.Skip("complete native runtime supplied by the package gate")
	}
	if reference == "" || awg == "" || os.Getenv("ROUTERVPN_PQ_TEST_KEYS") == "" {
		t.Fatal("native package gate must supply the genuine isolated PQ peers and disposable keys")
	}
	for index, pair := range [][2]string{{"wg", "wg-pq"}, {"awg2-strong", "awg2-pq"}, {"awg2-fast", "wg-pq"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			for _, execution := range []string{"local", "server"} {
				t.Run(execution, func(t *testing.T) {
					faults := []string{"none", "wrong-pq-peer"}
					if execution == "server" {
						faults = append(faults, "wrong-lease-password")
					}
					if index == 2 {
						// Both packet families already exercise their independent
						// keys and negative/restore cases. Keep real positive traffic
						// through the remaining entry variant without multiplying
						// the same expensive KEM rejection matrix a third time.
						faults = []string{"none"}
					}
					for _, fault := range faults {
						t.Run(fault, func(t *testing.T) {
							nativePQDesktopTraffic(t, binary, reference, awg, pair[0], pair[1], execution, fault)
						})
					}
				})
			}
		})
	}
}

func nativePQDesktopKey(t *testing.T, name, kind string) []byte {
	t.Helper()
	path := filepath.Join(os.Getenv("ROUTERVPN_PQ_TEST_KEYS"), name+"."+kind)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 2<<20 {
		t.Fatal("real disposable PQ fixture key missing or invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("real disposable PQ fixture key unavailable")
	}
	defer f.Close()
	opened, statErr := f.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if statErr != nil || readErr != nil || !os.SameFile(info, opened) || int64(len(raw)) != info.Size() {
		t.Fatal("real PQ fixture key changed during capture")
	}
	t.Cleanup(func() { clear(raw) })
	return raw
}

func nativePQDesktopTraffic(t *testing.T, binary, reference, awg, entryMode, exitMode, execution, fault string) {
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
		t.Fatal("loopback adapter unavailable")
	}
	root, selection := nativeMultihopCapturedFixture(t, entryMode, "off")
	selection.Entry.DAITAEnabled, selection.Exit.DAITAEnabled = false, false
	selection.Entry.DNSMode, selection.Entry.DNSProtocol, selection.Entry.DNSHost, selection.Entry.DNSPort, selection.Entry.DNSServerName, selection.Entry.DNSPath = "home", "", "", 0, "", ""
	selection.Exit.AdGuardIPv4 = "10.78.0.53"
	key := func() *ecdh.PrivateKey {
		value, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	entryServer, localExit, serverExit := key(), key(), key()
	encoded := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	entryPrivate, _ := base64.StdEncoding.DecodeString(testWGKey('p'))
	entryClient, _ := ecdh.X25519().NewPrivateKey(entryPrivate)
	clear(entryPrivate)
	clientPublic, pqClient := localExit.PublicKey(), "client"
	if execution == "server" {
		clientPublic, pqClient = serverExit.PublicKey(), "other"
	}
	peer := nativePQReferenceProcess(t, reference, exitMode, encoded(clientPublic.Bytes()), pqClient)
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
	packet := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.78.0.2/24\nDNS = %s\nMTU = 1420\n", encoded(localExit.Bytes()), selection.Exit.AdGuardIPv4)
	keys := make([]string, 0, len(peer.ready.Parameters))
	for name := range peer.ready.Parameters {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		packet += strings.ToUpper(name[:1]) + name[1:] + " = " + peer.ready.Parameters[name] + "\n"
	}
	packet += fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", peer.ready.PacketPublic, selection.Exit.Endpoint)
	full, split = "wg.conf", "wg-socks.conf"
	if exitMode == "awg2-pq" {
		full, split = "awg.conf", "awg-socks.conf"
	}
	assets := nativeMultihopPQAssets(t, exitMode, map[string][]byte{full: []byte(packet), split: []byte(packet)}, peer.ready.PacketPublic)
	assets["rosenpass-client-secret"], assets["rosenpass-client-public"], assets["rosenpass-server-public"] = nativePQDesktopKey(t, "client", "secret"), nativePQDesktopKey(t, "client", "public"), nativePQDesktopKey(t, "server", "public")
	for name, raw := range assets {
		if err := os.WriteFile(filepath.Join(root, "generated", "exit", exitMode, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if exitMode == "wg-pq" {
		for _, name := range []string{"wg.conf", "wg-socks.conf"} {
			if err := os.WriteFile(filepath.Join(root, "generated", "exit", "wg", name), []byte(packet), 0600); err != nil {
				t.Fatal(err)
			}
		}
		selection.Exit.NodeProofID, err = nodeProofIDFromWGConfig([]byte(packet))
		if err != nil {
			t.Fatal(err)
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
		value := raw.(map[string]any)
		if value["tag"] == "entry-wg" {
			entryEndpoint = value
		}
		if value["tag"] == "proxy" {
			exitEndpoint = value
		}
	}
	if exitEndpoint["type"] != mobilemultihop.PQType || exitEndpoint["mode"] != exitMode || selection.Native.localPacketPublic[exitMode] != encoded(localExit.PublicKey().Bytes()) {
		t.Fatal("captured desktop PQ endpoint or packet identity changed")
	}
	localPQ := sha256.Sum256(assets["rosenpass-client-public"])
	if selection.Native.localPQIdentity[exitMode] != hex.EncodeToString(localPQ[:]) {
		t.Fatal("captured desktop PQ identity changed")
	}
	leasePort := 26241
	physical := func(address string, ports map[int]int) int {
		listener := nativeMultihopTrafficPort(t, "tcp")
		rules := []any{}
		for from, to := range ports {
			rules = append(rules, map[string]any{"ip_cidr": []string{address + "/32"}, "network": "udp", "port": from, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": to})
		}
		rules = append(rules, map[string]any{"action": "reject"})
		nativeMultihopTrafficProcess(t, binary, map[string]any{"inbounds": []any{map[string]any{"type": "socks", "tag": "physical", "listen": "127.0.0.1", "listen_port": listener}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}}, "route": map[string]any{"rules": rules}}, listener)
		return listener
	}
	ports := map[int]int{51820: peer.ready.PacketPort, 51822: peer.ready.PQPort}
	entryPort, entryPhysical := 0, 0
	if entryMode == "wg" {
		entryPort = nativeMultihopTrafficPort(t, "udp")
		rules := []any{}
		for from, to := range ports {
			rules = append(rules, map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "network": "udp", "port": from, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1", "override_port": to})
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "port": []int{leasePort, leasePort + 1}, "action": "route", "outbound": "captured-only", "override_address": "127.0.0.1"}, map[string]any{"action": "reject"})
		nativeMultihopTrafficProcess(t, binary, map[string]any{"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": encoded(entryServer.Bytes()), "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "captured-only"}}, "route": map[string]any{"rules": rules}}, 0)
	} else {
		forwards := []any{}
		for from, to := range ports {
			forwards = append(forwards, map[string]any{"network": "udp", "address": selection.Exit.Endpoint, "port": from, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(to))})
		}
		for _, host := range []string{"10.77.0.1", "127.0.0.1"} {
			for _, lane := range []struct {
				network string
				port    int
			}{{"tcp", leasePort}, {"udp", leasePort + 1}} {
				forwards = append(forwards, map[string]any{"network": lane.network, "address": host, "port": lane.port, "target": net.JoinHostPort("127.0.0.1", strconv.Itoa(lane.port))})
			}
		}
		entryPort = nativeAmneziaReferenceProcess(t, awg, map[string]any{"private_key": encoded(entryServer.Bytes()), "addresses": []string{"10.77.0.1/24"}, "parameters": entryEndpoint["amnezia"], "peers": []any{map[string]any{"public_key": encoded(entryClient.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}, "forward": forwards})
		entryPhysical = physical(selection.Entry.Endpoint, map[int]int{51820: entryPort})
	}
	var descriptor *desktopExecutionDescriptor
	var serverConfig map[string]any
	if execution == "server" {
		serverPublic := nativePQDesktopKey(t, "other", "public")
		identity := sha256.Sum256(serverPublic)
		if identity == localPQ || serverExit.PublicKey().Equal(localExit.PublicKey()) {
			t.Fatal("Server reused Local packet or PQ identity")
		}
		request := multihoprelay.Request{SessionID: strings.Repeat("c", 32), EntryNodeID: selection.Entry.NodeProofID, ExitID: selection.Exit.ID, ExitMode: exitMode, ExpectedPacketPublicKey: encoded(serverExit.PublicKey().Bytes()), ExpectedPQClientIdentity: hex.EncodeToString(identity[:])}
		lease := multihoprelay.Lease{Request: request, NodeID: selection.Entry.NodeProofID, ExitNodeID: selection.Exit.NodeProofID, Host: "10.77.0.1", Port: leasePort, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48)}
		descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
		transport := cloneNativePacketTrafficGraph(t, exitEndpoint)
		delete(transport, "detour")
		// A separately provisioned Server transport has no client-interface
		// ownership field. Omit only the compiler's explicitly false value;
		// never allow a system endpoint or weaken the relay's strict schema.
		if system, present := transport["system"]; present {
			if system != false {
				t.Fatal("captured PQ fixture unexpectedly owns a system interface")
			}
			delete(transport, "system")
		}
		transport["private_key"] = encoded(serverExit.Bytes())
		pq := transport["pq"].(map[string]any)
		pq["secret"], pq["public"] = encoded(nativePQDesktopKey(t, "other", "secret")), encoded(serverPublic)
		paired := multihoprelay.Exit{ID: selection.Exit.ID, Mode: exitMode, NodeID: selection.Exit.NodeProofID, DNS: selection.Exit.AdGuardIPv4, Transport: transport}
		raw, err := multihoprelay.Build(paired, netip.MustParseAddr("10.77.0.2"), lease)
		if err != nil {
			fields := make([]string, 0, len(transport))
			for name := range transport {
				fields = append(fields, name)
			}
			sort.Strings(fields)
			t.Fatal("captured private Server transport rejected", err, fields)
		}
		serverConfig = retainedGraph(t, raw)
		serverConfig["inbounds"].([]any)[0].(map[string]any)["listen"] = "127.0.0.1"
		serverConfig["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.1/32"}
		serverConfig["endpoints"].([]any)[0].(map[string]any)["detour"] = "fixture-exit-sockets"
		// The fixture's physical mapper uses the native UoT framing path. The
		// plain SOCKS UDP adapter reports the framed datagram length, which is
		// not net.Conn's payload-write contract and is correctly rejected by
		// the real PQ controller. UoT's native vectorized writer preserves that
		// contract without changing the leased SOCKS path or any PQ packets.
		serverConfig["outbounds"] = append(serverConfig["outbounds"].([]any), map[string]any{"type": "socks", "tag": "fixture-exit-sockets", "server": "127.0.0.1", "server_port": physical(selection.Exit.Endpoint, ports), "version": "5", "udp_over_tcp": map[string]any{"enabled": true, "version": 2}})
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
			if endpoint["type"] != mobilemultihop.PQType || endpoint["detour"] != "entry-wg" {
				t.Fatal("Local lost its mandatory captured PQ owner")
			}
		}
	}
	if packetExit != (execution == "local") {
		t.Fatal("Server retained a competing local PQ owner")
	}
	mutate := func(value map[string]any) {
		if fault == "wrong-pq-peer" {
			wrongPeer := "other"
			if execution == "server" {
				// Server owns the independently paired "other" client. Use a
				// different genuine remote key, so this exercises negotiation
				// rejection rather than the earlier self-peer schema guard.
				wrongPeer = "client"
			}
			for _, raw := range value["endpoints"].([]any) {
				endpoint := raw.(map[string]any)
				if endpoint["type"] == mobilemultihop.PQType {
					endpoint["pq"].(map[string]any)["peer"] = encoded(nativePQDesktopKey(t, wrongPeer, "public"))
				}
			}
		}
	}
	if execution == "server" {
		backendPort := nativeMultihopTrafficPort(t, "tcp")
		serverConfig["inbounds"].([]any)[0].(map[string]any)["listen_port"] = backendPort
		if fault == "wrong-pq-peer" {
			invalid := cloneNativePacketTrafficGraph(t, serverConfig)
			mutate(invalid)
			nativePQUnprovedProcess(t, binary, invalid, backendPort, peer)
		}
		// The failed owner is fully joined above. Reuse the original captured
		// Server graph and reference identity; no new keys or selection occur.
		nativeMultihopTrafficProcess(t, binary, serverConfig, backendPort)
		nativeMultihopPrivateSOCKSAdapter(t, leasePort, leasePort+1, backendPort)
		if fault == "wrong-lease-password" {
			for _, raw := range graph["outbounds"].([]any) {
				out := raw.(map[string]any)
				if out["tag"] == "proxy" {
					out["password"] = "not-the-owned-pq-lease"
				}
			}
		}
	} else {
		if fault == "wrong-pq-peer" {
			invalid := cloneNativePacketTrafficGraph(t, graph)
			mutate(invalid)
			nativePQUnprovedProcess(t, binary, invalid, clientPort, peer)
		}
	}
	nativeMultihopTrafficProcess(t, binary, graph, clientPort)
	if fault == "wrong-lease-password" {
		for _, network := range []string{"tcp", "udp"} {
			if nativeMultihopTrafficExchangeTo(clientPort, 9999, network, [4]byte{10, 78, 0, 1}, 400*time.Millisecond) == nil {
				t.Fatal("wrong private Server credential carried PQ traffic", network)
			}
		}
		return
	}
	var previous nativePQReferenceRecord
	for epoch := 0; epoch < 2; epoch++ {
		if epoch != 0 {
			peer.command(t, "rekey")
		}
		for _, network := range []string{"tcp", "udp"} {
			if err := nativeMultihopTrafficExchangeMarked(clientPort, 9999, network, [4]byte{10, 78, 0, 1}, 4*time.Second, []byte("routervpn-authenticated-pq-data-")); err != nil {
				t.Fatal("actual captured PQ traffic failed", epoch, network, err)
			}
		}
		current := peer.command(t, "snapshot")
		if current.Updates < int64(epoch+1) || current.Packets == 0 || current.Plaintext || current.Handshake <= previous.Handshake {
			t.Fatal("desktop traffic did not use a fresh negotiated native handshake", epoch, current.Updates, current.Handshake)
		}
		previous = current
	}
}

type nativePQReferenceRecord struct {
	Ready        bool              `json:"ready"`
	Mode         string            `json:"mode"`
	PacketPublic string            `json:"packet_public"`
	PacketPort   int               `json:"packet_port"`
	PQPort       int               `json:"pq_port"`
	Parameters   map[string]string `json:"parameters"`
	Command      string            `json:"command"`
	Updates      int64             `json:"updates"`
	Packets      int64             `json:"packets"`
	Received     int64             `json:"received"`
	Handshake    int64             `json:"handshake"`
	Plaintext    bool              `json:"plaintext"`
}
type nativePQReference struct {
	ready   nativePQReferenceRecord
	input   io.WriteCloser
	replies <-chan nativePQReferenceRecord
	failure <-chan error
}

func (p *nativePQReference) command(t *testing.T, command string) nativePQReferenceRecord {
	t.Helper()
	if _, err := fmt.Fprintln(p.input, command); err != nil {
		t.Fatal("PQ reference owner pipe closed")
	}
	select {
	case reply := <-p.replies:
		if reply.Command != command {
			t.Fatal("PQ reference response lost operation identity")
		}
		return reply
	case err := <-p.failure:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("PQ reference command timed out")
	}
	return nativePQReferenceRecord{}
}
func nativePQReferenceProcess(t *testing.T, binary, mode, public, client string) *nativePQReference {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "peer.json")
	raw, _ := json.Marshal(map[string]any{"mode": mode, "packet_public": public, "pq_client": client})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestDesktopPQReferencePeer$", "-test.timeout=90s")
	command.Env = append(os.Environ(), "ROUTERVPN_PQ_REFERENCE_CONFIG="+path)
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
	replies := make(chan nativePQReferenceRecord, 4)
	failure := make(chan error, 1)
	readDone := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 16<<10)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "ROUTERVPN_PQ_REFERENCE ") {
				continue
			}
			var value nativePQReferenceRecord
			decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "ROUTERVPN_PQ_REFERENCE ")))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&value) != nil {
				failure <- errors.New("invalid PQ reference record")
				return
			}
			replies <- value
		}
		if scanner.Err() != nil {
			failure <- errors.New("PQ reference pipe failed")
		}
	}()
	go func() { <-readDone; done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("PQ reference failed joined shutdown", err)
			}
		case <-time.After(8 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("PQ reference did not join its owned peers")
		}
		<-readDone
	})
	result := &nativePQReference{input: input, replies: replies, failure: failure}
	select {
	case ready := <-replies:
		decoded, err := base64.StdEncoding.Strict().DecodeString(ready.PacketPublic)
		if !ready.Ready || ready.Mode != mode || err != nil || len(decoded) != 32 || ready.PacketPort < 1 || ready.PacketPort > 65535 || ready.PQPort < 1 || ready.PQPort > 65535 {
			t.Fatal("PQ reference readiness did not match captured owner")
		}
		result.ready = ready
	case <-readDone:
		t.Fatal("PQ reference exited before readiness")
	case <-time.After(10 * time.Second):
		t.Fatal("PQ reference readiness timed out")
	}
	return result
}

func nativePQUnprovedProcess(t *testing.T, binary string, graph map[string]any, port int, peer *nativePQReference) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "native.json")
	raw, _ := json.Marshal(graph)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-D", directory, "-c", path)
	command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			command.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("unproved PQ owner failed to drain")
			}
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 20*time.Millisecond); err == nil {
			c.Close()
			t.Fatal("unauthenticated PQ graph exposed its data listener")
		}
		select {
		case err := <-done:
			stopped = true
			if err == nil {
				t.Fatal("wrong PQ peer exited successfully")
			}
			deadline = time.Now()
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	status := peer.command(t, "snapshot")
	if status.Received == 0 || status.Updates != 0 || status.Handshake != 0 || status.Packets != 0 {
		t.Fatal("wrong PQ peer was not rejected by actual protocol negotiation", status.Received, status.Updates, status.Handshake, status.Packets)
	}
	if !stopped {
		if err := command.Process.Kill(); err != nil {
			t.Fatal("failed PQ trial could not be retired", err)
		}
		select {
		case <-done:
			stopped = true
		case <-time.After(5 * time.Second):
			t.Fatal("failed PQ trial did not join before captured restoration")
		}
	}
}
