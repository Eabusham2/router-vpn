//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// These are the same independent WG/AWG prefix and paired SS source inputs as
// the installed Linux host fixture. Darwin changes only the captured physical
// bind address and retained native controller; no proof/counter is simulated.
type macOSNodeChainFinalReply struct {
	Schema             int    `json:"schema"`
	Address            string `json:"address"`
	PublicCA           string `json:"public_ca"`
	EntryPublicIP      string `json:"entry_public_ip"`
	FinalPublicIP      string `json:"final_public_ip"`
	EntryRawUDP        int64  `json:"entry_raw_udp"`
	EntryTCP           int64  `json:"entry_tcp"`
	EntryUDP           int64  `json:"entry_udp"`
	FinalRawTCP        int64  `json:"final_raw_tcp"`
	FinalRawUDP        int64  `json:"final_raw_udp"`
	FinalTCP           int64  `json:"final_tcp"`
	FinalUDP           int64  `json:"final_udp"`
	EntryPublicQueries uint64 `json:"entry_public_queries"`
	FinalPublicQueries uint64 `json:"final_public_queries"`
	RouterQueries      uint64 `json:"router_queries"`
	DirectQueries      uint32 `json:"direct_router_queries"`
	DNSQueries         uint64 `json:"dns_queries"`
	MTUQueries         uint64 `json:"mtu_queries"`
	MTUReplies         uint64 `json:"mtu_replies"`
	CoverPackets       uint64 `json:"cover_packets"`
	CoverReplies       uint64 `json:"cover_replies"`
	CoverMaximum       uint32 `json:"cover_maximum"`
	DownloadBytes      uint64 `json:"download_bytes"`
	UploadBytes        uint64 `json:"upload_bytes"`
}

type macOSNodeChainBenchmarkReply struct {
	Port           int    `json:"port"`
	Packets        uint64 `json:"packets"`
	Replies        uint64 `json:"replies"`
	ReceivedBytes  uint64 `json:"received_bytes"`
	SentBytes      uint64 `json:"sent_bytes"`
	Held           bool   `json:"held"`
	HeldPackets    uint64 `json:"held_packets"`
	MaximumPayload uint32 `json:"maximum_payload"`
}

var macOSNodeChainHostCases = []string{
	"node-chain-3-connect", "node-chain-4-connect", "node-chain-3-wrong-middle-key", "node-chain-4-wrong-middle-proof",
	"node-chain-3-final-dns-failure", "node-chain-4-final-node-failure", "node-chain-4-middle-source", "node-chain-3-prefix-lost",
	"node-chain-3-awg-fast-wg-connect", "node-chain-3-wg-awg-strong-connect", "node-chain-3-awg-strong-awg-fast-connect",
	"node-chain-4-wg-awg-fast-awg-strong-connect", "node-chain-4-awg-fast-awg-strong-wg-connect", "node-chain-4-awg-strong-wg-awg-fast-connect",
	"node-chain-4-wg-awg-fast-awg-strong-wrong-middle-key", "node-chain-4-wg-awg-fast-awg-strong-wrong-awg-parameters",
	"node-chain-4-wg-awg-fast-awg-strong-middle-source", "node-chain-4-wg-awg-fast-awg-strong-prefix-lost",
	"node-chain-custom-wg-connect", "node-chain-custom-awg-fast-connect", "node-chain-custom-awg-strong-connect",
	"node-chain-custom-wg-wrong-middle-key", "node-chain-custom-wg-wrong-middle-public", "node-chain-custom-wg-final-dns-failure",
	"node-chain-custom-wg-middle-source", "node-chain-custom-wg-prefix-lost",
	"node-chain-3-mtu", "node-chain-4-wg-awg-fast-awg-strong-mtu",
}

type macOSNodeChainPrefixRequest struct {
	Mode            string            `json:"mode"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	PrivateKey      string            `json:"private_key"`
	ClientPublicKey string            `json:"client_public_key"`
	PreSharedKey    string            `json:"pre_shared_key"`
	NodeProofID     string            `json:"node_proof_id"`
	APIToken        string            `json:"api_token"`
}

type macOSNodeChainPeerReply struct {
	Schema   int    `json:"schema"`
	Address  string `json:"address"`
	PublicCA string `json:"public_ca"`
	Prefixes []struct {
		Mode             string `json:"mode"`
		ParametersSHA256 string `json:"parameters_sha256,omitempty"`
		RawUDP           int64  `json:"raw_udp"`
		TCP              int64  `json:"tcp"`
		UDP              int64  `json:"udp"`
		ProofQueries     uint64 `json:"proof_queries"`
		AuthRefusals     uint64 `json:"auth_refusals"`
	} `json:"prefixes"`
	Middle    *macOSNodeChainImportedCounters `json:"middle,omitempty"`
	Final     macOSNodeChainFinalReply        `json:"final"`
	Benchmark *macOSNodeChainBenchmarkReply   `json:"benchmark,omitempty"`
}

type macOSNodeChainPeer struct {
	input, output  *os.File
	reader         *bufio.Reader
	command        *exec.Cmd
	done           chan struct{}
	physical       netip.Addr
	failure        error
	clients        []*ecdh.PrivateKey
	requests       []macOSNodeChainPrefixRequest
	finalClient    *ecdh.PrivateKey
	finalServer    *ecdh.PrivateKey
	password       string
	middlePassword string
	middleMethod   string
	reply          macOSNodeChainPeerReply
}

func macOSNodeChainProofID(key *ecdh.PrivateKey) string {
	digest := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())))
	return hex.EncodeToString(digest[:])
}

type macOSNodeChainCipherCase struct {
	name, prefix string
	modes        []string
}

func macOSNodeChainCipherCases() []macOSNodeChainCipherCase {
	return []macOSNodeChainCipherCase{
		{"3-nodes", "node-chain-3-", []string{"wg", "wg"}}, {"4-nodes", "node-chain-4-", []string{"wg", "wg", "wg"}},
		{"awg-fast-wg-3-nodes", "node-chain-3-awg-fast-wg-", []string{"awg2-fast", "wg"}},
		{"wg-awg-strong-3-nodes", "node-chain-3-wg-awg-strong-", []string{"wg", "awg2-strong"}},
		{"awg-strong-awg-fast-3-nodes", "node-chain-3-awg-strong-awg-fast-", []string{"awg2-strong", "awg2-fast"}},
		{"wg-awg-fast-awg-strong-4-nodes", "node-chain-4-wg-awg-fast-awg-strong-", []string{"wg", "awg2-fast", "awg2-strong"}},
		{"awg-fast-awg-strong-wg-4-nodes", "node-chain-4-awg-fast-awg-strong-wg-", []string{"awg2-fast", "awg2-strong", "wg"}},
		{"awg-strong-wg-awg-fast-4-nodes", "node-chain-4-awg-strong-wg-awg-fast-", []string{"awg2-strong", "wg", "awg2-fast"}},
	}
}
func macOSNodeChainScenario(scenario string) ([]string, string, error) {
	found := false
	for _, name := range macOSNodeChainHostCases {
		if scenario == name {
			found = true
			break
		}
	}
	if !found {
		return nil, "", errors.New("uncaptured ordered installed scenario")
	}
	cases := append(macOSNodeChainCipherCases(), macOSNodeChainImportedCipherCases()...)
	// Longest captured prefixes must win over the original WG-only names.
	for i := len(cases) - 1; i >= 0; i-- {
		if action, ok := strings.CutPrefix(scenario, cases[i].prefix); ok {
			return append([]string(nil), cases[i].modes...), action, nil
		}
	}
	return nil, "", errors.New("ordered installed cipher inventory unavailable")
}
func macOSNodeChainSetModes(t *testing.T, peer *macOSNodeChainPeer, modes []string) {
	t.Helper()
	if len(modes) != len(peer.requests) {
		t.Fatal("installed ordered cipher count changed")
	}
	for i, mode := range modes {
		peer.requests[i].Mode = mode
		if mode == "wg" {
			peer.requests[i].Parameters = nil
			continue
		}
		if !awgpolicy.IsMode(mode) {
			t.Fatal("unknown installed ordered cipher")
		}
		values := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": strconv.Itoa(56 + i), "s2": "48", "s3": "24", "s4": strconv.Itoa(32 + i),
			"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
		if mode == "awg2-strong" {
			values["jc"], values["jmax"] = "8", "1200"
		}
		peer.requests[i].Parameters = values
	}
}

func macOSNodeChainPeerKeys(t *testing.T, count int) *macOSNodeChainPeer {
	t.Helper()
	if count != 3 && count != 4 {
		t.Fatal("installed ordered fixture requires its complete three/four-node inventory")
	}
	key := func() *ecdh.PrivateKey {
		value, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	random := func() string {
		var value [32]byte
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(value[:])
	}
	peer := &macOSNodeChainPeer{done: make(chan struct{}), finalClient: key(), finalServer: key(), password: random()}
	for i := 0; i < count-1; i++ {
		client, server := key(), key()
		peer.clients = append(peer.clients, client)
		peer.requests = append(peer.requests, macOSNodeChainPrefixRequest{Mode: "wg", PrivateKey: base64.StdEncoding.EncodeToString(server.Bytes()),
			ClientPublicKey: base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()), PreSharedKey: random(),
			NodeProofID: macOSNodeChainProofID(server), APIToken: fmt.Sprintf("installed-ordered-prefix-%d-token", i)})
	}
	return peer
}

func (peer *macOSNodeChainPeer) read(t *testing.T) macOSNodeChainPeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := peer.reader.ReadSlice('\n')
	var reply macOSNodeChainPeerReply
	if err != nil || len(raw) > 32768 || decodeRelayControlJSON(raw, &reply) != nil || reply.Schema != 1 || len(reply.Prefixes) != len(peer.requests) {
		t.Fatal("ordered peer lost its complete bounded independent reply", err)
	}
	address, err := netip.ParseAddrPort(reply.Address)
	if err != nil || address.Addr() != peer.physical || address.Port() == 0 || reply.PublicCA == "" || reply.Final.FinalPublicIP != "203.0.113.89" {
		t.Fatal("ordered peer substituted its physical endpoint or final TLS identity")
	}
	if peer.reply.Address != "" && (peer.reply.Address != reply.Address || peer.reply.PublicCA != reply.PublicCA) {
		t.Fatal("ordered peer replaced its original captured identity")
	}
	// Every command response, including held/retired observations, must retain
	// the separate originally requested sink. A missing receipt is not zero
	// traffic and cannot be borrowed from the previous response.
	if reply.Benchmark == nil || reply.Benchmark.Port != 45998 || reply.Benchmark.MaximumPayload > 8972 {
		t.Fatal("ordered peer lost its exact separate bounded benchmark receipt")
	}
	if peer.middlePassword != "" && (reply.Middle == nil || reply.Middle.Method != peer.middleMethod) || peer.middlePassword == "" && reply.Middle != nil {
		t.Fatal("ordered peer replaced its independently captured imported cipher")
	}
	for i, prefix := range peer.requests {
		expected := ""
		if awgpolicy.IsMode(prefix.Mode) {
			parameters, err := awgpolicy.ParametersUAPI(prefix.Parameters)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(parameters))
			expected = hex.EncodeToString(digest[:])
		} else if prefix.Mode != "wg" || len(prefix.Parameters) != 0 {
			t.Fatal("unowned ordered peer cipher")
		}
		if reply.Prefixes[i].Mode != prefix.Mode || reply.Prefixes[i].ParametersSHA256 != expected {
			t.Fatal("ordered peer native parameter readback changed", i)
		}
	}
	peer.reply = reply
	return reply
}

func (peer *macOSNodeChainPeer) observe(t *testing.T, action string) macOSNodeChainPeerReply {
	t.Helper()
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

func macOSNodeChainInstalledSources(t *testing.T, peer *macOSNodeChainPeer, fault string) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	assets := map[string]map[string]map[string][]byte{}
	var profiles []common.RouterProfile
	var nodes []common.MultihopNodeSelection
	for i, prefix := range peer.requests {
		inner := fmt.Sprintf("10.%d.0", 80+i)
		if i == len(peer.requests)-1 {
			inner = "10.78.0"
		}
		endpoint := fmt.Sprintf("198.51.100.%d:51820", 101+i)
		if i == 0 {
			endpoint = peer.reply.Address
		}
		address, err := netip.ParseAddrPort(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		private, err := base64.StdEncoding.DecodeString(prefix.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		server, err := ecdh.X25519().NewPrivateKey(private)
		clear(private)
		if err != nil {
			t.Fatal(err)
		}
		if fault == "wrong-middle-key" && i == 1 {
			server, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
		}
		profile := common.RouterProfile{ID: fmt.Sprintf("installed-ordered-prefix-%d", i), Name: fmt.Sprintf("Original prefix %d", i),
			NodeProofID: macOSNodeChainProofID(server), Endpoint: address.Addr().String(), RouterAPI: "http://" + inner + ".1:8787", APIToken: prefix.APIToken,
			AdGuardIPv4: "192.168.50.133", DNSMode: "home", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", BaseTunnel: "wg",
			KillSwitch: true, KillSwitchPolicy: "on-connect"}
		config := fmt.Sprintf("[Interface]\nAddress=%s.2/32,fd78:78::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=2000\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n",
			inner, base64.StdEncoding.EncodeToString(peer.clients[i].Bytes()), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), prefix.PreSharedKey, endpoint)
		standardConfig := config
		mode, file := prefix.Mode, "wg.conf"
		if mode != "wg" {
			values := make(map[string]string, len(prefix.Parameters))
			for key, value := range prefix.Parameters {
				values[key] = value
			}
			if fault == "wrong-awg-parameters" && i == 1 {
				values["h1"] = "51000000-51999999"
			}
			parameters, err := awgpolicy.ParametersUAPI(values)
			if err != nil {
				t.Fatal(err)
			}
			config = strings.Replace(config, "[Peer]", parameters+"[Peer]", 1)
			file = "awg.conf"
		}
		assets[profile.ID] = map[string]map[string][]byte{mode: {file: []byte(config)}}
		if mode != "wg" {
			assets[profile.ID]["wg"] = map[string][]byte{"wg.conf": []byte(standardConfig)}
		}
		profiles = append(profiles, profile)
		nodes = append(nodes, common.MultihopNodeSelection{ID: profile.ID, Mode: mode})
	}
	if peer.middlePassword != "" {
		middle := macOSNodeChainImportedProfile(t, peer, fault)
		profiles = append(profiles, middle)
		nodes = append(nodes, common.MultihopNodeSelection{ID: middle.ID, Mode: "shadowsocks"})
	}
	final := common.RouterProfile{ID: "installed-ordered-final", Name: "Original ordered paired final", NodeProofID: macOSNodeChainProofID(peer.finalServer),
		Endpoint: "10.77.0.1", RouterAPI: "http://10.77.0.1:8787", APIToken: "installed-ordered-final-token", AdGuardIPv4: "192.168.50.133", DNSMode: "home",
		IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", BaseTunnel: "wg", KillSwitch: true, KillSwitchPolicy: "on-connect",
		DAITAHost: "10.77.0.1", DAITAPort: 45998, MultihopEnabled: true, MultihopExecution: "local"}
	nodes = append(nodes, common.MultihopNodeSelection{ID: final.ID, Mode: "shadowsocks"})
	final.MultihopNodes = nodes
	profiles = append(profiles, final)
	for i := range profiles {
		if err := common.NormalizeRouterProfile(&profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "10.77.0.1", "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": peer.password}}, "route": map[string]any{"final": "proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	assets[final.ID] = map[string]map[string][]byte{
		"wg":          {"wg.conf": []byte(fmt.Sprintf("[Interface]\nAddress=10.79.0.2/32,fd79:79::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=2000\n[Peer]\nPublicKey=%s\nEndpoint=10.77.0.1:51820\nAllowedIPs=0.0.0.0/0,::/0\n", base64.StdEncoding.EncodeToString(peer.finalClient.Bytes()), base64.StdEncoding.EncodeToString(peer.finalServer.PublicKey().Bytes())))},
		"shadowsocks": {"sing-box.json": graph},
	}
	return common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: final.ID, Profiles: profiles}, assets
}

func startMacOSNodeChainPeer(t *testing.T, modes []string) *macOSNodeChainPeer {
	t.Helper()
	image := os.Getenv("ROUTERVPN_MACOS_NODE_CHAIN_PEER")
	raw, err := os.ReadFile(image)
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(image) || hex.EncodeToString(sum[:]) != os.Getenv("ROUTERVPN_MACOS_NODE_CHAIN_PEER_SHA256") {
		t.Fatal("ordered native fixture lost its captured independent peer image", err)
	}
	peer := macOSNodeChainPeerForModes(t, modes)
	peer.physical = macOSExternalNativeAddress(t)
	root, child := "TestRouterVPNDesktopNodeChainReferenceProcess", "ROUTERVPN_NODE_CHAIN_REFERENCE_CHILD=1"
	if peer.middlePassword != "" {
		root, child = "TestRouterVPNDesktopNodeChainImportedMiddleReferenceProcess", "ROUTERVPN_NODE_CHAIN_IMPORTED_REFERENCE_CHILD=1"
	}
	peer.command = exec.Command(image, "-test.run=^"+root+"$", "-test.count=1", "-test.timeout=240s")
	peer.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0",
		child, "ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1",
		"ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=" + peer.physical.String()}
	peer.command.Stderr = os.Stderr
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		inputRead.Close()
		inputWrite.Close()
		t.Fatal(err)
	}
	peer.input, peer.output, peer.reader = inputWrite, outputRead, bufio.NewReaderSize(outputRead, 32768)
	peer.command.Stdin, peer.command.Stdout = inputRead, outputWrite
	if err := peer.command.Start(); err != nil {
		inputRead.Close()
		inputWrite.Close()
		outputRead.Close()
		outputWrite.Close()
		t.Fatal(err)
	}
	inputRead.Close()
	outputWrite.Close()
	go func() { peer.failure = peer.command.Wait(); close(peer.done) }()
	t.Cleanup(func() {
		peer.input.Close()
		select {
		case <-peer.done:
			if peer.failure != nil {
				t.Error("ordered actual peer failed joined cleanup", peer.failure)
			}
		case <-time.After(10 * time.Second):
			t.Error("ordered actual peer did not join its captured control pipe")
			_ = peer.command.Process.Kill()
			<-peer.done
		}
		peer.output.Close()
	})
	request := map[string]any{"schema": 1, "address": peer.physical.String(), "client_address": peer.physical.String(), "prefixes": peer.requests,
		"final_password": peer.password, "final_node_proof_id": macOSNodeChainProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token",
		"benchmark_port": 45998}
	var wire any = request
	if peer.middlePassword != "" {
		wire = map[string]any{"schema": 1, "paired": request, "middle_method": peer.middleMethod, "middle_password": peer.middlePassword}
	}
	if err := json.NewEncoder(peer.input).Encode(wire); err != nil {
		t.Fatal(err)
	}
	peer.read(t)
	if peer.reply.Benchmark == nil || peer.reply.Benchmark.Port != 45998 || peer.reply.Benchmark.Held {
		t.Fatal("ordered peer omitted the separate captured final benchmark sink")
	}
	return peer
}

func installMacOSNodeChainProfiles(t *testing.T, peer *macOSNodeChainPeer, action string) common.RouterProfileStore {
	t.Helper()
	store, assets := macOSNodeChainInstalledSources(t, peer, action)
	raw, err := json.Marshal(store)
	if err != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), raw, 0600) != nil {
		t.Fatal("ordered saved source unavailable", err)
	}
	for id, modes := range assets {
		for mode, files := range modes {
			directory := filepath.Join(macOSOwnedControllerRoot, "generated", id, mode)
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	source := os.Getenv("ROUTERVPN_MACOS_FIXTURE_SOURCE")
	catalog, err := os.ReadFile(filepath.Join(source, "configs/client/modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "modes.json"), catalog, 0600); err != nil {
		t.Fatal(err)
	}
	// Copy the actual optimizer and its Python dependency closure before native
	// capture. No fake benchmark or ambient interpreter is admitted by this role.
	for _, name := range []string{"mtu-throughput-tuner.py", "mtu-throughput-tuner-platform.py", "network_context.py", "private_profile_store.py", "profile_id.py"} {
		body, err := os.ReadFile(filepath.Join(source, "modes", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "modes", name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, macOSNodeChainNativeMarker), []byte("explicit disposable macOS ordered PF and TUN fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return store
}
