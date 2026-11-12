//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
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
	"net/http"
	"net/http/httptest"
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
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobilemultihop"
)

var linuxNodeChainHostCases = []string{
	"node-chain-3-connect", "node-chain-4-connect", "node-chain-3-wrong-middle-key", "node-chain-4-wrong-middle-proof",
	"node-chain-3-final-dns-failure", "node-chain-4-final-node-failure", "node-chain-4-middle-source", "node-chain-3-prefix-lost",
	"node-chain-3-awg-fast-wg-connect", "node-chain-3-wg-awg-strong-connect", "node-chain-3-awg-strong-awg-fast-connect",
	"node-chain-4-wg-awg-fast-awg-strong-connect", "node-chain-4-awg-fast-awg-strong-wg-connect", "node-chain-4-awg-strong-wg-awg-fast-connect",
	"node-chain-4-wg-awg-fast-awg-strong-wrong-middle-key", "node-chain-4-wg-awg-fast-awg-strong-wrong-awg-parameters",
	"node-chain-4-wg-awg-fast-awg-strong-middle-source", "node-chain-4-wg-awg-fast-awg-strong-prefix-lost",
}

type linuxNodeChainPrefixRequest struct {
	Mode            string            `json:"mode"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	PrivateKey      string            `json:"private_key"`
	ClientPublicKey string            `json:"client_public_key"`
	PreSharedKey    string            `json:"pre_shared_key"`
	NodeProofID     string            `json:"node_proof_id"`
	APIToken        string            `json:"api_token"`
}

type linuxNodeChainPeerReply struct {
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
	Final linuxImportedPeerReply `json:"final"`
}

type linuxNodeChainPeer struct {
	input, output *os.File
	reader        *bufio.Reader
	command       *exec.Cmd
	done          chan struct{}
	diagnostic    linuxHostTUNOutput
	clients       []*ecdh.PrivateKey
	requests      []linuxNodeChainPrefixRequest
	finalClient   *ecdh.PrivateKey
	finalServer   *ecdh.PrivateKey
	password      string
	reply         linuxNodeChainPeerReply
}

func linuxNodeChainProofID(key *ecdh.PrivateKey) string {
	digest := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())))
	return hex.EncodeToString(digest[:])
}

type linuxNodeChainCipherCase struct {
	name, prefix string
	modes        []string
}

func linuxNodeChainCipherCases() []linuxNodeChainCipherCase {
	return []linuxNodeChainCipherCase{
		{"3-nodes", "node-chain-3-", []string{"wg", "wg"}}, {"4-nodes", "node-chain-4-", []string{"wg", "wg", "wg"}},
		{"awg-fast-wg-3-nodes", "node-chain-3-awg-fast-wg-", []string{"awg2-fast", "wg"}},
		{"wg-awg-strong-3-nodes", "node-chain-3-wg-awg-strong-", []string{"wg", "awg2-strong"}},
		{"awg-strong-awg-fast-3-nodes", "node-chain-3-awg-strong-awg-fast-", []string{"awg2-strong", "awg2-fast"}},
		{"wg-awg-fast-awg-strong-4-nodes", "node-chain-4-wg-awg-fast-awg-strong-", []string{"wg", "awg2-fast", "awg2-strong"}},
		{"awg-fast-awg-strong-wg-4-nodes", "node-chain-4-awg-fast-awg-strong-wg-", []string{"awg2-fast", "awg2-strong", "wg"}},
		{"awg-strong-wg-awg-fast-4-nodes", "node-chain-4-awg-strong-wg-awg-fast-", []string{"awg2-strong", "wg", "awg2-fast"}},
	}
}
func linuxNodeChainScenario(scenario string) ([]string, string, error) {
	found := false
	for _, name := range linuxNodeChainHostCases {
		if scenario == name {
			found = true
			break
		}
	}
	if !found {
		return nil, "", errors.New("uncaptured ordered installed scenario")
	}
	cases := linuxNodeChainCipherCases()
	// Longest captured prefixes must win over the original WG-only names.
	for i := len(cases) - 1; i >= 0; i-- {
		if action, ok := strings.CutPrefix(scenario, cases[i].prefix); ok {
			return append([]string(nil), cases[i].modes...), action, nil
		}
	}
	return nil, "", errors.New("ordered installed cipher inventory unavailable")
}
func linuxNodeChainSetModes(t *testing.T, peer *linuxNodeChainPeer, modes []string) {
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

func linuxNodeChainPeerKeys(t *testing.T, count int) *linuxNodeChainPeer {
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
	peer := &linuxNodeChainPeer{done: make(chan struct{}), finalClient: key(), finalServer: key(), password: random()}
	for i := 0; i < count-1; i++ {
		client, server := key(), key()
		peer.clients = append(peer.clients, client)
		peer.requests = append(peer.requests, linuxNodeChainPrefixRequest{Mode: "wg", PrivateKey: base64.StdEncoding.EncodeToString(server.Bytes()),
			ClientPublicKey: base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()), PreSharedKey: random(),
			NodeProofID: linuxNodeChainProofID(server), APIToken: fmt.Sprintf("installed-ordered-prefix-%d-token", i)})
	}
	return peer
}

func (peer *linuxNodeChainPeer) read(t *testing.T) linuxNodeChainPeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := peer.reader.ReadSlice('\n')
	var reply linuxNodeChainPeerReply
	if err != nil || len(raw) > 32768 || decodeRelayControlJSON(raw, &reply) != nil || reply.Schema != 1 || len(reply.Prefixes) != len(peer.requests) {
		t.Fatal("ordered peer lost its complete bounded independent reply", err, peer.diagnostic.String())
	}
	address, err := netip.ParseAddrPort(reply.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("192.168.210.2") || address.Port() == 0 || reply.PublicCA == "" || reply.Final.FinalPublicIP != "203.0.113.89" {
		t.Fatal("ordered peer substituted its physical endpoint or final TLS identity")
	}
	if peer.reply.Address != "" && (peer.reply.Address != reply.Address || peer.reply.PublicCA != reply.PublicCA) {
		t.Fatal("ordered peer replaced its original captured identity")
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

func (peer *linuxNodeChainPeer) observe(t *testing.T, action string) linuxNodeChainPeerReply {
	t.Helper()
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

func startLinuxNodeChainPeer(t *testing.T, modes []string) *linuxNodeChainPeer {
	t.Helper()
	directory, err := os.MkdirTemp("/opt", "routervpn-node-chain-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	image := filepath.Join(directory, "peer.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	peer := linuxNodeChainPeerKeys(t, len(modes)+1)
	linuxNodeChainSetModes(t, peer, modes)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	peer.command = exec.CommandContext(ctx, "ip", "netns", "exec", "rvpn-peer", image, "-test.run=^TestRouterVPNDesktopNodeChainReferenceProcess$", "-test.count=1", "-test.timeout=115s")
	peer.command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_NODE_CHAIN_REFERENCE_CHILD=1"}
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.input, peer.output, peer.reader = inputWrite, outputRead, bufio.NewReaderSize(outputRead, 32768)
	peer.command.Stdin, peer.command.Stdout, peer.command.Stderr = inputRead, outputWrite, &peer.diagnostic
	if err := peer.command.Start(); err != nil {
		t.Fatal(err)
	}
	inputRead.Close()
	outputWrite.Close()
	go func() { _ = peer.command.Wait(); close(peer.done) }()
	t.Cleanup(func() { inputWrite.Close(); cancel(); <-peer.done; outputRead.Close() })
	request := map[string]any{"schema": 1, "address": "192.168.210.2", "client_address": "192.168.210.1", "prefixes": peer.requests,
		"final_password": peer.password, "final_node_proof_id": linuxNodeChainProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token"}
	if err := json.NewEncoder(peer.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	peer.read(t)
	return peer
}

func linuxNodeChainInstalledSources(t *testing.T, peer *linuxNodeChainPeer, fault string) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
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
			NodeProofID: linuxNodeChainProofID(server), Endpoint: address.Addr().String(), RouterAPI: "http://" + inner + ".1:8787", APIToken: prefix.APIToken,
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
	final := common.RouterProfile{ID: "installed-ordered-final", Name: "Original ordered paired final", NodeProofID: linuxNodeChainProofID(peer.finalServer),
		Endpoint: "10.77.0.1", RouterAPI: "http://10.77.0.1:8787", APIToken: "installed-ordered-final-token", AdGuardIPv4: "192.168.50.133", DNSMode: "home",
		IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", BaseTunnel: "wg", KillSwitch: true, KillSwitchPolicy: "on-connect",
		MultihopEnabled: true, MultihopExecution: "local"}
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

func installLinuxNodeChainProfiles(t *testing.T, peer *linuxNodeChainPeer, fault string) {
	t.Helper()
	store, assets := linuxNodeChainInstalledSources(t, peer, fault)
	raw, err := json.Marshal(store)
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), raw, 0600) != nil {
		t.Fatal("ordered saved source unavailable", err)
	}
	if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "node-chain-peer-ca.pem"), []byte(peer.reply.PublicCA), 0600); err != nil {
		t.Fatal(err)
	}
	for id, modes := range assets {
		for mode, files := range modes {
			directory := filepath.Join(linuxOwnedControllerRoot, "generated", id, mode)
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
}

type linuxNodeChainHostResult struct {
	linuxImportedHostResult
	Proof *mobilemultihop.DesktopNodeChainReadyRecord `json:"proof,omitempty"`
	Nodes []common.MultihopNodeSelection              `json:"nodes,omitempty"`
}

func (process *linuxHostTUNController) readNodeChain(t *testing.T, scenario string) linuxNodeChainHostResult {
	t.Helper()
	if err := process.output.SetReadDeadline(time.Now().Add(75 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := process.reader.ReadSlice('\n')
	var result linuxNodeChainHostResult
	if err != nil || len(raw) > 32768 || decodeRelayControlJSON(raw, &result) != nil || result.Scenario != scenario {
		t.Fatal("ordered installed host omitted its complete bounded result", err, string(raw), process.diagnostic.String())
	}
	return result
}

func linuxHostTUNNodeChainParent(t *testing.T, installed, scenario string) {
	modes, action, err := linuxNodeChainScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	count := len(modes) + 1
	peer := startLinuxNodeChainPeer(t, modes)
	installLinuxNodeChainProfiles(t, peer, action)
	negative := action == "wrong-awg-parameters" || action == "wrong-middle-key" || action == "wrong-middle-proof" || action == "final-dns-failure" || action == "final-node-failure"
	switch action {
	case "wrong-middle-proof":
		peer.observe(t, "wrong-node:1")
	case "final-dns-failure":
		peer.observe(t, "fail-dns")
	case "final-node-failure":
		peer.observe(t, "wrong-node")
	}
	process := linuxHostTUNStartController(t, installed, scenario)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	result := process.readNodeChain(t, scenario)
	before := peer.observe(t, "stats")
	if negative {
		if !result.Rejected || !result.Retired || result.Ready != nil || result.Proof != nil || result.Session == "" || before.Prefixes[0].RawUDP == 0 || before.Prefixes[0].ProofQueries == 0 {
			t.Fatal("ordered negative never reached its actual first encrypted proof and joined refusal", result, before)
		}
		if action == "wrong-middle-proof" && before.Prefixes[1].ProofQueries == 0 || action == "final-dns-failure" && before.Final.DNSQueries == 0 || action == "final-node-failure" && before.Final.RouterQueries == 0 {
			t.Fatal("ordered negative failed before the intended independent middle/final service", before)
		}
		if (action == "wrong-middle-key" || action == "wrong-awg-parameters") && (before.Prefixes[1].RawUDP == 0 || before.Prefixes[1].ProofQueries != 0 || before.Final.RouterQueries != 0) {
			t.Fatal("wrong middle key bypassed its actual encrypted boundary", before)
		}
	} else {
		if result.Stage != "ready" || result.Ready == nil || result.Proof == nil || !result.Monitor || len(result.Nodes) != count || result.Proof.Generation != 1 ||
			before.Final.RouterQueries == 0 || before.Final.DNSQueries == 0 || before.Final.FinalPublicQueries == 0 || before.Final.FinalTCP == 0 || before.Final.FinalUDP == 0 {
			t.Fatal("ordered installed host omitted actual complete proof or final selected traffic", result, before)
		}
		for i, prefix := range before.Prefixes {
			if result.Nodes[i].Mode != modes[i] || prefix.Mode != modes[i] {
				t.Fatal("installed ordered runtime substituted captured cipher", i)
			}
			if prefix.RawUDP == 0 || prefix.TCP == 0 || prefix.UDP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 {
				t.Fatal("ordered path omitted independently encrypted authenticated prefix", i, prefix)
			}
		}
		if action == "prefix-lost" {
			peer.observe(t, "wrong-node:1")
		}
		if _, err := process.gate.Write([]byte{2}); err != nil {
			t.Fatal(err)
		}
		result = process.readNodeChain(t, scenario)
		if !result.Retired || result.Stage != "retired" {
			t.Fatal("ordered host did not join original native cleanup", result)
		}
	}
	select {
	case <-process.done:
		if process.waitErr != nil {
			t.Fatal("ordered installed controller failed", process.waitErr, process.diagnostic.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ordered installed controller did not join")
	}
	t.Log("verified installed host native lifecycle:", scenario)
	t.Log("verified installed host ordered independent prefixes and final:", scenario)
}

func linuxHostTUNNodeChainFixture(controller *ownedDesktopController, scenario string) (failure error) {
	modes, action, err := linuxNodeChainScenario(scenario)
	if err != nil {
		return err
	}
	count := len(modes) + 1
	raw, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "routers.json"), 64<<10)
	var profiles common.RouterProfileStore
	if err != nil || decodeRelayControlJSON(raw, &profiles) != nil || len(profiles.Profiles) != count || profiles.SelectedID != "installed-ordered-final" {
		return errors.Join(err, errors.New("ordered fixture lost its complete independently saved sources"))
	}
	a := &app{localController: controller, profiles: profiles, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{AutoTestSeconds: 10,
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "ordered-host-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 1); err != nil {
		return err
	}
	if err := os.Setenv("SSL_CERT_FILE", filepath.Join(linuxOwnedControllerRoot, "node-chain-peer-ca.pem")); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	releaseMTU, err := a.holdCapturedMTU(ctx)
	if err != nil {
		return err
	}
	defer releaseMTU()
	control, found := a.profileByIDLocked(profiles.SelectedID)
	if !found {
		return errors.New("ordered fixture lost original selected control")
	}
	tokens, err := a.connectionProfileTokensLocked(control)
	if err != nil {
		return err
	}
	body, err := json.Marshal(multihopConnectRequest{Nodes: control.MultihopNodes, Execution: "local",
		desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &profiles.SelectedID, ExpectedProfileTokens: tokens}})
	if err != nil {
		return err
	}
	var constructed *desktopNodeLaunch
	driver := nativeMultihopConnectRuntime{capture: captureNativeMultihopForApp,
		preflight: func(app *app, selected multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			var err error
			constructed, err = preflightOwnedNativeMultihopCommand(app, selected, descriptor)
			return constructed, err
		}, stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop}
	response := httptest.NewRecorder()
	a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(body)).WithContext(ctx), driver)
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	defer func() {
		if failure != nil && session.active != nil {
			cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			failure = errors.Join(failure, session.Retire(cleanup, session.active, false))
		}
	}()
	negative := action == "wrong-awg-parameters" || action == "wrong-middle-key" || action == "wrong-middle-proof" || action == "final-dns-failure" || action == "final-node-failure"
	result := linuxNodeChainHostResult{linuxImportedHostResult: linuxImportedHostResult{Scenario: scenario}}
	if negative {
		if response.Code == http.StatusOK || a.state.Connected || a.cmd != nil || constructed == nil || constructed.chain == nil || constructed.chain.platform == nil {
			return fmt.Errorf("ordered native negative admitted, retained a command or failed before construction: %d %s", response.Code, response.Body.String())
		}
		h := constructed.chain.platform.host
		if h == nil || h.process == nil || h.process.command.ProcessState == nil || !h.closed || !h.released || h.chain != nil || len(h.source) != 0 {
			return errors.New("ordered negative did not join its actual original process/source")
		}
		select {
		case <-h.process.joined:
		default:
			return errors.New("ordered negative returned before original Wait")
		}
		result.Session, result.Rejected = h.selection.SessionID, true
	} else {
		if response.Code != http.StatusOK {
			return fmt.Errorf("installed ordered native Connect failed: %d %s", response.Code, response.Body.String())
		}
		h := session.active
		if h == nil || h.chain == nil || h.activation == nil || h.ready == nil || h.monitor == nil || h.monitor.Load() == nil || h.Current(ctx) != nil || !a.state.Connected {
			return errors.New("ordered native Connect lost original activation, proof or monitor")
		}
		if _, duplicate := desktopNodeOwners.Load(a); duplicate {
			return errors.New("ordered Linux host created another process owner")
		}
		graph, found := getActiveMultihopGraph(a)
		runtime, err := capturedNativeMultihopRuntimeContext(ctx, a, a.cmd, graph)
		if err != nil || !found || runtime == nil || runtime.launch != h.launch || graph.ChainNodes != count || len(runtime.selection.Nodes) != count {
			return errors.Join(err, errors.New("ordered graph lost its original full Linux runtime"))
		}
		status, err := exchangeDesktopNodeChainMeasurement(ctx, h.launch, func(call context.Context) error {
			actual, err := capturedNativeMultihopRuntimeContext(call, a, a.cmd, graph)
			if err != nil || actual != runtime || !a.nativeMultihopProofOwnerCurrentContext(call, runtime.selection, a.cmd) {
				return errors.Join(err, errors.New("installed ordered measurement lost original owner"))
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("installed ordered prefix measurement: %w", err)
		}
		rows, err := desktopNodeChainMeasurementRows(status, runtime.selection.Nodes, 8<<20)
		if err != nil || len(rows) != count {
			return errors.Join(err, errors.New("installed ordered measurement omitted a captured prefix"))
		}
		h.launch.chain.mu.Lock()
		proof := h.launch.chain.ready
		if proof != nil {
			copied := *proof
			result.Proof = &copied
		}
		h.launch.chain.mu.Unlock()
		for i, member := range runtime.selection.Nodes {
			expected := "shadowsocks"
			if i < len(modes) {
				expected = modes[i]
			}
			if member.Mode != expected {
				return errors.New("ordered native owner replaced original cipher")
			}
			result.Nodes = append(result.Nodes, common.MultihopNodeSelection{ID: member.Profile.ID, Mode: member.Mode})
		}
		result.Stage, result.Session, result.Ready, result.Monitor = "ready", h.selection.SessionID, h.ready, true
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if err := linuxHostTUNRendezvous(gate, 2); err != nil {
			return err
		}
		if action == "middle-source" {
			a.mu.Lock()
			a.profiles.Profiles[1].APIToken += "-replaced-after-admission"
			a.mu.Unlock()
		}
		if action == "middle-source" || action == "prefix-lost" {
			deadline := time.NewTimer(12 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			for {
				a.mu.Lock()
				connected := a.state.Connected
				a.mu.Unlock()
				if !connected {
					break
				}
				select {
				case <-deadline.C:
					return errors.New("lost original middle source/proof remained Connected")
				case <-ticker.C:
				}
			}
		}
	}
	stop := httptest.NewRecorder()
	a.disconnect(stop, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil).WithContext(ctx))
	if stop.Code != http.StatusOK || a.cmd != nil || a.state.Connected || session.active != nil {
		return fmt.Errorf("ordered Disconnect did not join original owner: %d %s", stop.Code, stop.Body.String())
	}
	if session.journal == nil {
		return errors.New("ordered cleanup omitted original journal")
	}
	head, err := session.journal.Snapshot(ctx)
	if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
		return errors.Join(err, errors.New("ordered cleanup did not settle original protection"))
	}
	if _, found := nativeMultihopOwners.Load(a); found {
		return errors.New("ordered cleanup retained graph authority")
	}
	if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
		return err
	}
	result.Stage, result.Retired = "retired", true
	controller.close()
	return json.NewEncoder(os.Stdout).Encode(result)
}

func TestDesktopLinuxInstalledNodeChainFixtureKeepsCompiledAuthority(t *testing.T) {
	for _, scenario := range linuxNodeChainCipherCases() {
		count := len(scenario.modes) + 1
		t.Run(scenario.name, func(t *testing.T) {
			peer := linuxNodeChainPeerKeys(t, count)
			linuxNodeChainSetModes(t, peer, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			profiles, assets := linuxNodeChainInstalledSources(t, peer, "")
			root := t.TempDir()
			for id, modes := range assets {
				for mode, files := range modes {
					directory := filepath.Join(root, "generated", id, mode)
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
			final := profiles.Profiles[len(profiles.Profiles)-1]
			capture, err := captureDesktopNodeChain(context.Background(), root, final, profiles.Profiles, final.MultihopNodes, "local", nil)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("a", 32), "linux", 0)
			if err != nil {
				t.Fatal(err)
			}
			proofs := policy.NodeChain().ProofInventory()
			physical, err := policy.NodeChain().PhysicalEgress()
			if err != nil || len(proofs) != count || len(physical) != 1 || physical[0].Host != "192.168.210.2" {
				t.Fatal("ordered fixture lost complete source/first physical authority", physical, err)
			}
			var compiled map[string]any
			if json.Unmarshal([]byte(capture.chain.Config()), &compiled) != nil {
				t.Fatal("compiled installed graph unavailable")
			}
			for i, mode := range scenario.modes {
				row := compiled["endpoints"].([]any)[i].(map[string]any)
				expected := "wireguard"
				if mode != "wg" {
					expected = mobilemultihop.AmneziaType
					parameters := row["amnezia"].(map[string]any)
					if len(parameters) != len(peer.requests[i].Parameters) {
						t.Fatal("compiled installed AWG lost parameter inventory")
					}
					for key, value := range peer.requests[i].Parameters {
						if parameters[key] != value {
							t.Fatal("compiled installed AWG substituted parameters", i, key)
						}
					}
				}
				if row["type"] != expected {
					t.Fatal("compiled installed prefix substituted cipher", i)
				}
			}
			for i, proof := range proofs {
				if proof.ProfileID != profiles.Profiles[i].ID || proof.NodeID != profiles.Profiles[i].NodeProofID {
					t.Fatal("ordered fixture substituted middle/final proof", i)
				}
			}
		})
	}
}
