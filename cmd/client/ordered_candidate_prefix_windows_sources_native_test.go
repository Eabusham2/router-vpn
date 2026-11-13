//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

// Source fixtures retain the same independent paired WG/AWG identities used by
// the installed Linux gate. No runtime, packet, kernel or journal is modeled.
import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strconv"
	"strings"
	"testing"
)

type windowsPrefixPrefixRequest struct {
	Mode            string            `json:"mode"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	PrivateKey      string            `json:"private_key"`
	ClientPublicKey string            `json:"client_public_key"`
	PreSharedKey    string            `json:"pre_shared_key"`
	NodeProofID     string            `json:"node_proof_id"`
	APIToken        string            `json:"api_token"`
}
type windowsPrefixPeer struct {
	clients                  []*ecdh.PrivateKey
	requests                 []windowsPrefixPrefixRequest
	finalClient, finalServer *ecdh.PrivateKey
	password                 string
	reply                    windowsPrefixPeerReply
}

func windowsPrefixProofID(key *ecdh.PrivateKey) string {
	digest := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())))
	return hex.EncodeToString(digest[:])
}

func windowsPrefixSetModes(t *testing.T, peer *windowsPrefixPeer, modes []string) {
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

func windowsPrefixPeerKeys(t *testing.T, count int) *windowsPrefixPeer {
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
	peer := &windowsPrefixPeer{finalClient: key(), finalServer: key(), password: random()}
	for i := 0; i < count-1; i++ {
		client, server := key(), key()
		peer.clients = append(peer.clients, client)
		peer.requests = append(peer.requests, windowsPrefixPrefixRequest{Mode: "wg", PrivateKey: base64.StdEncoding.EncodeToString(server.Bytes()),
			ClientPublicKey: base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()), PreSharedKey: random(),
			NodeProofID: windowsPrefixProofID(server), APIToken: fmt.Sprintf("installed-ordered-prefix-%d-token", i)})
	}
	return peer
}

func windowsPrefixInstalledSources(t *testing.T, peer *windowsPrefixPeer, fault string) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
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
			NodeProofID: windowsPrefixProofID(server), Endpoint: address.Addr().String(), RouterAPI: "http://" + inner + ".1:8787", APIToken: prefix.APIToken,
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
	final := common.RouterProfile{ID: "installed-ordered-final", Name: "Original ordered paired final", NodeProofID: windowsPrefixProofID(peer.finalServer),
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

func windowsPrefixPrefixCandidateSources(t *testing.T, peer *windowsPrefixPeer) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	store, assets := windowsPrefixInstalledSources(t, peer, "")
	final := store.Profiles[len(store.Profiles)-1]
	candidate := cloneRouterProfile(final)
	candidate.ID, candidate.Name = "installed-prefix-candidate", "Original independent prefix candidate"
	candidate.MultihopEnabled = false
	candidate.MultihopNodes = nil
	candidate.MultihopEntryID, candidate.MultihopExitID, candidate.MultihopEntryMode = "", "", ""
	if err := common.NormalizeRouterProfile(&candidate); err != nil {
		t.Fatal(err)
	}
	assets[candidate.ID] = map[string]map[string][]byte{}
	for mode, files := range assets[final.ID] {
		assets[candidate.ID][mode] = map[string][]byte{}
		for name, data := range files {
			assets[candidate.ID][mode][name] = append([]byte(nil), data...)
		}
	}
	var original map[string]any
	if json.Unmarshal(assets[final.ID]["shadowsocks"]["sing-box.json"], &original) != nil {
		t.Fatal("missing original paired final source")
	}
	original["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	assets[final.ID]["shadowsocks"]["sing-box.json"] = raw
	store.Profiles = append(store.Profiles, candidate)
	return store, assets
}
