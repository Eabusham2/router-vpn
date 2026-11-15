//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const macOSPairedNodeNodeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type macOSPairedNodeCase struct{ Mode, Layer, Policy, Action string }

func macOSPairedNodeScenario(s string) macOSPairedNodeCase {
	fields := strings.Split(s, "/")
	if len(fields) != 4 {
		return macOSPairedNodeCase{}
	}
	return macOSPairedNodeCase{fields[0], fields[1], fields[2], fields[3]}
}
func macOSPairedNodeMode(s string) string   { return macOSPairedNodeScenario(s).Mode }
func macOSPairedNodeAction(s string) string { return macOSPairedNodeScenario(s).Action }
func macOSPairedNodeStartLayer(s string) string {
	v := macOSPairedNodeScenario(s).Layer
	if v == "off" {
		return ""
	}
	return v
}
func macOSPairedNodeAmneziaMode(s string) string    { return macOSPairedNodeMode(s) }
func macOSPairedNodeAmneziaLayer(s string) string   { return macOSPairedNodeStartLayer(s) }
func macOSPairedNodeHysteria2Layer(s string) string { return macOSPairedNodeStartLayer(s) }
func macOSPairedNodeSIP003Layer(s string) string    { return macOSPairedNodeStartLayer(s) }
func macOSPairedNodeIsAmnezia(s string) bool        { return awgpolicy.IsMode(s) }
func macOSPairedNodeAmneziaCase(s string) bool {
	return macOSPairedNodeIsAmnezia(macOSPairedNodeMode(s))
}
func macOSPairedNodeHysteria2Case(s string) bool { return macOSPairedNodeMode(s) == "hysteria2" }
func macOSPairedNodeHysteria2LayerCase(s string) bool {
	return macOSPairedNodeHysteria2Case(s) && macOSPairedNodeStartLayer(s) != ""
}
func macOSPairedNodeSIP003Case(s string) bool   { return macOSPairedNodeMode(s) == "ss-v2ray" }
func macOSPairedNodeWrongKeyCase(s string) bool { return macOSPairedNodeAction(s) == "wrong-key" }
func macOSPairedNodeCoverCase(s string) bool    { return false }
func macOSPairedNodePublicCase(s string) bool   { return true }
func macOSPairedNodeProfile(peer *macOSPairedNodePeer, s string) common.RouterProfile {
	c := macOSPairedNodeScenario(s)
	profile := common.RouterProfile{ID: "installed-macos-paired-node", Name: "Actual installed paired Router", NodeKind: "router-vpn", NodeProofID: peer.nodeID, Endpoint: peer.address.Addr().String(), RouterAPI: "http://10.77.0.1:8787", AdGuardIPv4: "192.168.50.133", DNSMode: "home", IPv6Mode: "on", KillSwitch: c.Policy != "off", KillSwitchPolicy: c.Policy, MTUPolicy: "manual", ManualMTU: 1376, StartLayer: c.Layer, DAITAHost: "10.77.0.1", DAITAPort: 45998}
	if c.Action == "home-lan-wrong-node" {
		profile.HomeLANAccess = true
		profile.HomeLANCIDRs = []string{"10.77.0.0/24"}
	}
	if c.Action == "mtu-rollback" {
		profile.MTUPolicy = "auto"
		profile.ManualMTU = 0
	}
	return profile
}
func macOSPairedNodeCopy(t *testing.T, source, destination string, maximum int64, expected string, mode os.FileMode) {
	t.Helper()
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !nativeDigest(expected) || maximum <= 0 {
		t.Fatal("installed-host fixture lost its exact original payload")
	}
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fd), "original-installed-host-payload")
	defer input.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || before.Mode&06022 != 0 || before.Size <= 0 || before.Size > maximum {
		t.Fatal("installed-host fixture lost its bounded regular source")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maximum+1))
	flushErr, closeErr := output.Sync(), output.Close()
	if err := syscall.Fstat(fd, &after); err != nil || copyErr != nil || flushErr != nil || closeErr != nil || n != before.Size ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Nlink != after.Nlink ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Size != after.Size || before.Mtimespec != after.Mtimespec || before.Ctimespec != after.Ctimespec ||
		hex.EncodeToString(hash.Sum(nil)) != expected {
		t.Fatal("installed-host payload changed during its original bounded copy", err, copyErr, flushErr, closeErr)
	}
	var installed syscall.Stat_t
	if syscall.Lstat(destination, &installed) != nil || installed.Mode&syscall.S_IFMT != syscall.S_IFREG || installed.Nlink != 1 || installed.Uid != 0 ||
		installed.Gid != 0 || installed.Mode&07777 != uint16(mode.Perm()) || installed.Size != n {
		t.Fatal("installed-host payload did not retain its exact protected private copy")
	}
}

func macOSPairedNodeStartPeer(t *testing.T, scenario string) *macOSPairedNodePeer {
	t.Helper()
	directory, err := os.MkdirTemp("/private/var/tmp", "routervpn-host-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	image := filepath.Join(directory, "peer.test")
	macOSPairedNodeCopy(t, os.Getenv("ROUTERVPN_MACOS_PAIRED_NODE_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_MACOS_PAIRED_NODE_PEER_SHA256"), 0755)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), macOSPairedNodeCaseBudget(scenario)+10*time.Second)
	t.Cleanup(cancel)
	peer := &macOSPairedNodePeer{physical: macOSExternalNativeAddress(t), password: base64.StdEncoding.EncodeToString(key[:]), done: make(chan struct{}), layer: macOSPairedNodeStartLayer(scenario),
		mode: macOSPairedNodeMode(scenario), nodeID: macOSPairedNodeNodeID}
	clear(key[:])
	selector, childOwner := "TestRouterVPNDesktopNodeLayerReferenceProcess", "ROUTERVPN_NODE_LAYER_REFERENCE_CHILD=1"
	var clientPublic string
	if peer.mode == "wg" || macOSPairedNodeIsAmnezia(peer.mode) {
		client, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		server, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peer.clientKey, clientPublic = base64.StdEncoding.EncodeToString(client.Bytes()), base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())
		peer.serverKey, peer.serverPublic = base64.StdEncoding.EncodeToString(server.Bytes()), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
		digest := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + peer.serverPublic))
		peer.nodeID = hex.EncodeToString(digest[:])
		selector, childOwner = "TestRouterVPNDesktopNodeWireGuardReferenceProcess", "ROUTERVPN_NODE_WG_REFERENCE_CHILD=1"
		if peer.mode == "wg" && peer.layer != "" {
			selector, childOwner = "TestRouterVPNDesktopNodeWireGuardLayerReferenceProcess", "ROUTERVPN_NODE_WG_LAYER_REFERENCE_CHILD=1"
			if _, err := rand.Read(key[:]); err != nil {
				t.Fatal(err)
			}
			peer.layerPassword = base64.StdEncoding.EncodeToString(key[:])
			clear(key[:])
		}
		if macOSPairedNodeIsAmnezia(peer.mode) {
			selector, childOwner = "TestRouterVPNDesktopNodeAmneziaReferenceProcess", "ROUTERVPN_NODE_AWG_REFERENCE_CHILD=1"
			peer.parameters = macOSPairedNodeAmneziaParameters(t, peer.mode)
			if peer.layer != "" {
				selector, childOwner = "TestRouterVPNDesktopNodeAmneziaLayerReferenceProcess", "ROUTERVPN_NODE_AWG_LAYER_REFERENCE_CHILD=1"
				if _, err := rand.Read(key[:]); err != nil {
					t.Fatal(err)
				}
				peer.layerPassword = base64.StdEncoding.EncodeToString(key[:])
				clear(key[:])
			}
		}
	}
	peer.command = exec.CommandContext(ctx, image,
		"-test.run=^"+selector+"$", "-test.count=1", "-test.timeout="+macOSPairedNodeCaseBudget(scenario).String())
	peer.command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", childOwner}
	if peer.layer == common.StartLayerAES256GCMXOR {
		relay := filepath.Join(directory, "start-layer-relay")
		macOSPairedNodeCopy(t, os.Getenv("ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_BINARY"), relay, 128<<20, os.Getenv("ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_SHA256"), 0755)
		peer.command.Env = append(peer.command.Env, "ROUTER_VPN_WHITENING_TEST_BINARY="+relay)
	}
	peer.input, err = peer.command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var writer *os.File
	peer.output, writer, err = os.Pipe()
	if err != nil {
		cancel()
		_ = peer.input.Close()
		t.Fatal(err)
	}
	peer.reader = bufio.NewReaderSize(peer.output, (64<<10)+1)
	peer.command.Stdout, peer.command.Stderr = writer, &peer.diagnostic
	if err := peer.command.Start(); err != nil {
		cancel()
		_ = peer.input.Close()
		_ = peer.output.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	go func() { peer.waitErr = peer.command.Wait(); close(peer.done) }()
	t.Cleanup(func() {
		_ = peer.input.Close()
		select {
		case <-peer.done:
			if peer.waitErr != nil {
				t.Error("installed-host independent reference failed", peer.waitErr, peer.diagnostic.String())
			}
		case <-time.After(5 * time.Second):
			cancel()
			<-peer.done
			t.Error("installed-host reference did not join its original owned pipe", peer.diagnostic.String())
		}
		cancel()
		_ = peer.output.Close()
	})
	request := map[string]any{"schema": 1, "mode": peer.mode, "layer": peer.layer, "address": peer.physical.String(),
		"password": peer.password, "node_proof_id": macOSPairedNodeNodeID, "direct_router": true, "configuration": map[string]any{}}
	if peer.mode == "wg" || macOSPairedNodeIsAmnezia(peer.mode) {
		request = map[string]any{"schema": 1, "address": peer.physical.String(), "client_address": peer.physical.String(),
			"private_key": peer.serverKey, "client_public_key": clientPublic, "pre_shared_key": peer.password, "node_proof_id": peer.nodeID, "direct_router": true}
	}
	if (peer.mode == "wg" || macOSPairedNodeIsAmnezia(peer.mode)) && peer.layer != "" {
		request["layer"], request["aes_password"], request["relay_source"] = peer.layer, peer.layerPassword, peer.physical.String()
		if macOSPairedNodeAction(scenario) == "wrong-whitening" {
			request["whitening_mismatch"] = true
		}
	}
	if macOSPairedNodeIsAmnezia(peer.mode) {
		request["mode"], request["parameters"] = peer.mode, peer.parameters
	}
	if (macOSPairedNodeHysteria2LayerCase(scenario) || macOSPairedNodeSIP003Case(scenario)) && macOSPairedNodeAction(scenario) == "wrong-whitening" {
		request["whitening_mismatch"] = true
	}
	if macOSPairedNodeCoverCase(scenario) {
		request["cover"] = true
	}
	request["benchmark_port"] = 45998
	if err := json.NewEncoder(peer.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	peer.read(t)
	return peer
}

func macOSPairedNodeDirectHealth(t *testing.T, peer *macOSPairedNodePeer) {
	t.Helper()
	before := peer.observe(t, "stats")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("direct Router control cannot redirect") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.77.0.1:8787/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("same-identity direct LAN positive control was not reachable", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	after := peer.observe(t, "stats")
	if readErr != nil || closeErr != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || validateCapturedNodeProof(peer.nodeID, body) != nil ||
		after.DirectQueries != before.DirectQueries+1 || after.RouterQueries != before.RouterQueries || after.RawTCP != before.RawTCP {
		t.Fatal("direct LAN control did not retain its independent valid-node response counter", readErr, closeErr, before, after)
	}
}

func macOSPairedNodeInstallProfile(t *testing.T, peer *macOSPairedNodePeer, scenario string) {
	t.Helper()
	profile := macOSPairedNodeProfile(peer, scenario)
	if macOSPairedNodePublicCase(scenario) {
		catalog, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
		if err != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "modes.json"), catalog, 0600) != nil {
			t.Fatal("actual installed public Connect lost the shipping runtime catalog", err)
		}
	}
	password := peer.password
	if peer.mode == "wg" || macOSPairedNodeIsAmnezia(peer.mode) {
		password = peer.layerPassword
	}
	if peer.mode != "wg" && !macOSPairedNodeIsAmnezia(peer.mode) && peer.mode != "hysteria2" && peer.mode != "ss-v2ray" && macOSPairedNodeWrongKeyCase(scenario) ||
		(peer.mode == "wg" || macOSPairedNodeIsAmnezia(peer.mode) || peer.mode == "hysteria2" || peer.mode == "ss-v2ray") && macOSPairedNodeAction(scenario) == "wrong-layer-key" {
		password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	}
	store, err := json.Marshal(common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
	if err != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), store, 0600) != nil {
		t.Fatal("actual installed host lost its captured profile", err)
	}
	directory := filepath.Join(macOSOwnedControllerRoot, "generated", profile.ID, peer.mode)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if peer.mode == "wg" {
		private, psk, endpoint := peer.clientKey, peer.password, peer.address
		if macOSPairedNodeAction(scenario) == "wrong-key" {
			private = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
		}
		if macOSPairedNodeAction(scenario) == "wrong-psk" {
			psk = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x28}, 32))
		}
		if peer.layer != "" {
			endpoint = peer.baseAddress
		}
		graph := fmt.Sprintf("[Interface]\nAddress=10.78.0.2/32,fd78:78::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=1280\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n", private, peer.serverPublic, psk, endpoint.String())
		if err := os.WriteFile(filepath.Join(directory, "wg.conf"), []byte(graph), 0600); err != nil {
			t.Fatal("installed WireGuard lost its exact paired private source", err)
		}
		if peer.layer == "" {
			return
		}
		directory = filepath.Join(macOSOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if macOSPairedNodeIsAmnezia(peer.mode) {
		if err := os.WriteFile(filepath.Join(directory, "awg.conf"), macOSPairedNodeAmneziaAsset(t, peer, scenario), 0600); err != nil {
			t.Fatal("installed AWG lost its exact paired source and parameters", err)
		}
		if peer.layer == "" {
			return
		}
		directory = filepath.Join(macOSOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if peer.mode == "hysteria2" {
		assets := macOSPairedNodeHysteria2Assets(t, peer, scenario)
		for _, name := range []string{"sing-box.json", "cert.pem"} {
			if err := os.WriteFile(filepath.Join(directory, name), assets[name], 0600); err != nil {
				t.Fatal("installed Hysteria2 lost its exact independent source bytes", err)
			}
		}
		if peer.layer == "" {
			return
		}
		directory = filepath.Join(macOSOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if peer.mode == "ss-v2ray" {
		assets := macOSPairedNodeSIP003Assets(t, peer, scenario)
		for _, name := range []string{"sing-box.json", "sslocal.json", "cert.pem"} {
			if err := os.WriteFile(filepath.Join(directory, name), assets[name], 0600); err != nil {
				t.Fatal("SIP003 lost a captured private source asset", err)
			}
		}
		if peer.layer == "" {
			return
		}
		directory = filepath.Join(macOSOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": profile.Endpoint, "server_port": int(peer.aesAddress.Port()),
			"method": "2022-blake3-aes-256-gcm", "password": password}}, "route": map[string]any{"final": "proxy"}})
	if err != nil || os.WriteFile(filepath.Join(directory, "sing-box.json"), graph, 0600) != nil {
		t.Fatal("actual installed host lost its private encrypted graph", err)
	}
}

func macOSPairedNodeAmneziaParameters(t *testing.T, mode string) map[string]string {
	t.Helper()
	if !awgpolicy.IsMode(mode) {
		t.Fatal("installed AWG peer has no captured mode")
	}
	parameters := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32",
		"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	if mode == "awg2-strong" {
		parameters["jc"], parameters["jmax"] = "8", "1200"
	}
	return parameters
}

func macOSPairedNodeAmneziaDigest(t *testing.T, parameters map[string]string) string {
	t.Helper()
	ipc, err := awgpolicy.ParametersUAPI(parameters)
	if err != nil {
		t.Fatal("installed AWG lost its bounded native parameters", err)
	}
	digest := sha256.Sum256([]byte(ipc))
	return hex.EncodeToString(digest[:])
}

func macOSPairedNodeAmneziaAsset(t *testing.T, peer *macOSPairedNodePeer, scenario string) []byte {
	t.Helper()
	if !macOSPairedNodeAmneziaCase(scenario) || macOSPairedNodeAmneziaMode(scenario) != peer.mode || peer.layer != macOSPairedNodeAmneziaLayer(scenario) ||
		peer.parametersSHA256 == "" || macOSPairedNodeAmneziaDigest(t, peer.parameters) != peer.parametersSHA256 {
		t.Fatal("installed AWG lost its original complete peer/source capture")
	}
	parameters := make(map[string]string, len(peer.parameters))
	for name, value := range peer.parameters {
		parameters[name] = value
	}
	private, psk := peer.clientKey, peer.password
	switch macOSPairedNodeAction(scenario) {
	case "wrong-key":
		private = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	case "wrong-psk":
		psk = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x28}, 32))
	case "wrong-header":
		parameters["h1"] = "50000000-59999999"
	case "wrong-padding":
		parameters["s1"] = "57"
	}
	ipc, err := awgpolicy.ParametersUAPI(parameters)
	if err != nil {
		t.Fatal("installed AWG negative source became malformed rather than a real mismatched native peer", err)
	}
	endpoint := peer.address
	if peer.layer != "" {
		endpoint = peer.baseAddress
	}
	return []byte(fmt.Sprintf("[Interface]\nAddress=10.78.0.2/32,fd78:78::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=1280\n%s[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n",
		private, ipc, peer.serverPublic, psk, endpoint.String()))
}

func macOSPairedNodeHysteria2Assets(t *testing.T, peer *macOSPairedNodePeer, scenario string) map[string][]byte {
	t.Helper()
	if peer.mode != "hysteria2" || peer.layer != macOSPairedNodeHysteria2Layer(scenario) || !macOSPairedNodeHysteria2Case(scenario) || peer.protocolFiles == "" {
		t.Fatal("installed Hysteria2 lost its captured peer/layer configuration")
	}
	var encoded map[string]string
	if json.Unmarshal([]byte(peer.protocolFiles), &encoded) != nil || len(encoded) != 2 || encoded["sing-box.json"] == "" || encoded["cert.pem"] == "" {
		t.Fatal("installed Hysteria2 lost its complete independent configuration and CA")
	}
	assets := make(map[string][]byte, len(encoded))
	for name, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) == 0 || len(raw) > 32<<10 || base64.StdEncoding.EncodeToString(raw) != value {
			t.Fatal("installed Hysteria2 changed its exact private source bytes", err)
		}
		assets[name] = raw
	}
	var graph struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			Password   string `json:"password"`
			Obfs       struct {
				Type     string `json:"type"`
				Password string `json:"password"`
			} `json:"obfs"`
			TLS struct {
				Enabled         bool   `json:"enabled"`
				Insecure        bool   `json:"insecure"`
				ServerName      string `json:"server_name"`
				CertificatePath string `json:"certificate_path"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(assets["sing-box.json"], &graph) != nil || len(graph.Outbounds) != 1 {
		t.Fatal("installed Hysteria2 has another independent transport graph")
	}
	out := graph.Outbounds[0]
	endpoint := peer.address
	if peer.layer != "" {
		endpoint = peer.baseAddress
	}
	if out.Type != "hysteria2" || out.Tag != "proxy" || out.Server != endpoint.Addr().String() || out.ServerPort != int(endpoint.Port()) ||
		out.Password == "" || out.Obfs.Type != "salamander" || out.Obfs.Password == "" || out.Obfs.Password == out.Password ||
		!out.TLS.Enabled || out.TLS.Insecure || out.TLS.ServerName != "captured-node.test" || out.TLS.CertificatePath != "cert.pem" {
		t.Fatal("installed Hysteria2 changed the captured UDP endpoint, authentication, Salamander or selected trust")
	}
	// Positive cases copy both original byte strings without reserialization.
	// Negative cases change only their named authentication/trust field.
	action := macOSPairedNodeAction(scenario)
	if action == "wrong-key" || action == "wrong-trust" || action == "wrong-salamander" {
		var changed map[string]any
		if err := json.Unmarshal(assets["sing-box.json"], &changed); err != nil {
			t.Fatal(err)
		}
		outer := changed["outbounds"].([]any)[0].(map[string]any)
		switch action {
		case "wrong-key":
			outer["password"] = out.Password + "-wrong"
		case "wrong-trust":
			outer["tls"].(map[string]any)["server_name"] = "wrong-node.test"
		case "wrong-salamander":
			outer["obfs"].(map[string]any)["password"] = out.Obfs.Password + "-wrong"
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		assets["sing-box.json"] = raw
	}
	return assets
}

func macOSPairedNodeSIP003Assets(t *testing.T, peer *macOSPairedNodePeer, scenario string) map[string][]byte {
	t.Helper()
	if peer.mode != "ss-v2ray" || peer.layer != macOSPairedNodeSIP003Layer(scenario) || !macOSPairedNodeSIP003Case(scenario) || peer.protocolFiles == "" {
		t.Fatal("SIP003 fixture lost its exact captured source")
	}
	var encoded map[string]string
	if json.Unmarshal([]byte(peer.protocolFiles), &encoded) != nil || len(encoded) != 3 || encoded["sing-box.json"] == "" || encoded["sslocal.json"] == "" || encoded["cert.pem"] == "" {
		t.Fatal("SIP003 fixture lost either private lane or selected CA")
	}
	assets := map[string][]byte{}
	for name, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) == 0 || len(raw) > 32<<10 || base64.StdEncoding.EncodeToString(raw) != value {
			t.Fatal("SIP003 source bytes changed", err)
		}
		assets[name] = raw
	}
	var helper map[string]any
	var graph map[string]any
	if json.Unmarshal(assets["sslocal.json"], &helper) != nil || json.Unmarshal(assets["sing-box.json"], &graph) != nil {
		t.Fatal("SIP003 lost its two exact JSON sources")
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok || len(outbounds) != 3 {
		t.Fatal("SIP003 fixture acquired another runtime lane")
	}
	tcp, ok := outbounds[0].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing TCP wrapper")
	}
	udp, ok := outbounds[1].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP branch")
	}
	tls, ok := udp["tls"].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP trust")
	}
	obfs, ok := udp["obfs"].(map[string]any)
	if !ok {
		t.Fatal("SIP003 missing UDP Salamander")
	}
	plugin, ok := helper["plugin_opts"].(string)
	const prefix = "tls;host=captured-sip003.test;path=/captured-shadowsocks;certRaw="
	if !ok || !strings.HasPrefix(plugin, prefix) || len(plugin) <= len(prefix) || strings.Contains(plugin[len(prefix):], ";") {
		t.Fatal("SIP003 fixture changed selected TLS host/path/CA")
	}
	certificate, err := base64.StdEncoding.Strict().DecodeString(plugin[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certificate)
	if err != nil || cert.VerifyHostname("captured-sip003.test") != nil {
		t.Fatal("SIP003 fixture lost its real selected TCP certificate", err)
	}
	key, ok := helper["password"].(string)
	if !ok {
		t.Fatal("SIP003 missing TCP credential")
	}
	keyBytes, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(keyBytes) != 32 || key == peer.password || helper["method"] != "2022-blake3-aes-256-gcm" || helper["mode"] != "tcp_only" || helper["plugin"] != "v2ray-plugin" || helper["server"] != peer.baseAddress.Addr().String() || helper["server_port"] != float64(peer.baseAddress.Port()) || helper["local_address"] != "127.0.0.1" || helper["local_port"] != float64(1092) ||
		tcp["type"] != "socks" || tcp["tag"] != "tcp-stack" || tcp["server"] != "127.0.0.1" || tcp["server_port"] != float64(1092) || tcp["version"] != "5" ||
		udp["type"] != "hysteria2" || udp["tag"] != "udp-stack" || udp["server"] != peer.udpBranchAddress.Addr().String() || udp["server_port"] != float64(peer.udpBranchAddress.Port()) ||
		tls["enabled"] != true || tls["insecure"] == true || tls["server_name"] != "captured-node.test" || tls["certificate_path"] != "cert.pem" || obfs["type"] != "salamander" {
		t.Fatal("SIP003 changed its endpoint, credential, protocol, trust or separate lane")
	}
	clear(keyBytes)
	password, ok := udp["password"].(string)
	if !ok || password == "" {
		t.Fatal("SIP003 lost independent UDP credential")
	}
	mask, ok := obfs["password"].(string)
	if !ok || mask == "" || mask == password {
		t.Fatal("SIP003 lost separate Salamander source")
	}
	// Positive cases copy the complete original three byte strings. Only the
	// named negative mutates its one authentication/trust field.
	action := macOSPairedNodeSIP003Action(scenario)
	switch action {
	case "tcp-key":
		helper["password"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	case "tcp-host":
		helper["plugin_opts"] = strings.Replace(plugin, "host=captured-sip003.test", "host=captured-sip003-alias.test", 1)
	case "tcp-path":
		helper["plugin_opts"] = strings.Replace(plugin, "path=/captured-shadowsocks", "path=/unrelated-path", 1)
	case "tcp-server-name":
		helper["plugin_opts"] = strings.Replace(plugin, "host=captured-sip003.test", "host=wrong-node.test", 1)
	case "tcp-certificate":
		block, rest := pem.Decode(assets["cert.pem"])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("SIP003 negative lost its other valid certificate")
		}
		helper["plugin_opts"] = prefix + base64.StdEncoding.EncodeToString(block.Bytes)
	case "udp-key":
		udp["password"] = password + "-wrong"
	case "udp-trust":
		tls["server_name"] = "wrong-node.test"
	case "udp-salamander":
		obfs["password"] = mask + "-wrong"
	}
	if macOSPairedNodeSIP003TCPFault(scenario) {
		raw, err := json.Marshal(helper)
		if err != nil {
			t.Fatal(err)
		}
		assets["sslocal.json"] = raw
	}
	if strings.HasPrefix(action, "udp-") {
		raw, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		assets["sing-box.json"] = raw
	}
	return assets
}

type macOSPairedNodeBenchmarkReply struct {
	Port           int    `json:"port"`
	Packets        uint64 `json:"packets"`
	Replies        uint64 `json:"replies"`
	ReceivedBytes  uint64 `json:"received_bytes"`
	SentBytes      uint64 `json:"sent_bytes"`
	Held           bool   `json:"held"`
	HeldPackets    uint64 `json:"held_packets"`
	MaximumPayload uint64 `json:"maximum_payload"`
}
type macOSPairedNodePeerReply struct {
	Benchmark             *macOSPairedNodeBenchmarkReply `json:"benchmark,omitempty"`
	Schema                int                            `json:"schema"`
	Address               string                         `json:"address"`
	AESAddress            string                         `json:"aes_address"`
	BaseAddress           string                         `json:"base_address"`
	PhysicalClientAddress string                         `json:"physical_client_address"`
	RelaySourceAddress    string                         `json:"relay_source_address"`
	RejectedUDP           int64                          `json:"rejected_udp"`
	ProtocolFiles         string                         `json:"protocol_files"`
	UDPBranchAddress      string                         `json:"udp_branch_address"`
	UDPBranchRawUDP       int64                          `json:"udp_branch_raw_udp"`
	UDPBranchTCP          int64                          `json:"udp_branch_tcp"`
	UDPBranchUDP          int64                          `json:"udp_branch_udp"`
	ProtocolTLSHTTP       int64                          `json:"protocol_tls_http"`
	ProtocolWebSocket     int64                          `json:"protocol_websocket"`
	ProtocolMux           int64                          `json:"protocol_mux"`
	ParametersSHA256      string                         `json:"parameters_sha256"`
	ProtocolRawTCP        int64                          `json:"protocol_raw_tcp"`
	ProtocolRawUDP        int64                          `json:"protocol_raw_udp"`
	ProtocolTCP           int64                          `json:"protocol_tcp"`
	ProtocolUDP           int64                          `json:"protocol_udp"`
	RawTCP                int64                          `json:"raw_tcp"`
	RawUDP                int64                          `json:"raw_udp"`
	PlainTCP              int64                          `json:"plain_tcp"`
	PlainUDP              int64                          `json:"plain_udp"`
	DNSQueries            uint32                         `json:"dns_queries"`
	RouterQueries         uint32                         `json:"router_queries"`
	DirectQueries         uint32                         `json:"direct_router_queries"`
	CoverPackets          uint64                         `json:"cover_packets"`
	CoverBytes            uint64                         `json:"cover_bytes"`
	CoverReplies          uint64                         `json:"cover_replies"`
	CoverReplyBytes       uint64                         `json:"cover_reply_bytes"`
	CoverMaximum          uint32                         `json:"cover_maximum"`
}

type macOSPairedNodePeer struct {
	physical         netip.Addr
	command          *exec.Cmd
	input            io.WriteCloser
	output           *os.File
	reader           *bufio.Reader
	diagnostic       macOSPairedNodeOutput
	done             chan struct{}
	waitErr          error
	address          netip.AddrPort
	aesAddress       netip.AddrPort
	layer            string
	password         string
	layerPassword    string
	mode             string
	nodeID           string
	clientKey        string
	serverKey        string
	serverPublic     string
	baseAddress      netip.AddrPort
	udpBranchAddress netip.AddrPort
	protocolFiles    string
	parameters       map[string]string
	parametersSHA256 string
}

func (peer *macOSPairedNodePeer) read(t *testing.T) macOSPairedNodePeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer peer.output.SetReadDeadline(time.Time{})
	raw, err := peer.reader.ReadSlice('\n')
	var reply macOSPairedNodePeerReply
	if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &reply) != nil || reply.Schema != 1 || reply.Benchmark == nil || reply.Benchmark.Port != 45998 {
		t.Fatal("installed-host encrypted reference lost its original bounded response", err, peer.diagnostic.String())
	}
	endpoint, err := netip.ParseAddrPort(reply.Address)
	if peer.mode == "wg" {
		if err != nil || endpoint.Addr().String() != peer.physical.String() || endpoint.Port() == 0 || peer.address.IsValid() && peer.address != endpoint ||
			reply.RawTCP != 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 || reply.ProtocolFiles != "" || reply.ParametersSHA256 != "" {
			t.Fatal("installed WireGuard reference changed its original UDP-only peer")
		}
		if peer.layer == "" {
			if reply.AESAddress != "" || reply.BaseAddress != reply.Address || reply.PhysicalClientAddress != "" || reply.RelaySourceAddress != "" {
				t.Fatal("plain WG reference acquired another source owner")
			}
		} else {
			base, baseErr := netip.ParseAddrPort(reply.BaseAddress)
			aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
			whitening := peer.layer == common.StartLayerAES256GCMXOR
			if baseErr != nil || aesErr != nil || base.Addr() != endpoint.Addr() || base.Port() == 0 || aes.Addr() != endpoint.Addr() || aes.Port() == 0 || base == aes || base == endpoint ||
				peer.layer != common.StartLayerAES256GCM && !whitening || whitening && (endpoint.Port() != 8389 || aes == endpoint) || !whitening && aes != endpoint ||
				peer.baseAddress.IsValid() && peer.baseAddress != base || peer.aesAddress.IsValid() && peer.aesAddress != aes || reply.PlainTCP != 0 ||
				reply.PhysicalClientAddress != peer.physical.String() || reply.RelaySourceAddress != peer.physical.String() || reply.RejectedUDP != 0 || reply.ProtocolRawTCP != 0 || reply.ProtocolRawUDP < 0 || reply.ProtocolTCP < 0 || reply.ProtocolUDP < 0 {
				t.Fatal("layered WG replaced original client, local AES relay or separate UDP owners")
			}
			peer.baseAddress, peer.aesAddress = base, aes
		}
		peer.address = endpoint
		return reply
	}
	if macOSPairedNodeIsAmnezia(peer.mode) {
		if err != nil || endpoint.Addr().String() != peer.physical.String() || endpoint.Port() == 0 ||
			peer.address.IsValid() && peer.address != endpoint || reply.RawTCP != 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 ||
			reply.ProtocolFiles != "" || reply.ParametersSHA256 != macOSPairedNodeAmneziaDigest(t, peer.parameters) ||
			peer.parametersSHA256 != "" && peer.parametersSHA256 != reply.ParametersSHA256 {
			t.Fatal("installed AWG reference changed its exact UDP peer or captured native parameters")
		}
		if peer.layer == "" {
			if reply.AESAddress != "" || reply.BaseAddress != reply.Address || reply.PhysicalClientAddress != "" || reply.RelaySourceAddress != "" {
				t.Fatal("plain AWG reference acquired another source owner")
			}
		} else {
			base, baseErr := netip.ParseAddrPort(reply.BaseAddress)
			aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
			whitening := peer.layer == common.StartLayerAES256GCMXOR
			if baseErr != nil || aesErr != nil || base.Addr() != endpoint.Addr() || base.Port() == 0 || aes.Addr() != endpoint.Addr() || aes.Port() == 0 || base == aes || base == endpoint ||
				peer.layer != common.StartLayerAES256GCM && !whitening || whitening && (endpoint.Port() != 8389 || aes == endpoint) || !whitening && aes != endpoint ||
				peer.baseAddress.IsValid() && peer.baseAddress != base || peer.aesAddress.IsValid() && peer.aesAddress != aes || reply.PlainTCP != 0 ||
				reply.PhysicalClientAddress != peer.physical.String() || reply.RelaySourceAddress != peer.physical.String() || reply.RejectedUDP != 0 || reply.ProtocolRawTCP != 0 || reply.ProtocolRawUDP < 0 || reply.ProtocolTCP < 0 || reply.ProtocolUDP < 0 {
				t.Fatal("layered AWG replaced original client, local AES relay or separate UDP owners")
			}
			peer.baseAddress, peer.aesAddress = base, aes
		}
		peer.address, peer.parametersSHA256 = endpoint, reply.ParametersSHA256
		return reply
	}
	if peer.mode == "ss-v2ray" {
		base, baseErr := netip.ParseAddrPort(reply.BaseAddress)
		udp, udpErr := netip.ParseAddrPort(reply.UDPBranchAddress)
		if err != nil || baseErr != nil || udpErr != nil || endpoint.Addr().String() != peer.physical.String() || endpoint.Port() == 0 || base.Addr() != endpoint.Addr() || base.Port() == 0 || udp.Addr() != endpoint.Addr() || udp.Port() == 0 || base == udp ||
			peer.address.IsValid() && peer.address != endpoint || peer.baseAddress.IsValid() && peer.baseAddress != base || peer.udpBranchAddress.IsValid() && peer.udpBranchAddress != udp || reply.ProtocolFiles == "" || peer.protocolFiles != "" && peer.protocolFiles != reply.ProtocolFiles ||
			reply.RawTCP < 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 || reply.ProtocolRawTCP < 0 || reply.ProtocolRawUDP != 0 || reply.ProtocolTCP < 0 || reply.ProtocolUDP != 0 || reply.UDPBranchRawUDP < 0 || reply.UDPBranchTCP != 0 || reply.UDPBranchUDP < 0 ||
			reply.ProtocolTLSHTTP < 0 || reply.ProtocolWebSocket < 0 || reply.ProtocolMux < 0 || reply.PhysicalClientAddress != "" || reply.RelaySourceAddress != "" || reply.ParametersSHA256 != "" || reply.RejectedUDP != 0 {
			t.Fatal("installed SIP003 lost its two exact private protocol endpoints or receipt fields")
		}
		if peer.layer == "" {
			if reply.AESAddress != "" || base != endpoint || reply.RawUDP != 0 || reply.PlainUDP != 0 || reply.ProtocolRawTCP < reply.RawTCP || reply.ProtocolTCP < reply.PlainTCP {
				t.Fatal("plain SIP003 borrowed an outer transport or changed its same-peer observations")
			}
		} else {
			aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
			white := peer.layer == common.StartLayerAES256GCMXOR
			if aesErr != nil || aes.Addr() != endpoint.Addr() || aes.Port() == 0 || aes == base || aes == udp || endpoint == base || endpoint == udp || peer.layer != common.StartLayerAES256GCM && !white || white && (endpoint.Port() != 8389 || aes == endpoint) || !white && aes != endpoint || peer.aesAddress.IsValid() && peer.aesAddress != aes {
				t.Fatal("layered SIP003 replaced the independent AES and final TCP/UDP owners")
			}
			peer.aesAddress = aes
		}
		peer.address, peer.baseAddress, peer.udpBranchAddress, peer.protocolFiles = endpoint, base, udp, reply.ProtocolFiles
		return reply
	}
	if peer.mode == "hysteria2" {
		// These are the same peer's atomic counters, read again later in the
		// reply. QUIC/cover may receive packets between those observations.
		base, baseErr := netip.ParseAddrPort(reply.BaseAddress)
		if err != nil || baseErr != nil || endpoint.Addr().String() != peer.physical.String() || endpoint.Port() == 0 || base.Addr() != endpoint.Addr() || base.Port() == 0 ||
			peer.address.IsValid() && peer.address != endpoint || peer.baseAddress.IsValid() && peer.baseAddress != base ||
			reply.ProtocolFiles == "" || peer.protocolFiles != "" && peer.protocolFiles != reply.ProtocolFiles ||
			reply.RawTCP != 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 || reply.ProtocolRawTCP != 0 ||
			reply.ProtocolRawUDP < 0 || reply.ProtocolTCP < 0 || reply.ProtocolUDP < 0 {
			t.Fatal("installed Hysteria2 reference changed its exact UDP peer, TLS source or protocol counters")
		}
		if peer.layer == "" {
			if reply.AESAddress != "" || base != endpoint || reply.ProtocolRawUDP < reply.RawUDP || reply.ProtocolTCP < reply.PlainTCP || reply.ProtocolUDP < reply.PlainUDP {
				t.Fatal("plain Hysteria2 changed its same-peer observations")
			}
		} else {
			aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
			whitening := peer.layer == common.StartLayerAES256GCMXOR
			if aesErr != nil || aes.Addr() != endpoint.Addr() || aes.Port() == 0 || base == aes || base == endpoint || reply.PlainTCP != 0 ||
				peer.layer != common.StartLayerAES256GCM && !whitening || whitening && (endpoint.Port() != 8389 || aes == endpoint) || !whitening && aes != endpoint ||
				peer.aesAddress.IsValid() && peer.aesAddress != aes {
				t.Fatal("layered Hysteria2 replaced its separate captured AES/QUIC UDP owners")
			}
			peer.aesAddress = aes
		}
		peer.address, peer.baseAddress, peer.protocolFiles = endpoint, base, reply.ProtocolFiles
		return reply
	}
	aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
	whitening := peer.layer == common.StartLayerAES256GCMXOR
	if err != nil || aesErr != nil || endpoint.Addr().String() != peer.physical.String() || endpoint.Port() == 0 || aes.Addr() != endpoint.Addr() || aes.Port() == 0 ||
		whitening && (endpoint.Port() != 8389 || aes == endpoint) || !whitening && aes != endpoint ||
		peer.address.IsValid() && peer.address != endpoint || peer.aesAddress.IsValid() && peer.aesAddress != aes ||
		reply.RawTCP < 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 {
		t.Fatal("installed-host encrypted reference replaced its captured private endpoint")
	}
	peer.address, peer.aesAddress = endpoint, aes
	return reply
}

func (peer *macOSPairedNodePeer) observe(t *testing.T, action string) macOSPairedNodePeerReply {
	t.Helper()
	if action != "stats" && action != "fail-dns" && action != "restore-dns" && action != "wrong-node" && action != "restore-node" && action != "drop-cover" && action != "hold-benchmark" && action != "release-benchmark" {
		t.Fatal("uncaptured installed-host peer observation")
	}
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

type macOSPairedNodeOutput struct {
	sync.Mutex
	bytes.Buffer
}

func (w *macOSPairedNodeOutput) Write(raw []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	return w.Buffer.Write(raw)
}

func (w *macOSPairedNodeOutput) String() string {
	w.Lock()
	defer w.Unlock()
	return w.Buffer.String()
}

func macOSPairedNodeSIP003Action(s string) string { return macOSPairedNodeAction(s) }
func macOSPairedNodeSIP003TCPFault(s string) bool { return false }
