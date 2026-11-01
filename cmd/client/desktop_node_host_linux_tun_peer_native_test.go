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
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

const linuxHostTUNNodeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type linuxHostTUNOutput struct {
	sync.Mutex
	bytes.Buffer
}

func (w *linuxHostTUNOutput) Write(raw []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	return w.Buffer.Write(raw)
}

func (w *linuxHostTUNOutput) String() string {
	w.Lock()
	defer w.Unlock()
	return w.Buffer.String()
}

func linuxHostTUNCommand(t *testing.T, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, arguments[0], arguments[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("owned installed-host namespace command failed: %v: %s", err, output)
	}
}

func linuxHostTUNNamespace(t *testing.T) {
	t.Helper()
	device, inode, present := strings.Cut(os.Getenv("ROUTERVPN_NODE_OUTER_NETNS_ID"), ":")
	outerDevice, deviceErr := strconv.ParseUint(device, 10, 64)
	outerInode, inodeErr := strconv.ParseUint(inode, 10, 64)
	var current, tun syscall.Stat_t
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || !present || deviceErr != nil || inodeErr != nil ||
		outerInode == 0 || syscall.Stat("/proc/self/ns/net", &current) != nil || current.Dev == outerDevice && current.Ino == outerInode {
		t.Fatal("installed Linux host acceptance requires its original separate native namespace")
	}
	if err := syscall.Stat("/dev/net/tun", &tun); err != nil || tun.Mode&syscall.S_IFMT != syscall.S_IFCHR || uint64(tun.Rdev) != (10<<8)|200 {
		t.Fatal("installed Linux host acceptance requires the actual provisioned TUN device", err)
	}
	for _, command := range []struct{ create, remove []string }{
		{[]string{"ip", "addr", "add", "192.168.210.1/30", "dev", "rvpn-test"}, []string{"ip", "addr", "del", "192.168.210.1/30", "dev", "rvpn-test"}},
		{[]string{"ip", "netns", "exec", "rvpn-peer", "ip", "addr", "add", "192.168.210.2/30", "dev", "rvpn-peer"}, []string{"ip", "netns", "exec", "rvpn-peer", "ip", "addr", "del", "192.168.210.2/30", "dev", "rvpn-peer"}},
		{[]string{"ip", "netns", "exec", "rvpn-peer", "ip", "addr", "add", "10.77.0.1/32", "dev", "rvpn-peer"}, []string{"ip", "netns", "exec", "rvpn-peer", "ip", "addr", "del", "10.77.0.1/32", "dev", "rvpn-peer"}},
		{[]string{"ip", "route", "add", "default", "via", "192.168.210.2", "dev", "rvpn-test"}, []string{"ip", "route", "del", "default", "via", "192.168.210.2", "dev", "rvpn-test"}},
	} {
		linuxHostTUNCommand(t, command.create...)
		t.Cleanup(func() { linuxHostTUNCommand(t, command.remove...) })
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
}

// Only an exact regular original is copied into the private installation.
// Keep the nofollow source descriptor through the copy/hash and metadata
// readback; replacing a pathname cannot redirect this source midway.
func linuxHostTUNCopy(t *testing.T, source, destination string, maximum int64, expected string, mode os.FileMode) {
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
		before.Uid != after.Uid || before.Gid != after.Gid || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim ||
		hex.EncodeToString(hash.Sum(nil)) != expected {
		t.Fatal("installed-host payload changed during its original bounded copy", err, copyErr, flushErr, closeErr)
	}
	var installed syscall.Stat_t
	if syscall.Lstat(destination, &installed) != nil || installed.Mode&syscall.S_IFMT != syscall.S_IFREG || installed.Nlink != 1 || installed.Uid != 0 ||
		installed.Gid != 0 || installed.Mode&07777 != uint32(mode.Perm()) || installed.Size != n {
		t.Fatal("installed-host payload did not retain its exact protected private copy")
	}
}

func linuxHostTUNInstallBundle(t *testing.T) {
	t.Helper()
	source, expected := os.Getenv("ROUTERVPN_NODE_HOST_BUNDLE"), os.Getenv("ROUTERVPN_NODE_HOST_BUNDLE_SHA256")
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !nativeDigest(expected) {
		t.Fatal("installed-host fixture has no actual completed native bundle")
	}
	directory := filepath.Join(linuxOwnedControllerRoot, "runtime", "native")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	receiptName := filepath.Join(directory, "NATIVE-RUNTIME.json")
	linuxHostTUNCopy(t, filepath.Join(source, "NATIVE-RUNTIME.json"), receiptName, 32768, expected, 0644)
	raw, err := os.ReadFile(receiptName)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil {
		t.Fatal("actual complete native receipt was not valid for this host", err)
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) != len(receipt.Files)+1 {
		t.Fatal("actual completed bundle omitted or added an unowned payload", err)
	}
	for _, entry := range entries {
		if entry.Name() == "NATIVE-RUNTIME.json" {
			continue
		}
		expected, found := receipt.Files[entry.Name()]
		if !found || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			t.Fatal("actual completed bundle has an unrelated payload")
		}
		mode := os.FileMode(0644)
		if entry.Name() == nativeBinaryName() || entry.Name() == bundledTorBinaryName(receipt.Target) {
			mode = 0755
		}
		linuxHostTUNCopy(t, filepath.Join(source, entry.Name()), filepath.Join(directory, entry.Name()), expected.Size, expected.SHA256, mode)
	}
	if err := verifyNativePayload(directory, receipt); err != nil {
		t.Fatal("installed complete native payload does not match its original receipt", err)
	}
	// The actual controller will execute verifyBundledNativeContext during
	// preparation and launch. This copy grants no substitute verifier result.
}

type linuxHostTUNPeerReply struct {
	Schema          int    `json:"schema"`
	Address         string `json:"address"`
	AESAddress      string `json:"aes_address"`
	RawTCP          int64  `json:"raw_tcp"`
	RawUDP          int64  `json:"raw_udp"`
	PlainTCP        int64  `json:"plain_tcp"`
	PlainUDP        int64  `json:"plain_udp"`
	DNSQueries      uint32 `json:"dns_queries"`
	RouterQueries   uint32 `json:"router_queries"`
	DirectQueries   uint32 `json:"direct_router_queries"`
	CoverPackets    uint64 `json:"cover_packets"`
	CoverBytes      uint64 `json:"cover_bytes"`
	CoverReplies    uint64 `json:"cover_replies"`
	CoverReplyBytes uint64 `json:"cover_reply_bytes"`
	CoverMaximum    uint32 `json:"cover_maximum"`
}

type linuxHostTUNPeer struct {
	command      *exec.Cmd
	input        io.WriteCloser
	output       *os.File
	reader       *bufio.Reader
	diagnostic   linuxHostTUNOutput
	done         chan struct{}
	waitErr      error
	address      netip.AddrPort
	aesAddress   netip.AddrPort
	layer        string
	password     string
	mode         string
	nodeID       string
	clientKey    string
	serverKey    string
	serverPublic string
}

func (peer *linuxHostTUNPeer) read(t *testing.T) linuxHostTUNPeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer peer.output.SetReadDeadline(time.Time{})
	raw, err := peer.reader.ReadSlice('\n')
	var reply linuxHostTUNPeerReply
	if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &reply) != nil || reply.Schema != 1 {
		t.Fatal("installed-host encrypted reference lost its original bounded response", err, peer.diagnostic.String())
	}
	endpoint, err := netip.ParseAddrPort(reply.Address)
	if peer.mode == "wg" {
		if err != nil || endpoint.Addr().String() != "192.168.210.2" || endpoint.Port() == 0 || reply.AESAddress != "" ||
			peer.address.IsValid() && peer.address != endpoint || reply.RawTCP != 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 {
			t.Fatal("installed WireGuard reference changed its original UDP-only peer")
		}
		peer.address = endpoint
		return reply
	}
	aes, aesErr := netip.ParseAddrPort(reply.AESAddress)
	whitening := peer.layer == common.StartLayerAES256GCMXOR
	if err != nil || aesErr != nil || endpoint.Addr().String() != "192.168.210.2" || endpoint.Port() == 0 || aes.Addr() != endpoint.Addr() || aes.Port() == 0 ||
		whitening && (endpoint.Port() != 8389 || aes == endpoint) || !whitening && aes != endpoint ||
		peer.address.IsValid() && peer.address != endpoint || peer.aesAddress.IsValid() && peer.aesAddress != aes ||
		reply.RawTCP < 0 || reply.RawUDP < 0 || reply.PlainTCP < 0 || reply.PlainUDP < 0 {
		t.Fatal("installed-host encrypted reference replaced its captured private endpoint")
	}
	peer.address, peer.aesAddress = endpoint, aes
	return reply
}

func (peer *linuxHostTUNPeer) observe(t *testing.T, action string) linuxHostTUNPeerReply {
	t.Helper()
	if action != "stats" && action != "fail-dns" && action != "restore-dns" && action != "wrong-node" && action != "restore-node" && action != "drop-cover" {
		t.Fatal("uncaptured installed-host peer observation")
	}
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

func linuxHostTUNStartPeer(t *testing.T, scenario string) *linuxHostTUNPeer {
	t.Helper()
	directory, err := os.MkdirTemp("/opt", "routervpn-host-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	image := filepath.Join(directory, "peer.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	t.Cleanup(cancel)
	peer := &linuxHostTUNPeer{password: base64.StdEncoding.EncodeToString(key[:]), done: make(chan struct{}), layer: linuxHostTUNStartLayer(scenario),
		mode: linuxHostTUNMode(scenario), nodeID: linuxHostTUNNodeID}
	clear(key[:])
	selector, childOwner := "TestRouterVPNDesktopNodeLayerReferenceProcess", "ROUTERVPN_NODE_LAYER_REFERENCE_CHILD=1"
	var clientPublic string
	if peer.mode == "wg" {
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
	}
	peer.command = exec.CommandContext(ctx, "ip", "netns", "exec", "rvpn-peer", image,
		"-test.run=^"+selector+"$", "-test.count=1", "-test.timeout=105s")
	peer.command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", childOwner}
	if peer.layer == common.StartLayerAES256GCMXOR {
		relay := filepath.Join(directory, "start-layer-relay")
		linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_WHITENING_BINARY"), relay, 128<<20, os.Getenv("ROUTERVPN_NODE_HOST_WHITENING_SHA256"), 0755)
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
	request := map[string]any{"schema": 1, "mode": "shadowsocks", "layer": peer.layer, "address": "192.168.210.2",
		"password": peer.password, "node_proof_id": linuxHostTUNNodeID, "direct_router": true, "configuration": map[string]any{}}
	if peer.mode == "wg" {
		request = map[string]any{"schema": 1, "address": "192.168.210.2", "client_address": "192.168.210.1",
			"private_key": peer.serverKey, "client_public_key": clientPublic, "pre_shared_key": peer.password, "node_proof_id": peer.nodeID, "direct_router": true}
	}
	if linuxHostTUNCoverCase(scenario) {
		request["cover"] = true
	}
	if err := json.NewEncoder(peer.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	peer.read(t)
	return peer
}

func linuxHostTUNDirectHealth(t *testing.T, peer *linuxHostTUNPeer) {
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

func linuxHostTUNProfile(peer *linuxHostTUNPeer, scenario string) common.RouterProfile {
	profile := common.RouterProfile{ID: "installed-linux-node", Name: "Actual installed Linux node", NodeKind: "router-vpn", NodeProofID: peer.nodeID,
		Endpoint: peer.address.Addr().String(), RouterAPI: "http://10.77.0.1:8787", AdGuardIPv4: "192.168.50.133", DNSMode: "home", IPv6Mode: "on",
		KillSwitch: true, KillSwitchPolicy: "on-connect", MTUPolicy: "fixed", ManualMTU: 1376, EffectiveMTU: 9000, StartLayer: peer.layer}
	if linuxHostTUNAction(scenario) == "home-lan" {
		profile.HomeLANAccess = true
		profile.HomeLANCIDRs = []string{"10.77.0.0/24", "192.168.210.0/30"}
	}
	if linuxHostTUNAction(scenario) == "always" || linuxHostTUNOffCase(scenario) {
		profile.KillSwitchPolicy = "always"
	}
	if linuxHostTUNCoverCase(scenario) {
		profile.DAITAHost, profile.DAITAPort, profile.DAITARateKbps = "10.77.0.1", 45999, 64
		profile.DAITAEnabled = !linuxHostTUNPublicCase(scenario) && !linuxHostTUNRestoreCase(scenario)
	}
	if linuxHostTUNMTUCase(scenario) || linuxHostTUNRestoreCase(scenario) {
		profile.MTUPolicy, profile.ManualMTU = "auto", 0
	}
	return profile
}

func linuxHostTUNInstallProfile(t *testing.T, peer *linuxHostTUNPeer, scenario string) {
	t.Helper()
	profile := linuxHostTUNProfile(peer, scenario)
	if linuxHostTUNPublicCase(scenario) {
		catalog, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
		if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "modes.json"), catalog, 0600) != nil {
			t.Fatal("actual installed public Connect lost the shipping runtime catalog", err)
		}
	}
	password := peer.password
	if linuxHostTUNWrongKeyCase(scenario) {
		password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	}
	store, err := json.Marshal(common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), store, 0600) != nil {
		t.Fatal("actual installed host lost its captured profile", err)
	}
	directory := filepath.Join(linuxOwnedControllerRoot, "generated", profile.ID, peer.mode)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if peer.mode == "wg" {
		private := peer.clientKey
		if linuxHostTUNWrongKeyCase(scenario) {
			private = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
		}
		graph := fmt.Sprintf("[Interface]\nAddress=10.78.0.2/32,fd78:78::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=1280\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n", private, peer.serverPublic, peer.password, peer.address.String())
		if err := os.WriteFile(filepath.Join(directory, "wg.conf"), []byte(graph), 0600); err != nil {
			t.Fatal("installed WireGuard lost its exact paired private source", err)
		}
		return
	}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": profile.Endpoint, "server_port": int(peer.aesAddress.Port()),
			"method": "2022-blake3-aes-256-gcm", "password": password}}, "route": map[string]any{"final": "proxy"}})
	if err != nil || os.WriteFile(filepath.Join(directory, "sing-box.json"), graph, 0600) != nil {
		t.Fatal("actual installed host lost its private encrypted graph", err)
	}
}
