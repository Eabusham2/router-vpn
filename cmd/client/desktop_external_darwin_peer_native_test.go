//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
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
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

type macOSExternalLayerReceipt struct {
	Mode          string `json:"mode"`
	InnerAddress  string `json:"inner_address"`
	Raw           int64  `json:"raw"`
	Authenticated int64  `json:"authenticated"`
	Forwarded     int64  `json:"forwarded"`
	Rejected      int64  `json:"rejected"`
}

type macOSExternalPeerReply struct {
	ParametersSHA256     string                       `json:"parameters_sha256,omitempty"`
	SOCKSRelays          []string                     `json:"socks_relays,omitempty"`
	SOCKSRejectedReplies uint32                       `json:"socks_rejected_replies,omitempty"`
	Layer                *macOSExternalLayerReceipt   `json:"layer,omitempty"`
	Latency              *macOSExternalLatencyReceipt `json:"latency,omitempty"`
	Schema               int                          `json:"schema"`
	Protocol             string                       `json:"protocol"`
	Address              string                       `json:"address"`
	CA                   string                       `json:"ca"`
	Connections          int64                        `json:"connections"`
	Streams              int64                        `json:"streams"`
	PhysicalUDP          int64                        `json:"physical_udp"`
	Packets              int64                        `json:"packets"`
	DNSQueries           uint32                       `json:"dns_queries"`
	PublicAttempts       uint32                       `json:"public_attempts"`
	PublicReplies        uint32                       `json:"public_replies"`
	AuthFailures         uint32                       `json:"auth_failures"`
}

type macOSExternalNativePeer struct {
	command                                  *exec.Cmd
	input                                    io.WriteCloser
	output                                   *os.File
	reader                                   *bufio.Reader
	joined                                   chan struct{}
	failure                                  error
	protocol, password, ca                   string
	name, layer, layerPassword, fault        string
	variant, policy, clientKey, peerKey, psk string
	inner                                    netip.AddrPort
	address                                  netip.AddrPort
	physical                                 netip.Addr
}

func macOSExternalNativeCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "LANG=en_US.UTF-8"}
	command.Dir = "/"
	return command.CombinedOutput()
}

func macOSExternalNativeAddress(t *testing.T) netip.Addr {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := macOSExternalNativeCommand(ctx, "/sbin/route", "-n", "get", "default")
	if err != nil || len(raw) > 8192 {
		t.Fatal("native fixture lost its actual default route", err)
	}
	name := ""
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "interface:" {
			if name != "" {
				t.Fatal("ambiguous native default interface")
			}
			name = fields[1]
		}
	}
	device, err := net.InterfaceByName(name)
	if err != nil || device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
		t.Fatal("native fixture requires its up physical default interface", err)
	}
	addresses, err := device.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var selected netip.Addr
	for _, raw := range addresses {
		prefix, err := netip.ParsePrefix(raw.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
			if selected.IsValid() {
				t.Fatal("ambiguous native physical IPv4 address")
			}
			selected = prefix.Addr()
		}
	}
	if !selected.IsValid() {
		t.Fatal("native fixture lacks a physical IPv4 address")
	}
	return selected
}

func (p *macOSExternalNativePeer) read(t *testing.T) macOSExternalPeerReply {
	t.Helper()
	if err := p.output.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer p.output.SetReadDeadline(time.Time{})
	raw, err := p.reader.ReadSlice('\n')
	var reply macOSExternalPeerReply
	if err != nil || len(raw) > 16384 || decodeRelayControlJSON(raw, &reply) != nil || reply.Schema != 1 || reply.Protocol != p.protocol {
		t.Fatal("native peer lost its bounded original response", err)
	}
	address, err := netip.ParseAddrPort(reply.Address)
	pool := x509.NewCertPool()
	if err != nil || address.Addr() != p.physical || address.Port() == 0 || p.address.IsValid() && p.address != address || len(reply.CA) > 8192 || !pool.AppendCertsFromPEM([]byte(reply.CA)) || p.ca != "" && p.ca != reply.CA {
		t.Fatal("native peer changed its captured address or TLS identity", err)
	}
	if reply.Connections < 0 || reply.Streams < 0 || reply.PhysicalUDP < 0 || reply.Packets < 0 {
		t.Fatal("native peer returned invalid transport counters")
	}
	if p.protocol == "amneziawg" && reply.ParametersSHA256 != macOSExternalNativeAmneziaDigest(t, p.variant) {
		t.Fatal("native AWG peer changed its actual eleven-parameter readback", reply.ParametersSHA256)
	}
	if p.protocol != "amneziawg" && reply.ParametersSHA256 != "" {
		t.Fatal("ordinary peer acquired an unrequested AWG parameter identity")
	}
	p.address, p.ca = address, reply.CA
	if p.layer == "" {
		if reply.Layer != nil {
			t.Fatal("ordinary Darwin peer acquired an unrequested layer")
		}
	} else {
		if reply.Layer == nil || reply.Layer.Mode != p.layer {
			t.Fatal("Darwin peer lost its captured encrypted layer")
		}
		layer := reply.Layer
		inner, parseErr := netip.ParseAddrPort(layer.InnerAddress)
		if parseErr != nil || inner.Addr() != p.physical || inner.Port() == 0 || inner == address || p.inner.IsValid() && p.inner != inner ||
			p.layer == common.StartLayerAES256GCMXOR && address.Port() != 8389 ||
			layer.Raw < 0 || layer.Authenticated < 0 || layer.Forwarded < 0 || layer.Rejected < 0 || layer.Raw != reply.PhysicalUDP {
			t.Fatal("Darwin layer changed its captured outer/private tuples or transport counters", parseErr)
		}
		p.inner = inner
	}
	return reply
}
func (p *macOSExternalNativePeer) stats(t *testing.T) macOSExternalPeerReply {
	t.Helper()
	if _, err := io.WriteString(p.input, "stats\n"); err != nil {
		t.Fatal(err)
	}
	return p.read(t)
}

func macOSExternalNativePeerStart(t *testing.T, scenario string) *macOSExternalNativePeer {
	t.Helper()
	image := os.Getenv("ROUTERVPN_MACOS_EXTERNAL_PEER")
	expected := os.Getenv("ROUTERVPN_MACOS_EXTERNAL_PEER_SHA256")
	raw, err := os.ReadFile(image)
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(image) || hex.EncodeToString(sum[:]) != expected {
		t.Fatal("native fixture lost its captured independent peer image", err)
	}
	protocol, layer, fault := macOSExternalNativeScenario(t, scenario)
	p := &macOSExternalNativePeer{policy: "on-connect", name: scenario, protocol: protocol, layer: layer, fault: fault, physical: macOSExternalNativeAddress(t), joined: make(chan struct{})}
	if scenario == "wireguard-always" || scenario == "socks5-always" || strings.HasPrefix(scenario, "amneziawg-") && strings.HasSuffix(scenario, "-always") {
		p.policy = "always"
	}
	if protocol == "amneziawg" {
		if strings.HasPrefix(scenario, "amneziawg-fast") {
			p.variant = "fast"
		} else {
			p.variant = "strong"
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p.password = base64.StdEncoding.EncodeToString(key)
	if layer != "" {
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		p.layerPassword = base64.StdEncoding.EncodeToString(key)
	}
	clear(key)
	p.command = exec.Command(image, "-test.run=^TestRouterVPNDesktopDarwinExternalReferenceProcess$", "-test.count=1", "-test.timeout=300s")
	p.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_DARWIN_EXTERNAL_REFERENCE_CHILD=1", "ROUTERVPN_DARWIN_EXTERNAL_REFERENCE_ADDRESS=" + p.physical.String()}
	if layer != "" {
		p.command.Env = append(p.command.Env, "ROUTERVPN_DARWIN_EXTERNAL_LAYER=1")
	}
	p.command.Stderr = os.Stderr
	p.input, err = p.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var writer *os.File
	p.output, writer, err = os.Pipe()
	if err != nil {
		p.input.Close()
		t.Fatal(err)
	}
	p.reader = bufio.NewReaderSize(p.output, 16385)
	p.command.Stdout = writer
	if err = p.command.Start(); err != nil {
		p.input.Close()
		p.output.Close()
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	go func() { p.failure = p.command.Wait(); close(p.joined) }()
	t.Cleanup(func() {
		p.input.Close()
		select {
		case <-p.joined:
			if p.failure != nil {
				t.Error("actual external peer failed joined cleanup", p.failure)
			}
		case <-time.After(10 * time.Second):
			t.Error("actual external peer did not join its original control pipe")
			_ = p.command.Process.Kill()
			<-p.joined
		}
		p.output.Close()
	})
	request := map[string]any{"schema": 1, "protocol": protocol, "address": p.physical.String(), "password": p.password, "hold": false}
	if protocol == "socks5" && (fault == "auth-downgrade" || fault == "relay-domain" || fault == "control-eof") {
		request["socks_fault"] = fault
	}
	if protocol == "wireguard" || protocol == "amneziawg" {
		provider, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.clientKey = base64.StdEncoding.EncodeToString(consumer.Bytes())
		p.peerKey = base64.StdEncoding.EncodeToString(provider.PublicKey().Bytes())
		p.psk, p.password = p.password, ""
		request["password"] = ""
		keys := map[string]any{"private_key": base64.StdEncoding.EncodeToString(provider.Bytes()), "client_public_key": base64.StdEncoding.EncodeToString(consumer.PublicKey().Bytes()), "preshared_key": p.psk}
		if protocol == "amneziawg" {
			keys["parameters"] = macOSExternalNativeAmneziaParameters(t, p.variant)
			request["amneziawg"] = keys
		} else {
			request["wireguard"] = keys
		}
	}
	if layer != "" {
		layerRequest := map[string]any{"mode": layer, "password": p.layerPassword}
		if fault == "wrong-whitening" {
			layerRequest["fault"] = "whitening"
		}
		request["layer"] = layerRequest
	}
	if err = json.NewEncoder(p.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	initial := p.read(t)
	if initial.Connections != 0 || initial.Streams != 0 || initial.PhysicalUDP != 0 || initial.Packets != 0 || initial.DNSQueries != 0 || initial.PublicAttempts != 0 || initial.PublicReplies != 0 || initial.AuthFailures != 0 || initial.Layer != nil && (initial.Layer.Raw != 0 || initial.Layer.Authenticated != 0 || initial.Layer.Forwarded != 0 || initial.Layer.Rejected != 0) {
		t.Fatal("native peer claimed traffic before its captured runtime")
	}
	return p
}

func macOSExternalNativeInstallProfile(t *testing.T, p *macOSExternalNativePeer) {
	t.Helper()
	profile := common.RouterProfile{ID: "installed-macos-external", Name: "Native independent external peer", NodeKind: "external", Endpoint: p.physical.String(),
		DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "off", StartLayer: common.StartLayerOff,
		MTUPolicy: "manual", ManualMTU: 1376, EffectiveMTU: 9000, KillSwitch: true, KillSwitchPolicy: "on-connect", MultihopExecution: "auto",
		External: &common.ExternalNodeConfig{Protocol: p.protocol, ExpectedPublicIP: "203.0.113.88"}}
	connect := &common.ExternalHTTPConnectConfig{Host: p.physical.String(), Port: int(p.address.Port()), Username: "captured-native-user", Password: p.password}
	profile.KillSwitchPolicy = p.policy
	if p.policy == "always" {
		profile.IPv6Mode = "on"
		profile.HomeLANAccess = true
	}
	if p.name == "wireguard-auto" {
		profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU = "auto", 0, 0
	}
	switch p.protocol {
	case "socks5":
		profile.DNSProtocol = "udp"
		profile.External.SOCKS5 = &common.ExternalSOCKS5Config{Host: p.physical.String(), Port: int(p.address.Port()), Username: "captured-native-user", Password: p.password}
		if p.fault == "wrong-password" {
			profile.External.SOCKS5.Password += "-different"
		}
		if p.fault == "wrong-exit" {
			profile.External.ExpectedPublicIP = "203.0.113.89"
		}
	case "wireguard", "amneziawg":
		profile.DNSProtocol = "udp"
		profile.External.WireGuard = &common.ExternalWireGuardConfig{PrivateKey: p.clientKey, PeerPublicKey: p.peerKey, PresharedKey: p.psk, Endpoint: p.address.String(), Addresses: []string{"10.78.0.2/32", "fd78:78::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1420, PersistentKeepalive: 25}
		switch p.fault {
		case "wrong-client-key":
			other, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			profile.External.WireGuard.PrivateKey = base64.StdEncoding.EncodeToString(other.Bytes())
		case "wrong-psk":
			var other [32]byte
			if _, err := rand.Read(other[:]); err != nil {
				t.Fatal(err)
			}
			profile.External.WireGuard.PresharedKey = base64.StdEncoding.EncodeToString(other[:])
			clear(other[:])
		case "wrong-exit":
			profile.External.ExpectedPublicIP = "203.0.113.89"
		}
		if p.protocol == "amneziawg" {
			parameters := macOSExternalNativeAmneziaParameters(t, p.variant)
			if p.fault == "wrong-parameters" {
				parameters["h1"] = "50000000-59999999"
			}
			profile.External.AmneziaWG = &common.ExternalAmneziaWGConfig{ExternalWireGuardConfig: *profile.External.WireGuard, Parameters: parameters}
			profile.External.WireGuard = nil
		}
	case "shadowsocks":
		profile.External.Shadowsocks = &common.ExternalShadowsocksConfig{Server: p.physical.String(), Port: int(p.address.Port()), Method: "2022-blake3-aes-256-gcm", Password: p.password}
	case "http-connect":
		profile.External.HTTPConnect = connect
	case "https-connect":
		connect.TLSServerName = "captured-external.example"
		profile.External.HTTPSConnect = connect
	case "hysteria2":
		profile.DNSProtocol = "udp"
		profile.External.Hysteria2 = &common.ExternalHysteria2Config{Server: p.physical.String(), Port: int(p.address.Port()), Password: p.password, TLSServerName: "captured-external.example"}
		if p.layer != "" {
			profile.StartLayer = p.layer
			profile.External.Hysteria2.Port = int(p.inner.Port())
			password := p.layerPassword
			if p.fault == "wrong-layer-key" {
				var other [32]byte
				if _, err := rand.Read(other[:]); err != nil {
					t.Fatal(err)
				}
				password = base64.StdEncoding.EncodeToString(other[:])
				clear(other[:])
			}
			profile.External.StartLayer = &common.ExternalStartLayer{Mode: p.layer, API: "http://10.93.0.1:8787", Transport: map[string]any{
				"type": "shadowsocks", "tag": "captured-private-layer", "server": p.physical.String(), "server_port": int(p.address.Port()),
				"method": "2022-blake3-aes-256-gcm", "password": password}}
			if p.fault == "wrong-inner-key" {
				profile.External.Hysteria2.Password += "-different-captured-inner"
			}
		}
	default:
		t.Fatal("native fixture refused another protocol")
	}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal("Darwin fixture profile rejected before native execution", err)
	}
	store := common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("ROUTERVPN_MACOS_FIXTURE_SOURCE")
	raw, err = os.ReadFile(filepath.Join(source, "configs/client/modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "modes.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, macOSExternalNativeMarker), []byte("explicit disposable macOS external PF and TUN fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func macOSExternalNativeBundle(t *testing.T) {
	t.Helper()
	source := os.Getenv("ROUTERVPN_MACOS_EXTERNAL_BUNDLE")
	raw, err := os.ReadFile(filepath.Join(source, "NATIVE-RUNTIME.json"))
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(source) || hex.EncodeToString(sum[:]) != os.Getenv("ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256") {
		t.Fatal("native fixture lost its sealed complete bundle", err)
	}
	directory := filepath.Join(macOSOwnedControllerRoot, "runtime/native")
	if err = os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(source, name)
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() {
			t.Fatal("native bundle contains an unowned filesystem object", name, err)
		}
		body, err := os.ReadFile(path)
		after, afterErr := os.Lstat(path)
		if err != nil || afterErr != nil || !os.SameFile(before, after) || before.Size() != int64(len(body)) || before.ModTime() != after.ModTime() {
			t.Fatal("native bundle changed during fixture copy", name, err, afterErr)
		}
		mode := os.FileMode(0644)
		if before.Mode().Perm()&0111 != 0 {
			mode = 0755
		}
		if err = os.WriteFile(filepath.Join(directory, name), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = verifyBundledNativeContext(ctx, macOSOwnedControllerRoot); err != nil {
		t.Fatal("actual installed complete bundle verifier rejected its sealed native engine", err)
	}
}

// The public proof has a fixed HTTPS destination. Trust the independent peer's
// freshly generated CA through the real native system verifier on this explicit
// disposable runner, then remove only that fingerprint after all clients join.
func macOSExternalNativeTrust(t *testing.T, p *macOSExternalNativePeer) {
	t.Helper()
	block, rest := pem.Decode([]byte(p.ca))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("invalid native peer root")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		t.Fatal("native peer has no complete root certificate", err)
	}
	digest := sha256.Sum256(block.Bytes)
	fingerprint := strings.ToUpper(hex.EncodeToString(digest[:]))
	// Apple SecurityTool security.c documents -Z as SHA-256 (or SHA-1).
	// Select only the freshly generated certificate SHA-256, never its name.
	file := filepath.Join(macOSOwnedControllerRoot, "fixture-external-root.pem")
	if err = os.WriteFile(file, []byte(p.ca), 0600); err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return macOSExternalNativeCommand(ctx, "/usr/bin/security", args...)
	}
	before, err := command("find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	if err != nil || len(before) > 1<<20 || strings.Contains(string(before), fingerprint) {
		t.Fatal("native fixture could not capture unchanged system certificates", err)
	}
	trustSnapshot := func() ([]byte, int, error) {
		body, failure := command("dump-trust-settings", "-d")
		code := 0
		if failure != nil {
			var exit *exec.ExitError
			if !errors.As(failure, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(body), "No Trust Settings were found") {
				return nil, 0, failure
			}
			code = 1
		}
		if len(body) > 1<<20 {
			return nil, 0, errors.New("native trust inventory exceeded its bound")
		}
		return body, code, nil
	}
	beforeTrust, beforeTrustCode, err := trustSnapshot()
	if err != nil {
		t.Fatal("native fixture could not capture original administrator trust", err)
	}
	installed := false
	t.Cleanup(func() {
		if !installed {
			return
		}
		lock, err := ownedDesktopLock(macOSOwnedProcessLock, true)
		if err != nil {
			t.Error("native trust remains captured while its runtime/controller is unjoined", err)
			return
		}
		defer lock.Close()
		captured, err := os.ReadFile(file)
		if err != nil || string(captured) != p.ca {
			t.Error("native fixture retained trust after its captured certificate file changed", err)
			return
		}
		// A failed add may have installed only part of its native state. Attempt
		// removal of this certificate only, then require both complete original
		// observations. Failed commands cannot substitute for those readbacks.
		_, _ = command("remove-trusted-cert", "-d", file)
		current, err := command("find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
		if err != nil {
			t.Error("native certificate cleanup has no current inventory", err)
			return
		}
		if strings.Contains(string(current), fingerprint) {
			_, _ = command("delete-certificate", "-Z", fingerprint, "/Library/Keychains/System.keychain")
		}
		after, certErr := command("find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
		afterTrust, afterTrustCode, trustErr := trustSnapshot()
		if certErr != nil || trustErr != nil || !reflect.DeepEqual(before, after) || beforeTrustCode != afterTrustCode || !reflect.DeepEqual(beforeTrust, afterTrust) {
			t.Error("native fixture certificate/trust inventories did not return to their captured state", certErr, trustErr)
		}
	})
	// Register cleanup before entering the mutating native command: even a
	// failed command may have added the certificate before reporting failure.
	installed = true
	if out, err := command("add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", file); err != nil {
		t.Fatal("native peer root was not accepted by the actual system trust service", err, string(out))
	}
	after, err := command("find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
	if err != nil || !strings.Contains(string(after), fingerprint) {
		t.Fatal("native system keychain did not retain the exact peer root", err)
	}
}

func macOSExternalNativeScenario(t *testing.T, scenario string) (protocol, layer, fault string) {
	t.Helper()
	if strings.HasPrefix(scenario, "amneziawg-") {
		for _, variant := range []string{"fast", "strong"} {
			base := "amneziawg-" + variant
			if scenario == base || scenario == base+"-always" {
				return "amneziawg", "", ""
			}
			for _, fault := range []string{"wrong-client-key", "wrong-psk", "wrong-parameters", "wrong-dns", "wrong-trust", "wrong-exit"} {
				if scenario == base+"-"+fault {
					return "amneziawg", "", fault
				}
			}
		}
		t.Fatal("native AWG scenario changed its complete captured variant")
	}
	switch scenario {
	case "socks5", "socks5-always":
		return "socks5", "", ""
	case "socks5-wrong-password", "socks5-auth-downgrade", "socks5-relay-domain", "socks5-control-eof", "socks5-wrong-dns", "socks5-wrong-trust", "socks5-wrong-exit":
		return "socks5", "", strings.TrimPrefix(scenario, "socks5-")
	case "wireguard", "wireguard-always", "wireguard-auto":
		return "wireguard", "", ""
	case "wireguard-wrong-client-key", "wireguard-wrong-psk", "wireguard-wrong-dns", "wireguard-wrong-trust", "wireguard-wrong-exit":
		return "wireguard", "", strings.TrimPrefix(scenario, "wireguard-")
	case "shadowsocks", "http-connect", "https-connect", "hysteria2":
		return scenario, "", ""
	}
	for _, entry := range []struct{ name, mode string }{{"hysteria2-aes", common.StartLayerAES256GCM}, {"hysteria2-aes-xor", common.StartLayerAES256GCMXOR}} {
		if scenario == entry.name {
			return "hysteria2", entry.mode, ""
		}
		for _, negative := range []string{"wrong-layer-key", "wrong-inner-key", "wrong-whitening"} {
			if scenario == entry.name+"-"+negative && (negative != "wrong-whitening" || entry.mode == common.StartLayerAES256GCMXOR) {
				return "hysteria2", entry.mode, negative
			}
		}
	}
	t.Fatal("unregistered Darwin installed scenario", scenario)
	return
}
