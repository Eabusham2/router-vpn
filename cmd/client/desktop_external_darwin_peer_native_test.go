//go:build darwin && routervpn_controller_privileged

package main

import (
	"bufio"
	"context"
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

type macOSExternalPeerReply struct {
	Latency        *macOSExternalLatencyReceipt `json:"latency,omitempty"`
	Schema         int                          `json:"schema"`
	Protocol       string                       `json:"protocol"`
	Address        string                       `json:"address"`
	CA             string                       `json:"ca"`
	Connections    int64                        `json:"connections"`
	Streams        int64                        `json:"streams"`
	PhysicalUDP    int64                        `json:"physical_udp"`
	Packets        int64                        `json:"packets"`
	DNSQueries     uint32                       `json:"dns_queries"`
	PublicAttempts uint32                       `json:"public_attempts"`
	PublicReplies  uint32                       `json:"public_replies"`
	AuthFailures   uint32                       `json:"auth_failures"`
}

type macOSExternalNativePeer struct {
	command                *exec.Cmd
	input                  io.WriteCloser
	output                 *os.File
	reader                 *bufio.Reader
	joined                 chan struct{}
	failure                error
	protocol, password, ca string
	address                netip.AddrPort
	physical               netip.Addr
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
	p.address, p.ca = address, reply.CA
	return reply
}
func (p *macOSExternalNativePeer) stats(t *testing.T) macOSExternalPeerReply {
	t.Helper()
	if _, err := io.WriteString(p.input, "stats\n"); err != nil {
		t.Fatal(err)
	}
	return p.read(t)
}

func macOSExternalNativePeerStart(t *testing.T, protocol string) *macOSExternalNativePeer {
	t.Helper()
	image := os.Getenv("ROUTERVPN_MACOS_EXTERNAL_PEER")
	expected := os.Getenv("ROUTERVPN_MACOS_EXTERNAL_PEER_SHA256")
	raw, err := os.ReadFile(image)
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(image) || hex.EncodeToString(sum[:]) != expected {
		t.Fatal("native fixture lost its captured independent peer image", err)
	}
	p := &macOSExternalNativePeer{protocol: protocol, physical: macOSExternalNativeAddress(t), joined: make(chan struct{})}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p.password = base64.StdEncoding.EncodeToString(key)
	clear(key)
	p.command = exec.Command(image, "-test.run=^TestRouterVPNDesktopDarwinExternalReferenceProcess$", "-test.count=1", "-test.timeout=300s")
	p.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_DARWIN_EXTERNAL_REFERENCE_CHILD=1", "ROUTERVPN_DARWIN_EXTERNAL_REFERENCE_ADDRESS=" + p.physical.String()}
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
	if err = json.NewEncoder(p.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	initial := p.read(t)
	if initial.Connections != 0 || initial.Streams != 0 || initial.PhysicalUDP != 0 || initial.Packets != 0 || initial.DNSQueries != 0 || initial.PublicAttempts != 0 || initial.PublicReplies != 0 || initial.AuthFailures != 0 {
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
	switch p.protocol {
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
	default:
		t.Fatal("native fixture refused another protocol")
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
