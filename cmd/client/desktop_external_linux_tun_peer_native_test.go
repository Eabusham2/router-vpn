//go:build linux && routervpn_controller_privileged

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
	"io"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/nativeopenvpn"
)

var linuxHostTUNExternalCases = []string{
	"external-ss-on-connect", "external-http-on-connect", "external-https-on-connect",
	"external-ss-always", "external-http-always", "external-https-always",
	"external-ss-cancelled", "external-ss-replacement", "external-ss-source", "external-ss-dns-failure",
	"external-ss-public",
	"external-hy2-on-connect", "external-hy2-always", "external-hy2-public", "external-hy2-cancelled",
	"external-hy2-wrong-key", "external-hy2-wrong-trust", "external-hy2-dns-failure",
	"external-wg-on-connect", "external-wg-always", "external-wg-public", "external-wg-cancelled",
	"external-wg-wrong-key", "external-wg-wrong-psk", "external-wg-dns-failure", "external-wg-replacement",
	"external-awgfast-on-connect", "external-awgfast-always", "external-awgfast-public", "external-awgfast-cancelled",
	"external-awgfast-wrong-key", "external-awgfast-wrong-psk", "external-awgfast-dns-failure", "external-awgfast-replacement", "external-awgfast-wrong-parameters",
	"external-awgstrong-on-connect", "external-awgstrong-always", "external-awgstrong-public", "external-awgstrong-cancelled",
	"external-awgstrong-wrong-key", "external-awgstrong-wrong-psk", "external-awgstrong-dns-failure", "external-awgstrong-replacement", "external-awgstrong-wrong-parameters",
	"external-ovpntcp-on-connect",
	"external-ovpntcp-always",
	"external-ovpntcp-public",
	"external-ovpntcp-cancelled",
	"external-ovpntcp-wrong-trust",
	"external-ovpntcp-wrong-control",
	"external-ovpntcp-dns-failure",
	"external-ovpntcp-replacement",
	"external-ovpntcp-fallback",
	"external-ovpnudp-on-connect",
	"external-ovpnudp-always",
	"external-ovpnudp-public",
	"external-ovpnudp-cancelled",
	"external-ovpnudp-wrong-trust",
	"external-ovpnudp-wrong-control",
	"external-ovpnudp-dns-failure",
	"external-ovpnudp-replacement",
	"external-ovpnudp-fallback",
}

func linuxHostTUNExternalCase(scenario string) bool {
	for _, candidate := range linuxHostTUNExternalCases {
		if scenario == candidate {
			return true
		}
	}
	return false
}

func linuxHostTUNExternalProtocol(scenario string) string {
	if !linuxHostTUNExternalCase(scenario) {
		return ""
	}
	if strings.HasPrefix(scenario, "external-https-") {
		return "https-connect"
	}
	if strings.HasPrefix(scenario, "external-http-") {
		return "http-connect"
	}
	if strings.HasPrefix(scenario, "external-hy2-") {
		return "hysteria2"
	}
	if strings.HasPrefix(scenario, "external-wg-") {
		return "wireguard"
	}
	if strings.HasPrefix(scenario, "external-awgfast-") || strings.HasPrefix(scenario, "external-awgstrong-") {
		return "amneziawg"
	}
	if strings.HasPrefix(scenario, "external-ovpntcp-") || strings.HasPrefix(scenario, "external-ovpnudp-") {
		return "openvpn"
	}
	return "shadowsocks"
}

// Representative imported test configurations, not replacement product
// defaults. Both retain all eleven parameters and distinct S4 padding.
func linuxHostTUNExternalAWGParameters(scenario string) map[string]string {
	if linuxHostTUNExternalProtocol(scenario) != "amneziawg" {
		return nil
	}
	parameters := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32",
		"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	if strings.HasPrefix(scenario, "external-awgfast-") {
		parameters["jc"], parameters["jmin"], parameters["jmax"], parameters["s4"] = "0", "20", "40", "8"
	}
	return parameters
}

func linuxHostTUNExternalAction(scenario string) string {
	if !linuxHostTUNExternalCase(scenario) {
		return ""
	}
	_, action, _ := strings.Cut(strings.TrimPrefix(scenario, "external-"), "-")
	return action
}

func linuxHostTUNExternalFailedProof(scenario string) bool {
	switch linuxHostTUNExternalAction(scenario) {
	case "dns-failure", "wrong-key", "wrong-trust", "wrong-psk", "wrong-parameters", "wrong-control":
		return true
	}
	return false
}

type linuxExternalTUNPeerReply struct {
	Schema           int    `json:"schema"`
	Protocol         string `json:"protocol"`
	Address          string `json:"address"`
	CA               string `json:"ca"`
	Connections      int64  `json:"connections"`
	Streams          int64  `json:"streams"`
	PhysicalUDP      int64  `json:"physical_udp"`
	Packets          int64  `json:"packets"`
	DNSQueries       uint32 `json:"dns_queries"`
	PublicAttempts   uint32 `json:"public_attempts"`
	PublicReplies    uint32 `json:"public_replies"`
	AuthFailures     uint32 `json:"auth_failures"`
	ParametersSHA256 string `json:"parameters_sha256,omitempty"`
	OpenVPNNetwork   string `json:"openvpn_network,omitempty"`
	OpenVPNProfile   string `json:"openvpn_profile,omitempty"`
}

type linuxExternalTUNPeer struct {
	command                        *exec.Cmd
	input                          io.WriteCloser
	output                         *os.File
	reader                         *bufio.Reader
	diagnostic                     linuxHostTUNOutput
	done                           chan struct{}
	waitErr                        error
	protocol                       string
	password                       string
	address                        netip.AddrPort
	ca                             string
	wireguard                      *common.ExternalWireGuardConfig
	parameters                     map[string]string
	serverPrivate, clientPublic    string
	openvpnNetwork, openvpnProfile string
	openvpnFallback                bool
}

func (peer *linuxExternalTUNPeer) read(t *testing.T) linuxExternalTUNPeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer peer.output.SetReadDeadline(time.Time{})
	raw, err := peer.reader.ReadSlice('\n')
	var reply linuxExternalTUNPeerReply
	if err != nil || len(raw) > 16<<10 || decodeRelayControlJSON(raw, &reply) != nil || reply.Schema != 1 || reply.Protocol != peer.protocol {
		t.Fatal("installed external peer lost its exact bounded reply", err, peer.diagnostic.String())
	}
	address, err := netip.ParseAddrPort(reply.Address)
	pool := x509.NewCertPool()
	if err != nil || address.Addr().String() != "11.77.0.2" || address.Port() == 0 || peer.address.IsValid() && peer.address != address ||
		len(reply.CA) > 8192 || !pool.AppendCertsFromPEM([]byte(reply.CA)) || peer.ca != "" && reply.CA != peer.ca || reply.Connections < 0 || reply.Streams < 0 {
		t.Fatal("installed external peer changed its endpoint or original private test root")
	}
	peer.address, peer.ca = address, reply.CA
	if peer.protocol == "amneziawg" {
		parameters, err := awgpolicy.ParametersUAPI(peer.parameters)
		digest := sha256.Sum256([]byte(parameters))
		if err != nil || len(peer.parameters) != 11 || reply.ParametersSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("installed external AWG peer lost its actual complete native parameter readback")
		}
	} else if reply.ParametersSHA256 != "" {
		t.Fatal("ordinary external peer acquired an unrequested AWG parameter owner")
	}
	if peer.protocol == "openvpn" {
		if len(reply.OpenVPNProfile) == 0 || len(reply.OpenVPNProfile) > 12<<10 || reply.OpenVPNNetwork != peer.openvpnNetwork ||
			peer.openvpnProfile != "" && peer.openvpnProfile != reply.OpenVPNProfile {
			t.Fatal("installed provider lost its complete original private import")
		}
		compiled, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: reply.OpenVPNProfile}, "exit", "")
		if err != nil {
			t.Fatal("installed provider import failed its actual compiler", err)
		}
		remotes, err := nativeopenvpn.Remotes(compiled)
		want := 1
		if peer.openvpnFallback {
			want = 2
		}
		if err != nil || len(remotes) != want || remotes[len(remotes)-1] != (nativeopenvpn.Remote{Host: address.Addr().String(), Port: int(address.Port()), Network: peer.openvpnNetwork}) {
			t.Fatal("installed provider changed its original ordered transport list", err)
		}
		if want == 2 && (remotes[0].Network != "tcp" || remotes[0].Host != address.Addr().String() || remotes[0].Port == int(address.Port())) {
			t.Fatal("installed provider lost its distinct original TCP fallback")
		}
		peer.openvpnProfile = reply.OpenVPNProfile
	} else if reply.OpenVPNNetwork != "" || reply.OpenVPNProfile != "" {
		t.Fatal("ordinary external peer acquired an unrequested provider import")
	}
	return reply
}

func (peer *linuxExternalTUNPeer) observe(t *testing.T, action string) linuxExternalTUNPeerReply {
	t.Helper()
	if action != "stats" && action != "fail-dns" && action != "release-proof" {
		t.Fatal("unowned installed external peer action")
	}
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

func linuxHostTUNExternalWGKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func linuxHostTUNStartExternalPeer(t *testing.T, scenario string) *linuxExternalTUNPeer {
	t.Helper()
	// The parent has proved a separate network namespace and provisioned TUN.
	// Use a public-unicast alias only on its disconnected peer veth: the real
	// guardian deliberately rejects TEST-NET/benchmark destinations, and no
	// fixture override may turn those reserved ranges into admitted sockets.
	device, inode, present := strings.Cut(os.Getenv("ROUTERVPN_NODE_OUTER_NETNS_ID"), ":")
	outerDevice, deviceErr := strconv.ParseUint(device, 10, 64)
	outerInode, inodeErr := strconv.ParseUint(inode, 10, 64)
	var current syscall.Stat_t
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 ||
		!present || deviceErr != nil || inodeErr != nil || outerInode == 0 || syscall.Stat("/proc/self/ns/net", &current) != nil ||
		current.Dev == outerDevice && current.Ino == outerInode {
		t.Fatal("installed external peer requires the original isolated controller namespace")
	}
	linuxHostTUNCommand(t, "ip", "netns", "exec", "rvpn-peer", "ip", "addr", "add", "11.77.0.2/32", "dev", "rvpn-peer")
	t.Cleanup(func() {
		linuxHostTUNCommand(t, "ip", "netns", "exec", "rvpn-peer", "ip", "addr", "del", "11.77.0.2/32", "dev", "rvpn-peer")
	})
	directory, err := os.MkdirTemp("/opt", "routervpn-external-peer-")
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
	peer := &linuxExternalTUNPeer{protocol: linuxHostTUNExternalProtocol(scenario), password: base64.StdEncoding.EncodeToString(key[:]), done: make(chan struct{})}
	clear(key[:])
	if peer.protocol == "wireguard" || peer.protocol == "amneziawg" {
		clientPrivate, clientPublic := linuxHostTUNExternalWGKey(t)
		serverPrivate, serverPublic := linuxHostTUNExternalWGKey(t)
		peer.serverPrivate, peer.clientPublic = serverPrivate, clientPublic
		peer.wireguard = &common.ExternalWireGuardConfig{PrivateKey: clientPrivate, PeerPublicKey: serverPublic, PresharedKey: peer.password,
			Addresses: []string{"10.78.0.2/32", "fd78:78::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1280, PersistentKeepalive: 25}
		peer.password = ""
		peer.parameters = linuxHostTUNExternalAWGParameters(scenario)
	}
	if peer.protocol == "openvpn" {
		peer.password = ""
		peer.openvpnNetwork = "tcp"
		if strings.HasPrefix(scenario, "external-ovpnudp-") {
			peer.openvpnNetwork = "udp"
		}
		peer.openvpnFallback = linuxHostTUNExternalAction(scenario) == "fallback"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	t.Cleanup(cancel)
	peer.command = exec.CommandContext(ctx, "ip", "netns", "exec", "rvpn-peer", image,
		"-test.run=^TestRouterVPNDesktopExternalInstalledReferenceProcess$", "-test.count=1", "-test.timeout=105s")
	peer.command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_EXTERNAL_INSTALLED_REFERENCE_CHILD=1"}
	peer.input, err = peer.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var writer *os.File
	peer.output, writer, err = os.Pipe()
	if err != nil {
		_ = peer.input.Close()
		t.Fatal(err)
	}
	peer.reader = bufio.NewReaderSize(peer.output, (16<<10)+1)
	peer.command.Stdout, peer.command.Stderr = writer, &peer.diagnostic
	if err := peer.command.Start(); err != nil {
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
				t.Error("installed external reference failed", peer.waitErr, peer.diagnostic.String())
			}
		case <-time.After(5 * time.Second):
			cancel()
			<-peer.done
			t.Error("installed external reference failed to join its owned pipe", peer.diagnostic.String())
		}
		cancel()
		_ = peer.output.Close()
	})
	request := map[string]any{"schema": 1, "protocol": peer.protocol, "address": "11.77.0.2",
		"password": peer.password, "hold": linuxHostTUNExternalAction(scenario) == "cancelled"}
	if peer.wireguard != nil {
		keys := map[string]any{"private_key": peer.serverPrivate, "client_public_key": peer.clientPublic, "preshared_key": peer.wireguard.PresharedKey}
		if peer.protocol == "amneziawg" {
			keys["parameters"] = maps.Clone(peer.parameters)
			request["amneziawg"] = keys
		} else {
			request["wireguard"] = keys
		}
	}
	if peer.protocol == "openvpn" {
		request["openvpn_network"], request["openvpn_fallback"] = peer.openvpnNetwork, peer.openvpnFallback
	}
	if err := json.NewEncoder(peer.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	initial := peer.read(t)
	if initial.Connections != 0 || initial.Streams != 0 || initial.PhysicalUDP != 0 || initial.Packets != 0 || initial.DNSQueries != 0 || initial.PublicAttempts != 0 || initial.PublicReplies != 0 || initial.AuthFailures != 0 {
		t.Fatal("external reference reported traffic before its selected native child")
	}
	return peer
}

// The existing runner has already unshared mount, user, PID and network
// namespaces and made /etc private. Bind only this ephemeral public CA over
// the existing certificate file; the shipping TLS verifier remains intact.
func linuxHostTUNExternalTrust(t *testing.T, peer *linuxExternalTUNPeer) {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 {
		t.Fatal("private test trust requires the original isolated installed namespace")
	}
	const target = "/etc/ssl/certs/ca-certificates.crt"
	var original syscall.Stat_t
	if syscall.Lstat(target, &original) != nil || original.Mode&syscall.S_IFMT != syscall.S_IFREG || original.Uid != 0 {
		t.Fatal("private test trust requires the existing regular system root file")
	}
	directory, err := os.MkdirTemp("/opt", "routervpn-external-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	source := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(source, []byte(peer.ca), 0644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("private test root bind", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(target, 0); err != nil {
			t.Error("private test root unmount", err)
		}
	})
	if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		t.Fatal("private test root read-only binding", err)
	}
}

func linuxHostTUNInstallExternalProfile(t *testing.T, peer *linuxExternalTUNPeer, scenario string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"))
	var profiles common.RouterProfileStore
	if err != nil || decodeRelayControlJSON(raw, &profiles) != nil || len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "installed-linux-node" {
		t.Fatal("external fixture lost its original private Router profile", err)
	}
	kill := "on-connect"
	if strings.HasSuffix(scenario, "-always") {
		kill = "always"
	}
	profiles.Profiles[0].KillSwitchPolicy = kill
	profile := common.RouterProfile{ID: "installed-linux-external", Name: "Independent installed external peer", NodeKind: "external",
		Endpoint: "11.77.0.2", DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353,
		IPv6Mode: "off", StartLayer: common.StartLayerOff, MTUPolicy: "manual", ManualMTU: 1376, EffectiveMTU: 9000,
		KillSwitch: true, KillSwitchPolicy: kill, MultihopExecution: "local",
		External: &common.ExternalNodeConfig{Protocol: peer.protocol, ExpectedPublicIP: "203.0.113.88"}}
	if linuxHostTUNExternalAction(scenario) == "public" {
		// Explicit Direct/Local Connect must persist its exact new execution
		// revision without giving unrelated saved-policy changes authority.
		profile.MultihopExecution = "auto"
	}
	connect := &common.ExternalHTTPConnectConfig{Host: "11.77.0.2", Port: int(peer.address.Port()), Username: "captured-native-user", Password: peer.password}
	switch peer.protocol {
	case "shadowsocks":
		profile.External.Shadowsocks = &common.ExternalShadowsocksConfig{Server: "11.77.0.2", Port: int(peer.address.Port()), Method: "2022-blake3-aes-256-gcm", Password: peer.password}
	case "http-connect":
		profile.External.HTTPConnect = connect
	case "https-connect":
		connect.TLSServerName = "captured-external.example"
		profile.External.HTTPSConnect = connect
	case "wireguard", "amneziawg":
		profile.DNSProtocol = "udp"
		config := *peer.wireguard
		config.Addresses = append([]string(nil), peer.wireguard.Addresses...)
		config.AllowedIPs = append([]string(nil), peer.wireguard.AllowedIPs...)
		config.Endpoint = peer.address.String()
		if linuxHostTUNExternalAction(scenario) == "wrong-key" {
			_, config.PeerPublicKey = linuxHostTUNExternalWGKey(t)
		}
		if linuxHostTUNExternalAction(scenario) == "wrong-psk" {
			config.PresharedKey, _ = linuxHostTUNExternalWGKey(t)
		}
		if peer.protocol == "amneziawg" {
			parameters := maps.Clone(peer.parameters)
			if linuxHostTUNExternalAction(scenario) == "wrong-parameters" {
				parameters["h1"] = "50000000-59999999"
			}
			profile.External.AmneziaWG = &common.ExternalAmneziaWGConfig{ExternalWireGuardConfig: config, Parameters: parameters}
		} else {
			profile.External.WireGuard = &config
		}
	case "openvpn":
		profile.DNSProtocol = "udp"
		config := peer.openvpnProfile
		if linuxHostTUNExternalAction(scenario) == "wrong-control" {
			config = strings.ReplaceAll(config, strings.Repeat("a", 32), strings.Repeat("b", 32))
		}
		if linuxHostTUNExternalAction(scenario) == "wrong-trust" {
			before, rest, ok := strings.Cut(config, "<ca>\n")
			_, after, closed := strings.Cut(rest, "</ca>\n")
			if !ok || !closed {
				t.Fatal("installed provider lost original inline CA")
			}
			config = before + "<ca>\n" + peer.ca + "</ca>\n" + after
		}
		profile.External.OpenVPN = &common.ExternalOpenVPNConfig{Config: config}
	case "hysteria2":
		profile.DNSProtocol = "udp"
		profile.External.Hysteria2 = &common.ExternalHysteria2Config{Server: "11.77.0.2", Port: int(peer.address.Port()), Password: peer.password, TLSServerName: "captured-external.example"}
		if linuxHostTUNExternalAction(scenario) == "wrong-key" {
			profile.External.Hysteria2.Password += "-different-peer-credential"
		}
		if linuxHostTUNExternalAction(scenario) == "wrong-trust" {
			profile.External.Hysteria2.TLSServerName = "different-captured-external.example"
		}
	default:
		t.Fatal("external fixture lost its exact protocol")
	}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal("external fixture rejected by actual saved profile validation", err)
	}
	profiles.Profiles = append(profiles.Profiles, profile)
	raw, err = json.Marshal(profiles)
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), raw, 0600) != nil {
		t.Fatal("external fixture failed to preserve both private profiles", err)
	}
	catalog, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "modes.json"), catalog, 0600) != nil {
		t.Fatal("external fixture lost the shipping public Connect catalog", err)
	}
}

type linuxExternalTUNResult struct {
	Stage             string                            `json:"stage"`
	Scenario          string                            `json:"scenario"`
	OriginalSession   string                            `json:"original_session"`
	ExternalSession   string                            `json:"external_session,omitempty"`
	FinalSession      string                            `json:"final_session,omitempty"`
	Protocol          string                            `json:"protocol"`
	MTU               int                               `json:"mtu"`
	Proof             *desktopExternalProof             `json:"proof,omitempty"`
	Restore           *linuxHostTUNRestoreResult        `json:"restore,omitempty"`
	SourcePreserved   bool                              `json:"source_preserved,omitempty"`
	ReplacementKept   bool                              `json:"replacement_kept,omitempty"`
	PublicPersisted   bool                              `json:"public_persisted,omitempty"`
	FailedProof       bool                              `json:"failed_proof,omitempty"`
	Journal           *linuxprotection.JournalSelection `json:"journal,omitempty"`
	ClosedTableSHA256 string                            `json:"closed_table_sha256,omitempty"`
}

func linuxHostTUNReadExternal(t *testing.T, process *linuxHostTUNController, scenario, stage string) linuxExternalTUNResult {
	t.Helper()
	if err := process.output.SetReadDeadline(time.Now().Add(70 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer process.output.SetReadDeadline(time.Time{})
	raw, err := process.reader.ReadSlice('\n')
	var result linuxExternalTUNResult
	if err != nil || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &result) != nil || result.Scenario != scenario || result.Stage != stage ||
		result.Protocol != linuxHostTUNExternalProtocol(scenario) || !desktopMTURequestPattern.MatchString(result.OriginalSession) {
		t.Fatal("installed external succession lost its exact bounded lifecycle record", err, string(raw), process.diagnostic.String())
	}
	return result
}

func linuxHostTUNExternalParent(t *testing.T, installed, scenario string) {
	t.Helper()
	action := linuxHostTUNExternalAction(scenario)
	original := linuxHostTUNStartPeer(t, "restore-sealed")
	linuxHostTUNDirectHealth(t, original)
	linuxHostTUNInstallProfile(t, original, "restore-sealed")
	peer := linuxHostTUNStartExternalPeer(t, scenario)
	linuxHostTUNExternalTrust(t, peer)
	linuxHostTUNInstallExternalProfile(t, peer, scenario)
	if action == "dns-failure" {
		peer.observe(t, "fail-dns")
	}
	process := linuxHostTUNStartController(t, installed, scenario)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	first := linuxHostTUNReadExternal(t, process, scenario, "router")
	before := original.observe(t, "stats")
	if first.MTU != 1300 || before.RouterQueries == 0 || before.DNSQueries < 2 || before.DirectQueries != 1 || before.PlainTCP == 0 || before.PlainUDP == 0 {
		t.Fatal("external succession did not begin with a genuinely proved Router and observed MTU", first, before)
	}
	if _, err := process.gate.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	stage := "external"
	if action == "cancelled" {
		stage = "external-pending"
	} else if scenario == "external-ss-source" {
		stage = "source-refused"
	} else if linuxHostTUNExternalFailedProof(scenario) {
		stage = "proof-refused"
	}
	middle := linuxHostTUNReadExternal(t, process, scenario, stage)
	observed := peer.observe(t, "stats")
	if action == "cancelled" {
		deadline := time.NewTimer(10 * time.Second)
		tick := time.NewTicker(25 * time.Millisecond)
		defer deadline.Stop()
		defer tick.Stop()
		for observed.PublicAttempts == 0 {
			select {
			case <-deadline.C:
				t.Fatal("cancellation fixture never reached the actual held HTTPS exit proof", observed)
			case <-tick.C:
				observed = peer.observe(t, "stats")
			}
		}
		if observed.DNSQueries == 0 || observed.PublicReplies != 0 || middle.Proof != nil {
			t.Fatal("cancelled external path fabricated proof before its original HTTPS reply", middle, observed)
		}
	} else if scenario == "external-ss-source" {
		if !middle.SourcePreserved || observed.Connections != 0 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 {
			t.Fatal("changed external source reached Stop or a new native engine", middle, observed)
		}
	} else if action == "wrong-key" || action == "wrong-trust" || action == "wrong-psk" || action == "wrong-parameters" || action == "wrong-control" {
		if !middle.FailedProof || (peer.protocol != "openvpn" && observed.PhysicalUDP == 0) || observed.Connections != 0 || observed.Streams != 0 || observed.Packets != 0 ||
			observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || middle.Proof != nil {
			t.Fatal("wrong external peer credential or TLS identity reached an inner destination or Connected", middle, observed)
		}
	} else if action == "dns-failure" {
		if !middle.FailedProof || observed.DNSQueries == 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || middle.Proof != nil {
			t.Fatal("failed selected DNS fabricated an exit proof or Connected", middle, observed)
		}
	} else if middle.Proof == nil || !middle.Proof.Healthy || !middle.Proof.DNSProven || middle.Proof.EntryProven ||
		middle.MTU != 1376 || (peer.protocol != "hysteria2" && peer.protocol != "wireguard" && peer.protocol != "amneziawg" && peer.protocol != "openvpn" && observed.Connections == 0) || (peer.protocol != "openvpn" && observed.Streams == 0) || observed.DNSQueries == 0 || observed.PublicReplies == 0 || observed.AuthFailures != 0 {
		t.Fatal("external succession bypassed its real encrypted/authenticated DNS and exit exchanges", middle, observed)
	}
	if (peer.protocol == "hysteria2" || peer.protocol == "wireguard" || peer.protocol == "amneziawg") && (observed.PhysicalUDP == 0 || observed.Connections != 0 ||
		(action != "wrong-key" && action != "wrong-trust" && action != "wrong-psk" && action != "wrong-parameters" && observed.Packets == 0)) {
		t.Fatal("external selected UDP DNS or TCP proof bypassed its single physical UDP peer", observed)
	}
	// The pinned provider owns its encrypted listener internally. Its decrypted
	// DNS/HTTPS observations are real upper-layer counters, never substituted
	// for unavailable raw physical TCP/UDP or netstack stream counts.
	if peer.protocol == "openvpn" && (observed.Connections != 0 || observed.PhysicalUDP != 0 || observed.Streams != 0 || observed.Packets != 0) {
		t.Fatal("provider fixture relabeled upper traffic as raw transport", observed)
	}
	if current := original.observe(t, "stats"); current.RouterQueries != before.RouterQueries || current.DirectQueries != before.DirectQueries {
		t.Fatal("external proof borrowed the previous Router response", before, current)
	}
	if _, err := process.gate.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	final := linuxHostTUNReadExternal(t, process, scenario, "retired")
	if final.OriginalSession != first.OriginalSession || final.Journal == nil || final.Journal.Incomplete || final.Journal.Record.Validate() != nil ||
		final.Journal.Record.Phase != "settled" || final.Journal.Record.Committed.Engine != nil || !desktopMTURequestPattern.MatchString(final.FinalSession) {
		t.Fatal("external succession lost its original durable journal or joined engine", final)
	}
	select {
	case <-process.done:
	case <-time.After(5 * time.Second):
		t.Fatal("installed external controller did not join after exact retirement", process.diagnostic.String())
	}
	if process.waitErr != nil || process.command.ProcessState == nil || !process.command.ProcessState.Success() || linuxHostTUNTUNAbsent(nil) != nil {
		t.Fatal("installed external lifecycle left its child or real TUN alive", process.waitErr, process.diagnostic.String())
	}
	after := original.observe(t, "stats")
	if scenario == "external-ss-source" {
		if !final.SourcePreserved || final.FinalSession != final.OriginalSession || after.RouterQueries != before.RouterQueries {
			t.Fatal("source refusal replaced the original proved Router", final, after)
		}
	} else if action == "replacement" {
		if !final.ReplacementKept || final.Restore != nil || after.RouterQueries != before.RouterQueries {
			t.Fatal("old external restore overwrote a replacement connection", final, after)
		}
	} else if action == "public" {
		if !final.PublicPersisted || final.FinalSession != final.ExternalSession || final.Restore != nil || after.RouterQueries != before.RouterQueries {
			t.Fatal("public external Connect lost persistence, retained monitor or its distinct exit", final, after)
		}
	} else if final.Restore == nil || !final.Restore.Cleared || final.Restore.RestoredMTU != 1300 || final.Restore.Execution != "local" ||
		final.Restore.PreviousSession != final.OriginalSession || final.Restore.FreshSession != final.FinalSession || final.FinalSession == final.OriginalSession ||
		after.RouterQueries <= before.RouterQueries || after.DirectQueries != before.DirectQueries {
		t.Fatal("external test did not restore and reprove the exact captured Router and observed MTU", final, before, after)
	}
	if strings.HasSuffix(scenario, "-always") {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		closed, err := linuxShutdownTable(ctx, final.FinalSession)
		digest := sha256.Sum256(closed)
		if err != nil || len(closed) == 0 || final.Journal.Record.Committed.Target == nil || hex.EncodeToString(digest[:]) != final.ClosedTableSHA256 {
			t.Fatal("external succession released or replaced its original Always closed protection", err)
		}
	} else if final.Journal.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxNodeAbsence(context.Background(), final.FinalSession) != nil {
		t.Fatal("external succession retained an unowned On-connect table")
	}
	if end := peer.observe(t, "stats"); end.AuthFailures != 0 || action == "cancelled" && end.PublicReplies != 0 {
		t.Fatal("retired external proof was adopted after cancellation", end)
	}
	t.Log("verified installed host retained external succession:", scenario)
	t.Log("verified installed host native lifecycle:", scenario)
}
