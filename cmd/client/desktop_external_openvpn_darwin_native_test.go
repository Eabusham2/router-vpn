//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

func macOSExternalNativeOpenVPNRead(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply, address netip.AddrPort) {
	t.Helper()
	if p.protocol != "openvpn" {
		if reply.OpenVPNProfile != "" || reply.OpenVPNNetwork != "" || reply.OpenVPNUsername != "" || reply.OpenVPNPassword != "" || reply.OpenVPNFallbackAttempts != 0 || reply.OpenVPNFirstSequence != 0 || reply.OpenVPNFinalSequence != 0 {
			t.Fatal("ordinary peer acquired another OpenVPN import")
		}
		return
	}
	if len(reply.OpenVPNProfile) == 0 || len(reply.OpenVPNProfile) > 12<<10 || reply.OpenVPNNetwork != p.openvpnNetwork || reply.OpenVPNUsername == "" || reply.OpenVPNPassword == "" || p.openvpnProfile != "" && (p.openvpnProfile != reply.OpenVPNProfile || p.openvpnUsername != reply.OpenVPNUsername || p.openvpnPassword != reply.OpenVPNPassword) {
		t.Fatal("OpenVPN peer changed its original imported source or credentials")
	}
	endpoint, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: reply.OpenVPNProfile, Username: reply.OpenVPNUsername, Password: reply.OpenVPNPassword}, mobilemultihop.ExternalFinalTag, "")
	if err != nil {
		t.Fatal("actual OpenVPN peer import invalid", err)
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	want := 1
	if p.openvpnFallback {
		want = 2
	}
	if err != nil || len(remotes) != want || remotes[len(remotes)-1] != (nativeopenvpn.Remote{Host: address.Addr().String(), Port: int(address.Port()), Network: p.openvpnNetwork}) {
		t.Fatal("OpenVPN peer changed the final captured remote", err)
	}
	if want == 2 && (remotes[0].Host != address.Addr().String() || remotes[0].Network != "tcp" || remotes[0].Port == int(address.Port())) {
		t.Fatal("OpenVPN peer lost distinct ordered fallback")
	}
	if reply.OpenVPNFallbackAttempts < 0 || !p.openvpnFallback && (reply.OpenVPNFallbackAttempts != 0 || reply.OpenVPNFirstSequence != 0) {
		t.Fatal("OpenVPN peer fabricated a fallback observation")
	}
	p.openvpnProfile, p.openvpnUsername, p.openvpnPassword = reply.OpenVPNProfile, reply.OpenVPNUsername, reply.OpenVPNPassword
}

func macOSExternalNativeOpenVPNProfile(t *testing.T, p *macOSExternalNativePeer) *common.ExternalOpenVPNConfig {
	t.Helper()
	value := &common.ExternalOpenVPNConfig{Config: p.openvpnProfile, Username: p.openvpnUsername, Password: p.openvpnPassword}
	switch p.fault {
	case "wrong-password":
		value.Password += "-different"
	case "wrong-username":
		value.Username += "-different"
	case "wrong-control":
		changed := strings.ReplaceAll(value.Config, strings.Repeat("a", 32), strings.Repeat("b", 32))
		if changed == value.Config {
			t.Fatal("OpenVPN control negative lost original key")
		}
		value.Config = changed
	case "wrong-provider-trust":
		before, rest, ok := strings.Cut(value.Config, "<ca>\n")
		_, after, closed := strings.Cut(rest, "</ca>\n")
		if !ok || !closed {
			t.Fatal("OpenVPN provider lost original CA")
		}
		value.Config = before + "<ca>\n" + p.ca + "</ca>\n" + after
	}
	return value
}

func macOSExternalNativeOpenVPNObservation(h *desktopMacOSExternalHost, result *macOSExternalNativeResult) error {
	capture, err := h.policy.Capture()
	if err != nil {
		return err
	}
	profile := h.launch.external.profile.External
	if profile == nil || profile.OpenVPN == nil || profile.ResponseProbe != nil || profile.OpenVPNResponseProbes != nil || profile.OpenVPNPairing != nil || len(capture.PhysicalRoots) != 1 || capture.EntryID == "" && capture.PhysicalRoots[0].Type != "openvpn-client" || capture.PhysicalRoots[0].Family != "endpoints" || capture.SelectedDNS.Physical {
		return errors.New("native OpenVPN observation lost its exact direct import")
	}
	endpoint, err := nativeopenvpn.CompileProfile(*profile.OpenVPN, mobilemultihop.ExternalFinalTag, capture.EntryTag)
	if err != nil {
		return err
	}
	result.OpenVPNRemotes, err = nativeopenvpn.Remotes(endpoint)
	if err != nil {
		return err
	}
	result.PhysicalDestinations = append([]mobilemultihop.PhysicalEgress(nil), capture.PhysicalRoots[0].Destinations...)
	wanted := map[mobilemultihop.PhysicalEgress]bool{}
	for _, remote := range result.OpenVPNRemotes {
		wanted[mobilemultihop.PhysicalEgress{Host: remote.Host, Port: remote.Port, Network: remote.Network}] = true
	}
	if capture.EntryID == "" {
		if len(wanted) != len(result.PhysicalDestinations) {
			return errors.New("native OpenVPN physical tuple count changed")
		}
		for _, destination := range result.PhysicalDestinations {
			if !wanted[destination] {
				return errors.New("native OpenVPN physical networks crossed captured remotes")
			}
		}
	} else {
		if capture.EntryTag != "external-entry" || capture.PhysicalRoots[0].Tag != capture.EntryTag || len(result.PhysicalDestinations) != 1 || result.PhysicalDestinations[0].Network != "udp" {
			return errors.New("OpenVPN final acquired physical remote permission")
		}
		result.InnerHost, result.InnerDetour = result.OpenVPNRemotes[len(result.OpenVPNRemotes)-1].Host, capture.EntryTag
	}
	for _, raw := range []string{h.policy.OriginalPolicy().Config(), h.policy.Config()} {
		var graph struct{ Endpoints []map[string]any }
		want := 1
		if capture.EntryID != "" {
			want = 2
		}
		if json.Unmarshal([]byte(raw), &graph) != nil || len(graph.Endpoints) != want {
			return errors.New("native OpenVPN endpoint owner changed")
		}
		var final map[string]any
		for _, row := range graph.Endpoints {
			if row["tag"] == mobilemultihop.ExternalFinalTag {
				if final != nil {
					return errors.New("duplicate original OpenVPN final")
				}
				final = row
			}
		}
		if final == nil || capture.EntryID != "" && final["detour"] != capture.EntryTag {
			return errors.New("OpenVPN endpoint lost its captured detour")
		}
		remotes, e := nativeopenvpn.Remotes(final)
		if e != nil || !reflect.DeepEqual(remotes, result.OpenVPNRemotes) {
			return errors.New("native OpenVPN lost ordered fallback")
		}
	}
	return nil
}
func macOSExternalNativeOpenVPNProved(t *testing.T, peer *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	endpoint, err := nativeopenvpn.CompileProfile(nativeopenvpn.Profile{Config: peer.openvpnProfile, Username: peer.openvpnUsername, Password: peer.openvpnPassword}, mobilemultihop.ExternalFinalTag, "")
	if err != nil {
		t.Fatal(err)
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	expectedIPv6 := "off"
	if peer.policy == "always" {
		expectedIPv6 = "on"
	}
	outer, mtu := "openvpn-client", 1376
	if peer.packetEntry {
		outer, mtu = macOSExternalNativeEntryType(peer), 1280
	}
	if err != nil || !reflect.DeepEqual(live.OpenVPNRemotes, remotes) || live.OuterType != outer || live.IPv6 != expectedIPv6 || live.HomeLAN != (peer.policy == "always") || live.DNSProtocol != "udp" || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.Network.MTU != mtu || observed.Packets < 1 || observed.OpenVPNFinalSequence == 0 || peer.openvpnNetwork == "tcp" && (observed.Connections < 1 || observed.PhysicalUDP != 0) || peer.openvpnNetwork == "udp" && (observed.PhysicalUDP < 1 || observed.Connections != 0) {
		t.Fatal("OpenVPN native proof lost exact transport, selected policy or decrypted packet evidence")
	}
	if peer.openvpnFallback && (observed.OpenVPNFallbackAttempts < 1 || observed.OpenVPNFirstSequence == 0 || observed.OpenVPNFirstSequence >= observed.OpenVPNFinalSequence) {
		t.Fatal("native OpenVPN did not try its first captured TCP remote before final encrypted provider")
	}
}
func macOSExternalNativeOpenVPNRefused(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("OpenVPN negative did not complete actual native refusal", status, failure, string(raw))
	}
	observed := peer.stats(t)
	if observed.OpenVPNFinalSequence == 0 || peer.openvpnNetwork == "tcp" && observed.Connections < 1 || peer.openvpnNetwork == "udp" && observed.PhysicalUDP < 1 {
		t.Fatal("OpenVPN negative never reached its independent encrypted provider")
	}
	macOSExternalNativeOpenVPNRefusalWitness(t, peer, observed)
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session || retired.Baseline.Capture.Source != retired.Source || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Protocol != "openvpn" || len(retired.OpenVPNRemotes) == 0 || len(retired.PhysicalDestinations) != len(retired.OpenVPNRemotes) {
		t.Fatal("OpenVPN refusal lost original source, joined child, complete PF tuples or utun retirement", status, failure, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}

// OpenVPN's imported remote policy requires a public literal. Hosted macOS
// runners commonly have only a private physical address, so this disposable
// fixture owns one real documentation /32 on that same original interface.
// It never changes the default route or the physical policy's source choice.
func macOSExternalNativeOpenVPNAddress(t *testing.T, original netip.Addr) netip.Addr {
	t.Helper()
	alias := netip.MustParseAddr("192.0.2.254")
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var captured net.Interface
	var before []string
	for _, device := range interfaces {
		addresses, e := device.Addrs()
		if e != nil {
			t.Fatal(e)
		}
		values := []string{}
		for _, raw := range addresses {
			values = append(values, raw.String())
			prefix, e := netip.ParsePrefix(raw.String())
			if e != nil {
				continue
			}
			if prefix.Addr() == alias {
				t.Fatal("OpenVPN documentation alias already belongs to another native owner")
			}
			if prefix.Addr() == original {
				if captured.Index != 0 || device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
					t.Fatal("OpenVPN original physical interface is ambiguous")
				}
				captured = device
			}
		}
		if captured.Index == device.Index {
			before = values
		}
	}
	if captured.Index == 0 {
		t.Fatal("OpenVPN fixture lost the original physical interface")
	}
	slices.Sort(before)
	current := func() ([]string, error) {
		device, e := net.InterfaceByIndex(captured.Index)
		if e != nil || device.Name != captured.Name || device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			return nil, errors.New("OpenVPN fixture physical identity changed")
		}
		addresses, e := device.Addrs()
		if e != nil {
			return nil, e
		}
		values := make([]string, len(addresses))
		for i, v := range addresses {
			values[i] = v.String()
		}
		slices.Sort(values)
		return values, nil
	}
	expected := append(append([]string(nil), before...), alias.String()+"/32")
	slices.Sort(expected)
	entered := false
	t.Cleanup(func() {
		if !entered {
			return
		}
		values, e := current()
		if e != nil {
			t.Error("OpenVPN alias cleanup lost original interface", e)
			return
		}
		found := false
		for _, value := range values {
			if value == alias.String()+"/32" {
				found = true
			}
		}
		if found {
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			_, e = macOSExternalNativeCommand(ctx, "/sbin/ifconfig", captured.Name, "inet", alias.String(), "-alias")
			stop()
			if e != nil {
				t.Error("OpenVPN fixture failed to remove its original alias", e)
				return
			}
		}
		values, e = current()
		if e != nil || !reflect.DeepEqual(values, before) {
			t.Error("OpenVPN alias cleanup did not restore the original physical address set", e)
		}
	})
	entered = true
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = macOSExternalNativeCommand(ctx, "/sbin/ifconfig", captured.Name, "inet", alias.String(), "netmask", "255.255.255.255", "alias")
	stop()
	if err != nil {
		t.Fatal("OpenVPN fixture failed native documentation alias acquisition", err)
	}
	after, err := current()
	if err != nil || !reflect.DeepEqual(after, expected) {
		t.Fatal("OpenVPN fixture alias lacks exact native readback", err)
	}
	return alias
}

func macOSExternalNativeOpenVPNRefusalWitness(t *testing.T, peer *macOSExternalNativePeer, observed macOSExternalPeerReply) {
	t.Helper()
	switch peer.fault {
	case "wrong-control", "wrong-provider-trust", "wrong-password", "wrong-username":
		if observed.DNSQueries != 0 || observed.Streams != 0 || observed.Packets != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("OpenVPN authentication refusal acquired decrypted proof")
		}
		if (peer.fault == "wrong-password" || peer.fault == "wrong-username") && observed.AuthFailures < 1 {
			t.Fatal("OpenVPN credential negative missed actual server authenticator")
		}
	case "wrong-dns":
		if observed.DNSQueries < 1 || observed.Packets < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("OpenVPN DNS negative missed selected encrypted DNS")
		}
	case "wrong-trust":
		if observed.DNSQueries < 1 || observed.Streams < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("OpenVPN public TLS negative missed actual trust boundary")
		}
	case "wrong-exit":
		if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 {
			t.Fatal("OpenVPN exit mismatch missed actual public proof")
		}
	default:
		t.Fatal("unknown native OpenVPN refusal")
	}
}

func macOSExternalNativeOpenVPNEntryRefusalWitness(t *testing.T, p *macOSExternalNativePeer, entry *macOSExternalPacketEntryReceipt, observed macOSExternalPeerReply) {
	t.Helper()
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters", "wrong-exit-address":
		if observed.Connections != 0 || observed.PhysicalUDP != 0 || observed.OpenVPNFinalSequence != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("OpenVPN crossed original entry or fixed final route")
		}
	case "wrong-entry-public":
		if entry.PublicReplies < 1 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("OpenVPN entry proof refusal acquired final proof")
		}
	default:
		if entry.PublicReplies < 1 || observed.OpenVPNFinalSequence == 0 || p.openvpnNetwork == "tcp" && observed.Connections < 1 || p.openvpnNetwork == "udp" && observed.PhysicalUDP < 1 {
			t.Fatal("OpenVPN final refusal missed original encrypted peers")
		}
		macOSExternalNativeOpenVPNRefusalWitness(t, p, observed)
	}
}
