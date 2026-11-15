//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

var macOSExternalOpenVPNSS2022Cases = []string{
	"openvpn-entry-ss-tcp", "openvpn-entry-ss-tcp-always", "openvpn-entry-ss-udp", "openvpn-entry-ss-udp-always",
	"openvpn-entry-ss-tcp-entry-always", "openvpn-entry-ss-tcp-final-off-entry-always",
	"openvpn-entry-ss-tcp-wrong-entry-public", "openvpn-entry-ss-tcp-wrong-control", "openvpn-entry-ss-udp-wrong-password",
	"openvpn-entry-ss-tcp-wrong-provider-trust", "openvpn-entry-ss-udp-wrong-final-key",
	"openvpn-entry-ss-tcp-wrong-dns", "openvpn-entry-ss-udp-wrong-trust", "openvpn-entry-ss-tcp-wrong-exit",
}

func macOSExternalOpenVPNSS2022Scenario(scenario string) (network, fault string, found bool) {
	for _, candidate := range macOSExternalOpenVPNSS2022Cases {
		if scenario != candidate {
			continue
		}
		rest := strings.TrimPrefix(scenario, "openvpn-entry-ss-")
		network, fault, _ = strings.Cut(rest, "-")
		if fault == "always" || fault == "entry-always" || fault == "final-off-entry-always" {
			fault = ""
		}
		return network, fault, true
	}
	return "", "", false
}

// Protection aggregates captured participants; DNS, LAN and IPv6 remain final-selected.
func (p *macOSExternalNativePeer) protectionPolicy() string {
	// An independent expected verdict for these finite native fixture cases.
	// Do not use the production aggregator to manufacture its own expectation.
	if p.entryPolicy == "always" {
		return "always"
	}
	if p.entryPolicy == "" || p.entryPolicy == "off" {
		return p.policy
	}
	return ""
}

func macOSExternalNativeOpenVPNSS2022Read(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	t.Helper()
	if !p.openvpnEntry {
		if reply.OpenVPNEntryAddress != "" || reply.OpenVPNEntryProofs != 0 {
			t.Fatal("unrequested OpenVPN entry receipt")
		}
		return
	}
	address, err := netip.ParseAddrPort(reply.OpenVPNEntryAddress)
	if err != nil || address.Addr() != p.physical || address.Port() == 0 || p.entryAddress.IsValid() && p.entryAddress != address || reply.Address != "198.51.100.240:8388" || reply.PacketEntry != nil || reply.ShadowsocksEntry != nil {
		t.Fatal("OpenVPN entry replaced its physical provider or independent private final")
	}
	// Reuse direct import validation against the entry's physical address, never
	// the SS2022 final. Its captured role remains explicit in the original peer.
	original := p.protocol
	p.protocol = "openvpn"
	macOSExternalNativeOpenVPNRead(t, p, reply, address)
	p.protocol = original
	p.entryAddress = address
}
func macOSExternalNativeOpenVPNSS2022Profile(t *testing.T, p *macOSExternalNativePeer, final *common.RouterProfile) *common.RouterProfile {
	t.Helper()
	if !p.openvpnEntry || final.External.Shadowsocks == nil {
		t.Fatal("OpenVPN entry lost independent SS2022 final")
	}
	final.MultihopEnabled, final.MultihopEntryID, final.MultihopExitID = true, macOSExternalNativeEntryID(p), final.ID
	final.MultihopExecution, final.MultihopEntryMode, final.DNSProtocol = "local", "", "udp"
	if p.fault == "wrong-final-key" {
		final.External.Shadowsocks.Password = testWGKey('z')
	}
	if p.fault == "wrong-exit" {
		final.External.ExpectedPublicIP = "203.0.113.89"
	}
	entry := &common.RouterProfile{ID: macOSExternalNativeEntryID(p), Name: "Captured physical OpenVPN entry", KillSwitch: p.entryPolicy == "always", KillSwitchPolicy: p.entryPolicy, NodeKind: "external", Endpoint: p.physical.String(), StartLayer: common.StartLayerOff, MTUPolicy: "manual", ManualMTU: 1500, External: &common.ExternalNodeConfig{Protocol: "openvpn", ExpectedPublicIP: "203.0.113.77", OpenVPN: macOSExternalNativeOpenVPNProfile(t, p)}}
	if p.fault == "wrong-entry-public" {
		entry.External.ExpectedPublicIP = "203.0.113.76"
	}
	if err := common.NormalizeRouterProfile(entry); err != nil {
		t.Fatal(err)
	}
	return entry
}
func macOSExternalNativeOpenVPNSS2022Observation(h *desktopMacOSExternalHost, result *macOSExternalNativeResult) error {
	capture, err := h.policy.Capture()
	if err != nil {
		return err
	}
	if !desktopExternalOpenVPNEntryOwner(h.launch.external) || capture.EntryID != h.launch.external.entry.ID || capture.EntryTag != "external-entry" || capture.EntryMTU != 1500 || capture.SelectedDNS.Physical || len(capture.PhysicalRoots) != 1 {
		return errors.New("OpenVPN entry lost original bounded capture")
	}
	root := capture.PhysicalRoots[0]
	endpoint, err := nativeopenvpn.CompileProfile(*h.launch.external.entry.External.OpenVPN, capture.EntryTag, "")
	if err != nil {
		return err
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	if err != nil || len(remotes) != 1 || root.Family != "endpoints" || root.Tag != capture.EntryTag || root.Type != "openvpn-client" || len(root.Destinations) != 1 || root.Destinations[0].Host != remotes[0].Host || root.Destinations[0].Port != remotes[0].Port || root.Destinations[0].Network != remotes[0].Network {
		return errors.New("OpenVPN entry changed exact physical remote")
	}
	if err := macOSExternalNativeOpenVPNSS2022Graph(h.policy.Config(), capture.EntryTag, remotes); err != nil {
		return err
	}
	result.OpenVPNRemotes = remotes
	result.PhysicalDestinations = append([]mobilemultihop.PhysicalEgress(nil), root.Destinations...)
	return nil
}
func macOSExternalNativeOpenVPNSS2022Proved(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	ipv6 := "off"
	if p.policy == "always" {
		ipv6 = "on"
	}
	if live.Baseline == nil || live.Baseline.Capture.FinalPolicy != p.policy || live.Baseline.Capture.EntryPolicy != p.entryPolicy || live.Baseline.Capture.Policy != p.protectionPolicy() || live.Baseline.Capture.ProfileID != "installed-macos-external" || live.Baseline.Capture.EntryProfileID != macOSExternalNativeEntryID(p) {
		t.Fatal("OpenVPN SS2022 baseline lost exact original member policies", live.Baseline)
	}
	if !p.openvpnEntry || !live.Proof.EntryProven || live.Proof.EntryID != macOSExternalNativeEntryID(p) || live.Proof.EntryNodeID != "" || live.Proof.ExitID != "installed-macos-external" || live.Proof.IP != "203.0.113.88" || live.OuterTag != "external-entry" || live.OuterType != "openvpn-client" || live.InnerHost != "198.51.100.240" || live.InnerDetour != "external-entry" || live.PhysicalAddress != p.entryAddress.String() || live.PhysicalNetwork != p.openvpnNetwork || len(live.OpenVPNRemotes) != 1 || live.OpenVPNRemotes[0] != (nativeopenvpn.Remote{Host: p.physical.String(), Port: int(p.entryAddress.Port()), Network: p.openvpnNetwork}) || live.Network.MTU != 1376 || live.DNSProtocol != "udp" || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.IPv6 != ipv6 || live.HomeLAN != (p.policy == "always") || observed.OpenVPNFinalSequence == 0 || observed.OpenVPNEntryProofs < 1 || observed.Streams < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 || observed.AuthFailures != 0 || p.openvpnNetwork == "tcp" && observed.Connections < 1 || p.openvpnNetwork == "udp" && observed.PhysicalUDP < 1 {
		t.Fatal("OpenVPN SS2022 proof omitted original encrypted entry, final, selected policy or capacity", live, observed)
	}
}
func macOSExternalNativeOpenVPNSS2022Refused(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("OpenVPN SS2022 negative did not reach native refusal", status, failure, string(raw))
	}
	observed := p.stats(t)
	if observed.OpenVPNFinalSequence == 0 || p.openvpnNetwork == "tcp" && observed.Connections < 1 || p.openvpnNetwork == "udp" && observed.PhysicalUDP < 1 {
		t.Fatal("OpenVPN SS2022 negative never reached original provider")
	}
	if p.fault == "wrong-final-key" {
		if observed.OpenVPNEntryProofs < 1 || observed.Packets < 1 || observed.AuthFailures < 1 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("SS2022 final key negative bypassed actual independent authenticator", observed)
		}
	} else if p.fault == "wrong-entry-public" || p.fault == "wrong-trust" {
		if observed.Streams < 1 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || (p.fault == "wrong-entry-public" && observed.OpenVPNEntryProofs < 1) || (p.fault == "wrong-trust" && observed.OpenVPNEntryProofs != 0) {
			t.Fatal("OpenVPN entry proof negative crossed independent final", observed)
		}
	} else {
		if (p.fault == "wrong-dns" || p.fault == "wrong-exit") && observed.OpenVPNEntryProofs < 1 {
			t.Fatal("final negative omitted independent entry proof")
		}
		macOSExternalNativeOpenVPNRefusalWitness(t, p, observed)
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session || retired.Baseline.Capture.Source != retired.Source || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Protocol != "shadowsocks" || len(retired.OpenVPNRemotes) != 1 || len(retired.PhysicalDestinations) != 1 {
		t.Fatal("OpenVPN SS2022 refusal lost original native retirement", status, failure, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}

// Loss is exercised by closing the actual independent TCP provider. This is
// native channel-loss acceptance, not a claim of endpoint reconnect coverage.
func macOSExternalNativeOpenVPNSS2022Loss(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/speed-lab/external-latency", "")
	var before desktopLatencyView
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &before) != nil || before.SessionID != live.Session || before.SourceSHA256 != live.Source || before.ConfigSHA256 != live.Config || before.ProfileToken == "" {
		t.Fatal("provider loss omitted original measured owner", status, err, string(raw))
	}
	if _, err = p.input.Write([]byte("close-openvpn-entry\n")); err != nil {
		t.Fatal(err)
	}
	observed := p.read(t)
	if observed.OpenVPNEntryProofs < 1 || observed.PublicReplies < 1 {
		t.Fatal("provider loss preceded original composed proof")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
		if err != nil {
			t.Fatal("provider loss replaced controller", err)
		}
		if status == http.StatusConflict {
			break
		}
		var value macOSExternalNativeResult
		if status == http.StatusOK && decodeRelayControlJSON(raw, &value) == nil && value.Closed && !value.Connected {
			break
		}
		if status != http.StatusOK || time.Now().After(deadline) {
			t.Fatal("closed OpenVPN provider retained original native proof", status, string(raw))
		}
		time.Sleep(20 * time.Millisecond)
	}
	request := desktopLatencyRequest{ProfileID: before.ProfileID, ProfileToken: before.ProfileToken, SessionID: live.Session, Request: strings.Repeat("9", 32)}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/speed-lab/external-latency", string(body))
	if err != nil || status != http.StatusConflict {
		t.Fatal("lost OpenVPN provider retained measurement authority", status, err, string(raw))
	}
}
