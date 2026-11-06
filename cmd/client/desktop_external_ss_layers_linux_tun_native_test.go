//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

var linuxHostTUNSSLayerCases = func() []string {
	var names []string
	for a := 0; a < 3; a++ {
		for b := 0; b < 3; b++ {
			names = append(names, fmt.Sprintf("external-ss256ss256l%d%d-on-connect", a, b))
		}
	}
	for _, action := range []string{"always", "always-off", "cancelled", "source", "entry-source", "replacement", "dns-failure", "wrong-entry-public", "wrong-entry-layer", "wrong-final-layer", "entry-whitening", "final-whitening"} {
		names = append(names, "external-ss256ss256l22-"+action)
	}
	return names
}()

type linuxSSLayerSelection struct {
	mode, key string
	address   netip.AddrPort
}

func linuxHostTUNSSLayerToken(token string) (string, int, int, bool) {
	base, suffix, found := strings.Cut(token, "l")
	if !found {
		return token, 0, 0, false
	}
	if len(suffix) != 2 || suffix[0] < '0' || suffix[0] > '2' || suffix[1] < '0' || suffix[1] > '2' {
		return "", 0, 0, false
	}
	return base, int(suffix[0] - '0'), int(suffix[1] - '0'), true
}
func linuxHostTUNSSLayerMode(mode int) string {
	return []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR}[mode]
}
func linuxHostTUNSSLayerRequest(t *testing.T, peer *linuxExternalTUNPeer, request map[string]any, scenario string) {
	t.Helper()
	if peer.ssEntry == nil {
		return
	}
	for _, item := range []struct {
		name  string
		layer *linuxSSLayerSelection
	}{{"ss_entry_layer", &peer.ssEntry.entryLayer}, {"ss_final_layer", &peer.ssEntry.finalLayer}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		fault := ""
		action := linuxHostTUNExternalAction(scenario)
		if item.name == "ss_entry_layer" && action == "entry-whitening" || item.name == "ss_final_layer" && action == "final-whitening" {
			fault = "whitening"
		}
		request[item.name] = map[string]any{"mode": item.layer.mode, "password": item.layer.key, "fault": fault}
	}
}
func linuxHostTUNSSLayerRead(t *testing.T, peer *linuxExternalTUNPeer, reply linuxExternalTUNPeerReply) {
	t.Helper()
	if peer.ssEntry == nil {
		if reply.SSEntryLayer != nil || reply.SSFinalLayer != nil {
			t.Fatal("foreign SS layer receipt")
		}
		return
	}
	for _, item := range []struct {
		layer   *linuxSSLayerSelection
		receipt *linuxExternalTUNSSEntryReceipt
		entry   bool
	}{{&peer.ssEntry.entryLayer, reply.SSEntryLayer, true}, {&peer.ssEntry.finalLayer, reply.SSFinalLayer, false}} {
		layer, r := item.layer, item.receipt
		if layer.mode == "" || layer.mode == common.StartLayerOff {
			if r != nil {
				t.Fatal("Off acquired SS layer")
			}
			continue
		}
		if r == nil || r.Method != common.StartLayerAES256GCMTransport {
			t.Fatal("missing captured SS layer")
		}
		address, err := netip.ParseAddrPort(r.Address)
		if err != nil || address.Port() == 0 || item.entry && address.Addr().String() != "11.77.0.2" || !item.entry && !address.Addr().IsLoopback() || layer.address.IsValid() && layer.address != address {
			t.Fatal("SS layer changed original listener")
		}
		if item.entry && layer.mode == common.StartLayerAES256GCMXOR && address.Port() != 8389 {
			t.Fatal("SS XOR physical port changed")
		}
		layer.address = address
	}
}
func linuxHostTUNSSLayerProfiles(t *testing.T, peer *linuxExternalTUNPeer, scenario string, profile, entry *common.RouterProfile) {
	t.Helper()
	s := peer.ssEntry
	for i, item := range []struct {
		p       *common.RouterProfile
		layer   linuxSSLayerSelection
		private string
	}{{entry, s.entryLayer, "10.94.0.1"}, {profile, s.finalLayer, "10.93.0.1"}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		port := int(item.layer.address.Port())
		if i == 1 {
			port = int(peer.address.Port())
			item.p.External.Shadowsocks.Port = 8388
		}
		item.p.StartLayer = item.layer.mode
		item.p.External.StartLayer = &common.ExternalStartLayer{Mode: item.layer.mode, API: "http://" + item.private + ":8787", Transport: map[string]any{"type": "shadowsocks", "tag": "captured-layer", "server": item.p.External.Shadowsocks.Server, "server_port": port, "method": common.StartLayerAES256GCMTransport, "password": item.layer.key}}
		action := linuxHostTUNExternalAction(scenario)
		if i == 0 && action == "wrong-entry-layer" || i == 1 && action == "wrong-final-layer" {
			item.p.External.StartLayer.Transport["password"] = linuxHostTUNSSKey(t, common.StartLayerAES256GCMTransport)
		}
	}
}
func linuxHostTUNSSLayerFailure(t *testing.T, peer *linuxExternalTUNPeer, action string, middle linuxExternalTUNResult, reply linuxExternalTUNPeerReply) bool {
	entry := action == "wrong-entry-layer" || action == "entry-whitening"
	final := action == "wrong-final-layer" || action == "final-whitening"
	if !entry && !final {
		return false
	}
	layer := reply.SSEntryLayer
	if final {
		layer = reply.SSFinalLayer
	}
	if !middle.FailedProof || middle.Proof != nil || layer == nil || layer.AuthTCP+layer.AuthUDP == 0 || layer.Streams != 0 || layer.Packets != 0 || reply.Streams != 0 || reply.Packets != 0 || reply.DNSQueries != 0 || reply.PublicReplies != 0 {
		t.Fatal("failed SS layer bypassed independent authentication", reply)
	}
	if entry && (reply.ShadowsocksEntry == nil || reply.ShadowsocksEntry.PhysicalTCP != 0 || reply.ShadowsocksEntry.PhysicalUDP != 0 || reply.Connections != 0 || reply.PhysicalUDP != 0) {
		t.Fatal("failed outer entry reached inner peer", reply)
	}
	return true
}
func linuxHostTUNSSLayerStats(t *testing.T, peer *linuxExternalTUNPeer, action string, reply linuxExternalTUNPeerReply) bool {
	if peer.ssEntry == nil {
		return false
	}
	for _, item := range []struct {
		layer linuxSSLayerSelection
		r     *linuxExternalTUNSSEntryReceipt
		entry bool
	}{{peer.ssEntry.entryLayer, reply.SSEntryLayer, true}, {peer.ssEntry.finalLayer, reply.SSFinalLayer, false}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		r := item.r
		if r == nil {
			t.Fatal("layer stats missing")
		}
		failedEntry := action == "wrong-entry-layer" || action == "entry-whitening"
		failedFinal := action == "wrong-final-layer" || action == "final-whitening"
		if action == "source" || action == "entry-source" || !item.entry && (failedEntry || action == "wrong-entry-public") {
			if r.PhysicalTCP != 0 || r.PhysicalUDP != 0 || r.Streams != 0 || r.Packets != 0 {
				t.Fatal("unproved layer reached successor", reply)
			}
			continue
		}
		if item.entry && failedEntry || !item.entry && failedFinal {
			if r.AuthTCP+r.AuthUDP == 0 || r.Streams != 0 || r.Packets != 0 {
				t.Fatal("missing real layer authentication refusal")
			}
			continue
		}
		if r.AuthTCP != 0 || r.AuthUDP != 0 || r.PhysicalTCP+r.PhysicalUDP == 0 || r.Streams+r.Packets == 0 {
			t.Fatal("layer never independently decrypted original traffic", reply)
		}
	}
	return action == "wrong-entry-layer" || action == "entry-whitening"
}
func linuxHostTUNSSLayerAuthority(native *desktopNodeLaunch) error {
	bad := errors.New("Linux independent SS layers changed original source or physical owner")
	if native == nil || native.external == nil || native.external.physical == nil {
		return bad
	}
	o := native.external
	if validateDesktopMacOSExternalSources(o.profile, o.entry, native) != nil {
		return bad
	}
	capture, err := o.physical.Capture()
	if err != nil || len(capture.PhysicalRoots) != 1 || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
		return bad
	}
	root := capture.PhysicalRoots[0]
	host, port := o.entry.External.Shadowsocks.Server, o.entry.External.Shadowsocks.Port
	tag, kind := "external-entry", "shadowsocks"
	if o.entry.External.StartLayer != nil {
		layer := o.entry.External.StartLayer
		tag = mobilemultihop.ExternalEntryStartLayerTag
		if layer.Mode == common.StartLayerAES256GCMXOR {
			kind = "routervpn-aes-xor"
		}
		host, _ = layer.Transport["server"].(string)
		raw, _ := json.Marshal(layer.Transport["server_port"])
		if json.Unmarshal(raw, &port) != nil {
			return bad
		}
	}
	if root.Tag != tag || root.Type != kind || len(root.Destinations) != 2 {
		return bad
	}
	networks := map[string]bool{"tcp": true, "udp": true}
	for _, d := range root.Destinations {
		if !networks[d.Network] || d.Host != host || d.Port != port {
			return bad
		}
		delete(networks, d.Network)
	}
	var old, current map[string]any
	if json.Unmarshal([]byte(o.physical.OriginalPolicy().Config()), &old) != nil || json.Unmarshal([]byte(o.physical.Config()), &current) != nil {
		return bad
	}
	rows, _ := current["outbounds"].([]any)
	original, _ := old["outbounds"].([]any)
	if len(rows) != len(original)+1 {
		return bad
	}
	for _, item := range original {
		row := item.(map[string]any)
		actual := taggedRuntimeItem(rows, row["tag"].(string))
		if actual == nil {
			return bad
		}
		if row["tag"] == tag {
			if actual["detour"] != mobilemultihop.DesktopExternalPhysicalTag {
				return bad
			}
			delete(actual, "detour")
		}
		if !reflect.DeepEqual(row, actual) {
			return bad
		}
	}
	return nil
}
