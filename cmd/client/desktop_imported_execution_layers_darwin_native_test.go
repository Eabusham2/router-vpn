//go:build darwin && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"testing"
)

type macOSImportedExecutionLayerCase struct{ Name, Mode, Entry, Final, Requested, Winner, Fault string }

var macOSImportedExecutionLayerCases = []macOSImportedExecutionLayerCase{
	{"awg2-fast-off-aes-auto-server", "awg2-fast", "off", "aes-256-gcm", "auto", "server", ""},
	{"awg2-strong-off-xor-auto-local", "awg2-strong", "off", "aes-256-gcm+xor-whitening", "auto", "local", ""},
	{"awg2-fast-aes-off-auto-local", "awg2-fast", "aes-256-gcm", "off", "auto", "local", ""},
	{"awg2-strong-aes-aes-server", "awg2-strong", "aes-256-gcm", "aes-256-gcm", "server", "server", ""},
	{"wg-aes-xor-auto-server", "wg", "aes-256-gcm", "aes-256-gcm+xor-whitening", "auto", "server", ""},
	{"awg2-strong-xor-off-auto-server", "awg2-strong", "aes-256-gcm+xor-whitening", "off", "auto", "server", ""},
	{"wg-xor-aes-auto-local", "wg", "aes-256-gcm+xor-whitening", "aes-256-gcm", "auto", "local", ""},
	{"awg2-fast-xor-xor-server", "awg2-fast", "aes-256-gcm+xor-whitening", "aes-256-gcm+xor-whitening", "server", "server", ""},
	{"wg-entry-aes-wrong-key", "wg", "aes-256-gcm", "off", "server", "server", "entry-layer-key"},
	{"awg2-fast-entry-xor-wrong-key", "awg2-fast", "aes-256-gcm+xor-whitening", "off", "server", "server", "entry-layer-key"},
	{"awg2-strong-entry-xor-wrong-whitening", "awg2-strong", "aes-256-gcm+xor-whitening", "off", "server", "server", "entry-whitening"},
	{"wg-final-aes-wrong-key", "wg", "off", "aes-256-gcm", "server", "server", "final-layer-key"},
	{"awg2-fast-final-xor-wrong-key", "awg2-fast", "off", "aes-256-gcm+xor-whitening", "server", "server", "final-layer-key"},
	{"awg2-strong-final-xor-wrong-whitening", "awg2-strong", "off", "aes-256-gcm+xor-whitening", "server", "server", "final-whitening"},
}

func macOSImportedExecutionLayerScenario(name string) (macOSImportedExecutionLayerCase, bool) {
	for _, c := range macOSImportedExecutionLayerCases {
		if c.Name == name {
			return c, true
		}
	}
	return macOSImportedExecutionLayerCase{}, false
}

type macOSImportedExecutionLayerObservation struct {
	Entry          string                       `json:"entry"`
	Final          string                       `json:"final"`
	EntryTransport *macOSExternalSSEntryReceipt `json:"entry_transport,omitempty"`
	FinalTransport *macOSExternalSSEntryReceipt `json:"final_transport"`
}

func macOSImportedExecutionInstallLayers(t *testing.T, p *macOSImportedExecutionPeer, store *common.RouterProfileStore) {
	t.Helper()
	if p.layers == nil {
		return
	}
	if len(store.Profiles) != 3 || p.layerObservation.Entry != p.layers.Entry || p.layerObservation.Final != p.layers.Final || p.layerObservation.FinalTransport == nil {
		t.Fatal("original independent layer source missing")
	}
	store.Profiles[0].StartLayer, store.Profiles[2].StartLayer = p.layers.Entry, p.layers.Final
	if p.layers.Entry == "off" {
		if p.layerObservation.EntryTransport != nil {
			t.Fatal("Off entry borrowed layer ownership")
		}
		return
	}
	outer := p.layerObservation.EntryTransport
	if outer == nil || outer.Method != "2022-blake3-aes-256-gcm" {
		t.Fatal("original packet layer missing")
	}
	address, err := netip.ParseAddrPort(outer.Address)
	if err != nil || address.Addr() != p.peer.physical || address.Port() == 0 || p.layers.Entry == "aes-256-gcm+xor-whitening" && address.Port() != 8389 {
		t.Fatal("packet layer changed captured physical endpoint", err)
	}
	directory := filepath.Join(macOSOwnedControllerRoot, "generated", store.Profiles[0].ID, "shadowsocks")
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": p.peer.physical.String(), "server_port": int(address.Port()), "method": "2022-blake3-aes-256-gcm", "password": p.entryPassword}}, "route": map[string]any{"final": "proxy"}})
	if err != nil || os.WriteFile(filepath.Join(directory, "sing-box.json"), graph, 0600) != nil {
		t.Fatal("original independent entry AES source not captured", err)
	}
}
func macOSImportedExecutionCheckLayers(t *testing.T, p *macOSImportedExecutionPeer, observed macOSNodeChainPeerReply, launches uint64, raw json.RawMessage) {
	t.Helper()
	c := p.layers
	var layers macOSImportedExecutionLayerObservation
	if c == nil || json.Unmarshal(raw, &layers) != nil || layers.Entry != c.Entry || layers.Final != c.Final || layers.FinalTransport == nil || len(observed.Prefixes) != 1 || observed.Prefixes[0].Mode != c.Mode || observed.Middle == nil {
		t.Fatal("independent layers lost original provider observations")
	}
	first := observed.Prefixes[0]
	last := layers.FinalTransport
	if last.Address != p.layerObservation.FinalTransport.Address || last.Method != "2022-blake3-aes-256-gcm" {
		t.Fatal("final layer replaced original paired listener")
	}
	if c.Entry == "off" {
		if layers.EntryTransport != nil {
			t.Fatal("Off entry invented layer provider")
		}
	} else {
		entry := layers.EntryTransport
		if entry == nil || entry.Address != p.layerObservation.EntryTransport.Address || entry.Method != "2022-blake3-aes-256-gcm" || entry.PhysicalUDP == 0 {
			t.Fatal("original independent entry ciphertext absent")
		}
		if c.Fault == "entry-layer-key" || c.Fault == "entry-whitening" {
			if entry.AuthUDP == 0 || entry.Packets != 0 || first.RawUDP != 0 || first.ProofQueries != 0 || launches != 0 || observed.Middle.TCP != 0 || observed.Final.RouterQueries != 0 || observed.Final.DNSQueries != 0 {
				t.Fatal("entry layer rejection missed original authentication boundary")
			}
			macOSImportedExecutionLogLayers(t, c, layers, observed, launches)
			return
		}
		if entry.Packets == 0 || entry.AuthUDP != 0 {
			t.Fatal("original entry layer failed decryption")
		}
	}
	if first.RawUDP == 0 || first.TCP == 0 || first.ProofQueries == 0 || launches == 0 || observed.Middle.TCP == 0 || observed.Middle.PublicQueries == 0 {
		t.Fatal("layered execution failed before original entry/middle/lease proof")
	}
	if c.Fault == "final-layer-key" || c.Fault == "final-whitening" {
		if last.PhysicalTCP == 0 || last.AuthTCP == 0 || last.Streams != 0 || observed.Final.RouterQueries != 0 || observed.Final.DNSQueries != 0 {
			t.Fatal("final layer rejection missed original authentication boundary")
		}
	} else if last.PhysicalTCP == 0 || last.Streams == 0 || last.AuthTCP != 0 || observed.Final.RouterQueries == 0 || observed.Final.DNSQueries == 0 {
		t.Fatal("layered final did not prove original private identity and DNS")
	}
	macOSImportedExecutionLogLayers(t, c, layers, observed, launches)
}
func macOSImportedExecutionLogLayers(t *testing.T, c *macOSImportedExecutionLayerCase, layers macOSImportedExecutionLayerObservation, observed macOSNodeChainPeerReply, launches uint64) {
	value, err := json.Marshal(map[string]any{"case": c.Name, "entry": c.Entry, "final": c.Final, "fault": c.Fault, "layers": layers, "launches": launches, "entry_packets": observed.Prefixes[0].RawUDP, "entry_proofs": observed.Prefixes[0].ProofQueries, "middle_public": observed.Middle.PublicQueries, "final_proofs": observed.Final.RouterQueries, "dns": observed.Final.DNSQueries})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DARWIN_IMPORTED_EXECUTION_LAYERS %s", value)
}
func TestMacOSImportedTrioExecutionLayersNative(t *testing.T) {
	for _, c := range macOSImportedExecutionLayerCases {
		t.Run(c.Name, func(t *testing.T) { macOSImportedExecutionNativeCase(t, c.Name) })
	}
}
