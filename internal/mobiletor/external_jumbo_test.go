package mobiletor

import (
	"encoding/json"
	"testing"
)

func TestMobileTorInheritsOrdinaryProxyJumboWithoutPacketExpansion(t *testing.T) {
	for _, protocol := range []string{"socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, mode := range []string{"auto", "default"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				exit, entry, graph := mobileExternalTorSelection(t, protocol)
				entry["jumbo_tun"], entry["mtu_policy"], exit["mtu_policy"] = true, mode, mode
				selected, predecessor, source := torHostEncode(t, exit), torHostEncode(t, entry), torHostEncode(t, graph)
				compiled, err := CompileProfileWithExternalPredecessor(selected, "ordinary-jumbo-owner", source, predecessor)
				if err != nil {
					t.Fatal("compatible ordinary entry Jumbo failed native composition", err)
				}
				owner, err := NewExternalPredecessorProof(predecessor, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, mtu, err := MTUInterface(compiled); err != nil || mtu != 9000 {
					t.Fatal("Tor discarded the captured proxy interface capacity", mtu, err)
				}
				authority, err := MTUAuthorityWithExternalPredecessor(compiled, selected, "ordinary-jumbo-owner", owner)
				var receipt map[string]any
				if err != nil || json.Unmarshal([]byte(authority), &receipt) != nil || receipt["jumbo_tun"] != true || receipt["mtu_policy"] != mode {
					t.Fatal("Tor MTU authority lost the original Jumbo policy", authority, err)
				}
				if selected != torHostEncode(t, exit) || predecessor != torHostEncode(t, entry) || source != torHostEncode(t, graph) {
					t.Fatal("Tor Jumbo changed the original source")
				}
			})
		}
	}
}
