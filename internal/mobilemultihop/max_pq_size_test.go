package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func TestCompleteMAXPrivateCopyRetainsNativeSizedPQKeys(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			base, outs, node := compiledMAXBoundary(t, mode, "off", "10.77.0.1")
			pq := base["pq"].(map[string]any)
			// Match the pinned StaticKem serialization size. Actual cryptography
			// is exercised by the separately required native PQ traffic gate.
			pq["secret"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'s'}, 13608))
			pq["public"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 524160))
			pq["peer"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'r'}, 524160))
			before, _ := json.Marshal([]any{base, outs})
			paired, err := multihoprelay.PairMAXChain(base, outs, mode, node, canonicalMAXTags())
			if err != nil || len(paired) <= 1<<20 || len(paired) >= 4<<20 {
				t.Fatal("native-sized complete chain failed private pairing", err)
			}
			var plan map[string]any
			if json.Unmarshal(paired, &plan) != nil {
				t.Fatal("invalid paired chain")
			}
			exit := multihoprelay.Exit{Mode: mode, NodeID: node, DNS: "10.88.0.1", Transport: plan}
			encoded, err := multihoprelay.Build(exit, netip.MustParseAddr("10.77.0.2"), multihoprelay.Lease{Host: "10.77.0.1", Port: 26240, Username: "user", Password: "private"})
			if err != nil {
				t.Fatal("native-sized complete chain failed relay build", err)
			}
			var graph map[string]any
			if json.Unmarshal(encoded, &graph) != nil {
				t.Fatal("invalid relay graph")
			}
			endpoint := graph["endpoints"].([]any)[0].(map[string]any)
			outputs := graph["outbounds"].([]any)
			restored, restoredOut, err := multihoprelay.RelabelMAXChain(endpoint, outputs, mode, node, "", multihoprelay.MAXRelayTags(), canonicalMAXTags(), "", "")
			if err != nil || !reflect.DeepEqual(restored, base) || !reflect.DeepEqual(restoredOut, outs) {
				t.Fatal("relabel changed native key bytes or chain ownership", err)
			}
			restored["pq"].(map[string]any)["secret"] = "changed"
			after, _ := json.Marshal([]any{base, outs})
			if !bytes.Equal(before, after) {
				t.Fatal("private MAX copy aliased the original source")
			}
			// All individual keys remain valid under their native bound while
			// this complete chain exceeds its unchanged private 4 MiB bound.
			pq["public"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 1600<<10))
			pq["peer"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'r'}, 1600<<10))
			if _, err = multihoprelay.PairMAXChain(base, outs, mode, node, canonicalMAXTags()); err == nil {
				t.Fatal("complete MAX private bound widened")
			}
			if _, _, err = multihoprelay.RelabelMAXChain(base, outs, mode, node, "", canonicalMAXTags(), multihoprelay.MAXRelayTags(), "", ""); err == nil {
				t.Fatal("relabel bypassed the complete MAX private bound")
			}
		})
	}
}
