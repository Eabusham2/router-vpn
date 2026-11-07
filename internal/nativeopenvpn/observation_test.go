package nativeopenvpn

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPacketObservationRequiresExactLiveShape(t *testing.T) {
	original := PacketObservation{Remote: RemoteReceipt{Remote: Remote{Host: "203.0.113.24", Port: 1194, Network: "udp"}, Generation: 2, ConnectedAt: 1700000000000}, MTU: 1420}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PacketObservation
	if json.Unmarshal(raw, &decoded) != nil || decoded != original {
		t.Fatal("original native observation lost", string(raw))
	}
	for _, body := range []string{
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":1279`, 1),
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":65536`, 1),
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":1420.5`, 1),
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":null`, 1),
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":1420,"entry_mtu":1420`, 1),
		strings.Replace(string(raw), `"entry_mtu":1420`, `"entry_mtu":1420,"saved":true`, 1),
		strings.Replace(string(raw), `"generation":2`, `"generation":0`, 1),
		strings.Replace(string(raw), `"host":"203.0.113.24"`, `"host":"127.0.0.1"`, 1),
		strings.Replace(string(raw), `"connected_at":1700000000000`, `"connected_at":null`, 1),
		`{}`, `null`,
	} {
		actual := original
		if json.Unmarshal([]byte(body), &actual) == nil || actual != original {
			t.Fatal("invalid observation admitted or overwrote original", body, actual)
		}
	}
}
