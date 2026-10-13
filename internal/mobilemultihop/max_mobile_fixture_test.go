package mobilemultihop

import (
	"encoding/json"
	"os"
	"testing"
)

// Export the real complete-chain compiler fixtures to host integration tests.
// These generated keys exercise configuration ownership, not KEM negotiation;
// native encrypted-traffic tests use independently generated real keys.
func TestExportMAXMobileProfiles(t *testing.T) {
	path := os.Getenv("ROUTERVPN_MAX_PROFILE_FIXTURES")
	if path == "" {
		t.Skip("fixture export is explicitly requested by the host test")
	}
	result := map[string]any{}
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		files, metadata := maxFixture(t, mode)
		compiled, err := CompileMAXProfile(mode, pqEncoded(files), metadata)
		if err != nil {
			t.Fatal(err)
		}
		var policy, graph map[string]any
		if err = json.Unmarshal([]byte(metadata), &policy); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal([]byte(compiled), &graph); err != nil {
			t.Fatal(err)
		}
		result[mode] = map[string]any{"files": files, "policy": policy, "graph": graph}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
