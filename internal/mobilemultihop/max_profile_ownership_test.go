package mobilemultihop

import (
	"encoding/json"
	"router-vpn/internal/applexray"
	"testing"
)

// Check the complete native boundary, not only the mode label/config_json.
// Reusing the generator's SOCKS map retained server/server_port/version fields
// even after its type became routervpn-xray. The native decoder rejects them.
func TestMAXTLSCompilerDiscardsOnlyTheReplacedSOCKSWrapper(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg"} {
		t.Run(mode, func(t *testing.T) {
			files, metadata := maxFixture(t, mode)
			before := pqEncoded(files)
			encoded, err := CompileMAXProfile(mode, before, metadata)
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]any
			if err = json.Unmarshal([]byte(encoded), &root); err != nil {
				t.Fatal(err)
			}
			outbounds := root["outbounds"].([]any)
			if len(outbounds) != 2 {
				t.Fatal("required middle or outer transport missing")
			}
			outer := outbounds[1].(map[string]any)
			if err = applexray.ValidateSingleTransport(outer, "reality-xhttp"); err != nil {
				t.Fatal("compiled outer is not accepted by its native boundary", err)
			}
			for _, key := range []string{"server", "server_port", "version", "username", "password"} {
				if _, exists := outer[key]; exists {
					t.Fatal("old SOCKS field survived native composition", key)
				}
			}
			if outer["tag"] != MAXOuterTag || pqEncoded(files) != before {
				t.Fatal("route ownership or imported source changed")
			}
		})
	}
}
