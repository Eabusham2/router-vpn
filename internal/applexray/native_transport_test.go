package applexray

import (
	"strings"
	"testing"
)

func TestSingleTransportCannotLoseSecurityOrHideHelpers(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		out := map[string]any{"type": Type, "tag": "exit", "mode": mode, "config_json": string(sampleConfig(mode))}
		if e := ValidateSingleTransport(out, mode); e != nil {
			t.Fatal(e)
		}
		for _, key := range []string{"detour", "domain_resolver", "bind_interface", "server", "certificate_path", "private_key", "network"} {
			out[key] = "unowned"
			if e := ValidateSingleTransport(out, mode); e == nil {
				t.Fatal("extra dial owner accepted", key)
			}
			delete(out, key)
		}
		for _, tag := range []any{"../exit", "", true, nil} {
			out["tag"] = tag
			if e := ValidateSingleTransport(out, mode); e == nil {
				t.Fatal("invalid tag accepted")
			}
		}
		out["tag"] = "exit"
		out["config_json"] = `{"private":"secret-never-echo"}`
		if e := ValidateSingleTransport(out, mode); e == nil || strings.Contains(e.Error(), "secret-never-echo") {
			t.Fatal("bad private configuration diagnostic")
		}
	}
	for _, mode := range []string{"split", "max", "tor", "direct", "all"} {
		if SingleTransportMode(mode) {
			t.Fatal("multiple or unimplemented transports collapsed")
		}
	}
}
