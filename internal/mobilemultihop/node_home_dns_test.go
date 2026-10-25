package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestNodeHomeDNSAllRawFamiliesRetainEncryptedTransport(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, "")
				profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "home", protocol, profile["adguard_ipv4"], float64(5443)
				profile["dns_server_name"], profile["dns_path"] = "adguard.home.example", "/owned-query"
				compiled, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
				if err != nil {
					t.Fatal(err)
				}
				graph := startObject(t, compiled.Config())
				dns := graph["dns"].(map[string]any)
				servers := dns["servers"].([]any)
				selected := servers[0].(map[string]any)
				if dns["final"] != ExternalDNSTag || selected["detour"] != "proxy" || selected["type"] != protocol || selected["server"] != profile["adguard_ipv4"] || selected["server_port"] != float64(5443) {
					t.Fatal("native family changed Home resolver ownership", mode, selected)
				}
				if mode == "naive-h2" || mode == "naive-h3" {
					// Naive's captured resolver bootstrap is separate from final
					// application DNS so resolving its transport cannot recurse.
					if len(servers) != 2 {
						t.Fatal("Naive acquired an unrequested resolver")
					}
					bootstrap := servers[1].(map[string]any)
					var transport map[string]any
					for _, raw := range graph["outbounds"].([]any) {
						candidate := raw.(map[string]any)
						if candidate["type"] == "naive" {
							transport = candidate
						}
					}
					if transport == nil || transport["domain_resolver"].(map[string]any)["server"] != bootstrap["tag"] || bootstrap["detour"] != transport["detour"] {
						t.Fatal("Naive bootstrap lost its captured lower transport")
					}
					for key, value := range selected {
						if key != "tag" && key != "detour" && !reflect.DeepEqual(bootstrap[key], value) {
							t.Fatal("Naive bootstrap substituted Home policy", key)
						}
					}
				} else if len(servers) != 1 {
					t.Fatal("ordinary Router DNS acquired an unrequested resolver")
				}
				if protocol == "tls" || protocol == "https" || protocol == "h3" {
					if selected["tls"].(map[string]any)["server_name"] != "adguard.home.example" {
						t.Fatal("native Home TLS identity changed")
					}
				}
				if protocol == "https" || protocol == "h3" {
					if selected["path"] != "/owned-query" {
						t.Fatal("native Home HTTP path changed")
					}
				}
			})
		}
	}
}
