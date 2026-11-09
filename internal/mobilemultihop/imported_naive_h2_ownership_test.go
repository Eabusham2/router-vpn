package mobilemultihop

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestImportedNaiveH2EntryCipherKeys(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size)))
		for _, layer := range importedPQLayers {
			for _, candidate := range []struct {
				name, value string
				valid       bool
			}{
				{"original", key, true}, {"malformed", "invalid-key", false}, {"empty", "", false},
				{"short", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size-1))), false},
				{"long", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", size+1))), false},
				{"identity-chain", key + ":" + key, method != "2022-blake3-chacha20-poly1305"},
				{"empty-identity", key + ":", false},
			} {
				t.Run(method+"/"+layer+"/"+candidate.name, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, "shadowsocks", layer, "aes-256-gcm+xor-whitening")
					graph, capture := externalTestRead(t, source[0]), externalTestRead(t, source[1])
					transport := externalTestFind(t, graph, ExternalFinalTag)
					profile := capture["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)
					transport["method"], profile["method"] = method, method
					transport["password"], profile["password"] = candidate.value, candidate.value
					source[0], source[1] = externalTestJSON(t, graph), externalTestJSON(t, capture)
					plan, err := NewImportedEntry(source[0], source[1], source[2], source[3], source[4], source[5], source[6])
					if !candidate.valid {
						if err == nil || plan != nil {
							t.Fatal("imported Naive H2 accepted malformed selected SS2022 cipher key")
						}
						return
					}
					if err != nil {
						t.Fatal("valid original SS2022 identity was rejected", err)
					}
					entry := externalTestFind(t, importedPQGraph(t, plan.Config()), "entry-wg")
					if entry["method"] != method || entry["password"] != candidate.value {
						t.Fatal("H2 changed its original entry cipher or identity chain")
					}
				})
			}
		}
	}
}

// Attack the actual compiled dependency closure at the composition boundary.
// A valid final has two independent resolver trees; no layer may introduce a
// different endpoint, physical bypass, cycle or silently discarded query field.
func TestImportedNaiveH2RejectsChangedBootstrapClosure(t *testing.T) {
	for _, layer := range []string{"off", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"application-detour", "bootstrap-detour", "bootstrap-endpoint", "bootstrap-port", "bootstrap-server-name", "bootstrap-path", "bootstrap-query-option", "bootstrap-cycle", "bootstrap-duplicate", "bootstrap-extra", "bootstrap-removed", "final-resolver-server", "final-resolver-strategy", "physical-bootstrap", "unknown-bootstrap-key"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				source := importedNaiveH2Fixture(t, "https-connect", "aes-256-gcm", layer)
				importedNaiveH2HostnameDNS(t, source, "tcp")
				original, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				graph := importedPQGraph(t, original.Config())
				final := externalTestFind(t, graph, "proxy")
				if err := importedNaiveH2DNS(graph, final, false); err != nil {
					t.Fatal("unchanged captured Naive dependency closure was rejected", err)
				}
				dns := graph["dns"].(map[string]any)
				servers := dns["servers"].([]any)
				var application, lower, bootstrap map[string]any
				for _, raw := range servers {
					server := raw.(map[string]any)
					switch server["tag"] {
					case ExternalDNSTag:
						application = server
					case "routervpn-predecessor-bootstrap-0":
						lower = server
					case "routervpn-predecessor-bootstrap-1":
						bootstrap = server
					}
				}
				if application == nil || lower == nil || bootstrap == nil {
					t.Fatal("fixture omitted its original DNS dependency tree")
				}
				switch fault {
				case "application-detour":
					application["detour"] = "direct"
				case "bootstrap-detour":
					lower["detour"] = "foreign-entry"
				case "bootstrap-endpoint":
					bootstrap["server"] = "192.0.2.155"
				case "bootstrap-port":
					bootstrap["server_port"] = float64(53)
				case "bootstrap-server-name":
					lower["tls"].(map[string]any)["server_name"] = "foreign.example.test"
				case "bootstrap-path":
					lower["path"] = "/different-query"
				case "bootstrap-query-option":
					delete(lower["domain_resolver"].(map[string]any), "disable_cache")
				case "bootstrap-cycle":
					lower["domain_resolver"].(map[string]any)["server"] = lower["tag"]
				case "bootstrap-duplicate":
					bootstrap["tag"] = lower["tag"]
				case "bootstrap-extra":
					dns["servers"] = append(servers, predecessorCopy(bootstrap))
				case "bootstrap-removed":
					dns["servers"] = servers[:3]
				case "final-resolver-server":
					final["domain_resolver"].(map[string]any)["server"] = ExternalDNSTag
				case "final-resolver-strategy":
					final["domain_resolver"].(map[string]any)["strategy"] = "ipv6_only"
				case "physical-bootstrap":
					bootstrap["detour"] = "direct"
				case "unknown-bootstrap-key":
					bootstrap["fallback"] = "system"
				}
				if err := importedNaiveH2DNS(graph, final, false); err == nil {
					t.Fatal("changed bootstrap authority was accepted", fault)
				}
			})
		}
	}
}

func TestImportedNaiveH2RetainsSealedOriginalLaunch(t *testing.T) {
	for _, kind := range importedPQKinds {
		for _, first := range importedPQLayers {
			for _, last := range importedPQLayers {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					source := importedNaiveH2Fixture(t, kind, first, last)
					original := importedNaiveH2Compile(t, source)
					checkImportedLaunchRoundTrip(t, original, source)
					protected := desktopImportedOriginal(t, source, "always")
					policy := desktopImportedPlan(t, protected, desktopNodeTestSession, 1392)
					assertDesktopImportedExactDerivation(t, policy)
					_, meta, capture, err := policy.ReadValidated()
					if err != nil || meta.ExitMode != "naive-h2" || meta.RestoredMTU != 1392 || meta.KillSwitchPolicy != "always" || meta.SOCKSUDPAssociationRequired || capture.SelectedDNS.Physical {
						t.Fatal("sealed H2 derivation changed final transport, protection, restored MTU or physical scope", err)
					}
				})
			}
		}
	}
}
