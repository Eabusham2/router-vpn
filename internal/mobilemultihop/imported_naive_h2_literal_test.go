package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func TestImportedNaiveH2CONNECTLiteralHomeUDP(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		for _, first := range importedPQLayers {
			t.Run(kind+"/"+first, func(t *testing.T) {
				source := importedNaiveH2Fixture(t, kind, first, "off")
				profile := externalTestRead(t, source[4])
				delete(profile, "dns_protocol")
				profile["kill_switch_policy"] = "on-connect"
				source[4] = externalTestJSON(t, profile)
				original := append([]string(nil), source...)
				plan := importedNaiveH2Compile(t, source)
				defer plan.Close()
				node, err := NewNodeProfile(source[2], source[3], source[4], source[5], source[6])
				if err != nil {
					t.Fatal(err)
				}
				graph, prior := importedPQGraph(t, plan.Config()), importedPQGraph(t, node.Config())
				rows, previous := graph["dns"].(map[string]any)["servers"].([]any), prior["dns"].(map[string]any)["servers"].([]any)
				if len(rows) != 2 || len(previous) != 2 || !reflect.DeepEqual(rows[0], previous[0]) {
					t.Fatal("literal H2 changed selected DNS closure")
				}
				selected := rows[0].(map[string]any)
				if selected["type"] != "udp" || selected["server"] != profile["adguard_ipv4"] || selected["server_port"] != float64(53) || selected["detour"] != "proxy" {
					t.Fatal("default Home UDP lost final ownership", selected)
				}
				lower := predecessorCopy(rows[1].(map[string]any))
				if lower["detour"] != "entry-wg" {
					t.Fatal("bootstrap gained another lower owner")
				}
				delete(lower, "detour")
				if !reflect.DeepEqual(lower, previous[1]) {
					t.Fatal("literal H2 replaced or removed its original bootstrap")
				}
				final := predecessorCopy(externalTestFind(t, graph, LocalTag))
				final["tag"] = "proxy"
				delete(final, "detour")
				if !reflect.DeepEqual(final, externalTestFind(t, prior, "proxy")) || !reflect.DeepEqual(source, original) || plan.Healthy() {
					t.Fatal("literal admission changed source, credentials, TLS or invented proof")
				}
				capture, err := plan.ImportedDesktopCapture()
				if err != nil || !capture.UDPAvailable || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical || len(capture.BootstrapDNS) != 1 {
					t.Fatal("literal H2 lost captured final and bootstrap ownership", err)
				}
				if len(capture.PhysicalRoots) != 1 || capture.BootstrapDNS[0].Physical {
					t.Fatal("dormant resolver gained physical socket authority")
				}
				for _, destination := range capture.PhysicalRoots[0].Destinations {
					if destination.Network != "tcp" {
						t.Fatal("CONNECT gained lower UDP authority", destination)
					}
				}
				policy, err := NewDesktopImportedPolicy(plan, desktopNodeTestSession, "windows")
				if err != nil {
					t.Fatal("captured Home DNS graph lost protected policy", err)
				}
				assertDesktopImportedExactDerivation(t, policy)
				for _, fault := range []string{"hostname", "wrong-resolver", "missing-resolver", "foreign-lower"} {
					t.Run(fault, func(t *testing.T) {
						changed := predecessorCopy(prior)
						f := externalTestFind(t, changed, "proxy")
						switch fault {
						case "hostname":
							f["server"] = "foreign.invalid"
						case "wrong-resolver":
							f["domain_resolver"] = map[string]any{"server": "foreign"}
						case "missing-resolver":
							delete(f, "domain_resolver")
						case "foreign-lower":
							changed["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)["detour"] = "direct"
						}
						if err := importedNaiveH2DNS(changed, f, false); err == nil {
							t.Fatal("literal exception admitted changed original owner", fault)
						}
					})
				}
				plan.config = strings.Replace(plan.config, "routervpn-predecessor-bootstrap-0", "foreign-bootstrap", 1)
				if _, err := plan.ImportedDesktopCapture(); err == nil {
					t.Fatal("mutated retained graph kept source authority")
				}
			})
		}
	}
}
