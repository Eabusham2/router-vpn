package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestExternalEntryProofOwnsOriginalPhysicalTransport(t *testing.T) {
	for _, entry := range []string{"shadowsocks", "wireguard", "amneziawg", "hysteria2"} {
		t.Run(entry, func(t *testing.T) {
			fixtureEntry := entry
			if entry == "amneziawg" {
				fixtureEntry = "wireguard"
			}
			graph, selection := externalTestFixture(t, "hysteria2", fixtureEntry)
			if entry == "amneziawg" {
				parameters := map[string]any{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32", "h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
				endpoint := externalTestFind(t, graph, "external-entry")
				endpoint["type"], endpoint["amnezia"] = AmneziaType, parameters
				external := selection["entry"].(map[string]any)["external"].(map[string]any)
				imported := external["wireguard"].(map[string]any)
				imported["parameters"] = parameters
				external["protocol"], external["amneziawg"] = "amneziawg", imported
				delete(external, "wireguard")
			}
			selection["profile"].(map[string]any)["kill_switch_policy"] = "always"
			original := externalDesktopCompile(t, graph, selection)
			root := externalTestFind(t, graph, "external-entry")
			host, port := root["server"], root["server_port"]
			if entry == "wireguard" || entry == "amneziawg" {
				peer := root["peers"].([]any)[0].(map[string]any)
				host, port = peer["address"], peer["port"]
			}
			networks := []string{"udp"}
			if entry == "shadowsocks" {
				networks = []string{"tcp", "udp"}
			}
			want := make([]PhysicalEgress, 0, len(networks))
			for _, network := range networks {
				want = append(want, PhysicalEgress{host.(string), int(port.(float64)), network})
			}
			actual, err := original.PhysicalEgress()
			if err != nil || !reflect.DeepEqual(actual, want) {
				t.Fatal("entry proof lost exact physical transport or leaked final", actual, want, err)
			}
			capture, err := original.DesktopCapture()
			if err != nil || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != "external-entry" || !reflect.DeepEqual(capture.PhysicalRoots[0].Networks, networks) || !reflect.DeepEqual(capture.PhysicalRoots[0].Destinations, want) || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != ExternalFinalTag {
				t.Fatal("desktop capture replaced independent entry/final DNS ownership", err)
			}
			if entry == "shadowsocks" {
				policy, err := NewDesktopExternalPolicy(original, desktopExternalTestSession, "windows")
				if err != nil || policy.Validate() != nil {
					t.Fatal("Windows SS HY2 lost required entry TCP proof intent", err)
				}
				derived, err := policy.Capture()
				if err != nil || !reflect.DeepEqual(derived.PhysicalRoots[0].Destinations, want) {
					t.Fatal("native capture changed original proof authority", err)
				}
			}
		})
	}
}

func TestExternalEntryProofDoesNotAddDirectTCPAuthority(t *testing.T) {
	graph, selection := externalTestFixture(t, "hysteria2", "")
	original := externalDesktopCompile(t, graph, selection)
	tuples, err := original.PhysicalEgress()
	if err != nil || len(tuples) != 1 || tuples[0].Network != "udp" {
		t.Fatal("direct HY2 acquired unrequested entry proof transport", tuples, err)
	}
	capture, err := original.DesktopCapture()
	if err != nil || len(capture.PhysicalRoots) != 1 || !reflect.DeepEqual(capture.PhysicalRoots[0].Networks, []string{"udp"}) {
		t.Fatal("direct native capture invented entry TCP", err)
	}
}
