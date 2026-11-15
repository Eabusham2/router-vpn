//go:build routervpn_controller_privileged

package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

// The installed observer reads the derived host graph. NewDesktopExternalPolicy
// inserts the captured physical broker as a top-level detour on the original
// OpenVPN endpoint; CompileProfile's unbound original is not that host graph.
func macOSExternalNativeOpenVPNSS2022Graph(config, tag string, remotes []nativeopenvpn.Remote) error {
	var graph struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal([]byte(config), &graph) != nil || len(graph.Endpoints) != 1 {
		return errors.New("OpenVPN entry changed endpoint inventory")
	}
	actual := graph.Endpoints[0]
	actualRemotes, err := nativeopenvpn.Remotes(actual)
	if actual["tag"] != tag || actual["type"] != "openvpn-client" || actual["detour"] != mobilemultihop.DesktopExternalPhysicalTag || actual["dialer"] != nil || err != nil || !reflect.DeepEqual(actualRemotes, remotes) {
		return errors.New("OpenVPN entry acquired another endpoint route")
	}
	return nil
}

func TestMacOSOpenVPNEntryObservationUsesActualDerivedPhysicalDetour(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			_, entry, launch := desktopExternalOpenVPNEntryFixture(t, network)
			if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
				t.Fatal(err)
			}
			policy := launch.external.physical
			if policy == nil || policy.Validate() != nil {
				t.Fatal("fixture omitted actual adapted policy")
			}
			capture, err := policy.Capture()
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := nativeopenvpn.CompileProfile(*entry.External.OpenVPN, capture.EntryTag, "")
			if err != nil {
				t.Fatal(err)
			}
			remotes, err := nativeopenvpn.Remotes(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if err := macOSExternalNativeOpenVPNSS2022Graph(policy.Config(), capture.EntryTag, remotes); err != nil {
				t.Fatal("actual adapted physical endpoint rejected", err)
			}
			for _, fault := range []string{"missing", "empty", "direct", "foreign", "nested-only", "nested-foreign"} {
				t.Run(fault, func(t *testing.T) {
					var graph map[string]any
					if json.Unmarshal([]byte(policy.Config()), &graph) != nil {
						t.Fatal("actual adapted graph unreadable")
					}
					actual := graph["endpoints"].([]any)[0].(map[string]any)
					switch fault {
					case "missing":
						delete(actual, "detour")
					case "empty":
						actual["detour"] = ""
					case "direct":
						actual["detour"] = "direct"
					case "foreign":
						actual["detour"] = "foreign-egress"
					case "nested-only":
						delete(actual, "detour")
						actual["dialer"] = map[string]any{"detour": mobilemultihop.DesktopExternalPhysicalTag}
					case "nested-foreign":
						actual["dialer"] = map[string]any{"detour": "foreign-egress"}
					}
					raw, err := json.Marshal(graph)
					if err != nil {
						t.Fatal(err)
					}
					if macOSExternalNativeOpenVPNSS2022Graph(string(raw), capture.EntryTag, remotes) == nil {
						t.Fatal("changed physical detour acquired native observation", fault)
					}
				})
			}
		})
	}
}
