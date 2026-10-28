package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopDirectBridgeLines(count int) []string {
	lines := make([]string, count)
	for i := range lines {
		endpoint := fmt.Sprintf("203.0.113.%d:%d", 60+i, 8443+i)
		if i%2 == 1 {
			endpoint = fmt.Sprintf("[2001:db8::%x]:%d", 60+i, 8443+i)
		}
		lines[i] = strings.Replace(clientTorBridge, "203.0.113.44:443", endpoint, 1)
	}
	return lines
}

func TestDesktopTorDirectFixedSetUsesActualConnectAndOwnedShutdown(t *testing.T) {
	for _, count := range []int{1, 2, 8} {
		for _, transport := range []string{"obfs4", "custom"} {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, transport, kill), func(t *testing.T) {
					f := newDesktopTorConnectFixture(t)
					f.unified = true
					profile := &f.a.profiles.Profiles[0]
					profile.External.TorBridge.Transport, profile.External.TorBridge.Bridges = transport, desktopDirectBridgeLines(count)
					profile.KillSwitch, profile.KillSwitchPolicy = true, kill
					entry := cloneRouterProfile(f.a.profiles.Profiles[1])
					source := cloneRouterProfile(*profile)
					direct := true
					reply := f.request(t, externalProfileConnectRequest{ProfileID: profile.ID, Direct: &direct})
					if reply.Code != http.StatusOK || f.launch == nil || f.launch.tor.predecessor != nil || f.launch.tor.expected.KillSwitchPolicy != kill || !f.a.state.Connected {
						t.Fatal("fixed set did not reach actual Direct controller admission", reply.Code, reply.Body.String())
					}
					var staged struct {
						Egress []mobilemultihop.PhysicalEgress `json:"desktop_physical_egress"`
					}
					raw, err := readDesktopRuntimeFile(f.launch, "tor-profile.json", desktopTorInputLimit("tor-profile.json"))
					if err != nil || json.Unmarshal(raw, &staged) != nil || len(staged.Egress) != count {
						t.Fatal("actual staging lost part of the fixed set", err)
					}
					for i, row := range staged.Egress {
						if row.Network != "tcp" || row.Port != 8443+i || row.Host == source.DNSHost || row.Host == entry.Endpoint {
							t.Fatal("fixed set opened UDP, selected DNS, an entry, or another port", row)
						}
					}
					if !reflect.DeepEqual(f.a.profiles.Profiles[0].External, source.External) || !reflect.DeepEqual(f.a.profiles.Profiles[1], entry) ||
						f.a.profiles.Profiles[0].MultihopEnabled || f.a.profiles.Profiles[0].MultihopEntryID != "" || f.a.profiles.Profiles[0].DNSHost != source.DNSHost {
						t.Fatal("Direct connection changed credentials, DNS, or the other private node")
					}
					saved, _ := json.Marshal(f.a.profiles)
					if strings.Contains(string(saved), "desktop_physical_egress") {
						t.Fatal("runtime authority entered the durable profile schema")
					}
					if err := f.a.stopModeWithIntent(true); err != nil {
						t.Fatal("fixed set failed owned shutdown", err)
					}
					if _, present := desktopNodeOwners.Load(f.a); present || !desktopNodeProcessExited(f.launch) {
						t.Fatal("fixed set shutdown retained a native process owner")
					}
				})
			}
		}
	}
}

func TestDesktopTorDirectFixedSourceIsImmutableAfterStaging(t *testing.T) {
	for _, fault := range []string{"later-bridge", "later-port", "credentials", "projection", "policy-id", "missing-source"} {
		t.Run(fault, func(t *testing.T) {
			a, prepared := desktopTorPreparedFixture(t, desktopDirectBridgeLines(2)...)
			launch := prepared.Launch
			before := cloneRouterProfileStore(a.profiles)
			path := filepath.Join(launch.directory, "tor-profile.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := string(raw)
			switch fault {
			case "later-bridge":
				changed = strings.Replace(changed, "2001:db8::3d", "2001:db8::99", 1)
			case "later-port":
				changed = strings.Replace(changed, ":8444", ":53", 1)
			case "credentials":
				changed = strings.Replace(changed, "cert=abcdefghijklmnopqrstuvwxyz", "cert=changedrelaycredentials", 1)
			case "projection":
				changed = strings.Replace(changed, `"network":"tcp"`, `"network":"udp"`, 1)
			case "policy-id":
				changed = strings.Replace(changed, `"id":"captured-tor"`, `"id":"other-tor"`, 1)
			case "missing-source":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if fault != "missing-source" {
				if changed == string(raw) {
					t.Fatal("source mutation did not change fixture", fault)
				}
				if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if environment, err := desktopTorLaunchEnvironment(nil, clientRoot(a), prepared); err == nil || environment != nil {
				t.Fatal("changed source acquired physical launch authority", fault)
			}
			if !reflect.DeepEqual(before, a.profiles) || launch.command != nil || a.state.Connected {
				t.Fatal("rejected source changed saved state or launched a process")
			}
		})
	}
}

func TestDesktopTorFixedImportPreservesBoundsAndDynamicRejections(t *testing.T) {
	for _, transport := range []string{"obfs4", "custom"} {
		for count := 1; count <= 8; count++ {
			p := existingTorImportProfile("direct-fixed")
			p.External.TorBridge.Transport, p.External.TorBridge.Bridges = transport, desktopDirectBridgeLines(count)
			p.KillSwitchPolicy = "always"
			got, err := normalizeTorBridgeImportPolicy(p)
			if err != nil || got.KillSwitchPolicy != "always" || !got.KillSwitch || len(got.External.TorBridge.Bridges) != count {
				t.Fatal("fixed import lost requested strict policy", transport, count, err)
			}
		}
	}
	for _, lines := range [][]string{{clientMeekBridge}, {clientSnowflakeBridge}, {clientWebTunnelBridge}, {clientTorBridge, clientMeekBridge}, {clientTorBridge, clientSnowflakeBridge}, {clientTorBridge, clientWebTunnelBridge}} {
		p := existingTorImportProfile("dynamic-direct")
		p.External.TorBridge.Transport, p.External.TorBridge.Bridges, p.KillSwitchPolicy = "custom", append([]string(nil), lines...), "always"
		if _, err := normalizeTorBridgeImportPolicy(p); err == nil {
			t.Fatal("dynamic source gained fixed Direct authority", lines)
		}
	}
}
