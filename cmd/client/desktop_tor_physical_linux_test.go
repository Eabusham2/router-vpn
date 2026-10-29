//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// The owned local IPC fixture supplies engine verification and proof. Actual
// HTTP selection, profile capture, shared compilation, immutable staging,
// native launch environment and checked shutdown are the shipping controller.
// The independent guardian tests exercise real kernel/firewall enforcement.
func TestDesktopTorPhysicalBrokerReachesCapturedConnectAndShutdown(t *testing.T) {
	for name, lines := range map[string][]string{"plain": nil, "meek": {clientMeekBridge}, "snowflake": {clientSnowflakeBridge},
		"webtunnel": {clientWebTunnelBridge}, "mixed": {clientTorBridge, clientMeekBridge, clientSnowflakeBridge, clientWebTunnelBridge}} {
		for _, kill := range []string{"on-connect", "always"} {
			t.Run(name+"/"+kill, func(t *testing.T) {
				f := newDesktopTorConnectFixture(t)
				f.unified = true
				profile := &f.a.profiles.Profiles[0]
				if len(lines) == 0 {
					profile.External = &common.ExternalNodeConfig{Protocol: "tor"}
				} else {
					profile.External.TorBridge.Transport, profile.External.TorBridge.Bridges = "custom", append([]string(nil), lines...)
				}
				profile.KillSwitch, profile.KillSwitchPolicy = true, kill
				before := cloneRouterProfile(*profile)
				entry := cloneRouterProfile(f.a.profiles.Profiles[1])
				command := f.driver.command
				// Stale inherited variables must not grant another runtime's
				// endpoint, UID-less tuple or previous session to this launch.
				t.Setenv("HOMEVPN_EXTERNAL_SESSION", strings.Repeat("f", 32))
				t.Setenv("HOMEVPN_NATIVE_EGRESS_JSON", `[{"host":"10.99.0.8","port":443,"network":"tcp"}]`)
				t.Setenv("HOMEVPN_NATIVE_ENDPOINTS_JSON", `["10.99.0.8"]`)
				t.Setenv("HOMEVPN_TOR_PHYSICAL_BROKER", "foreign")
				f.driver.command = func(a *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
					values := map[string]string{}
					for _, row := range environment {
						key, value, _ := strings.Cut(row, "=")
						values[key] = value
					}
					if prepared.BridgeEndpoint != "" || prepared.Launch.endpoint != "" || values["HOMEVPN_ENDPOINT"] != "" ||
						values["HOMEVPN_TOR_PHYSICAL_BROKER"] != "1" || values["HOMEVPN_EXTERNAL_SESSION"] != "" ||
						values["HOMEVPN_NATIVE_ENDPOINTS_JSON"] != "" || values["HOMEVPN_NATIVE_EGRESS_JSON"] != "" {
						t.Fatal("dynamic Direct handoff acquired an unowned endpoint exception", values)
					}
					return command(a, prepared, environment)
				}
				direct := true
				reply := f.request(t, externalProfileConnectRequest{ProfileID: profile.ID, Direct: &direct})
				if reply.Code != http.StatusOK || f.launch == nil || !f.a.state.Connected || !f.launch.tor.expected.PhysicalBroker || f.launch.tor.expected.KillSwitchPolicy != kill || f.launch.tor.predecessor != nil {
					t.Fatal("actual Connect did not retain its protected Linux Direct capture", reply.Code, reply.Body.String())
				}
				raw, err := readDesktopRuntimeFile(f.launch, "tor-profile.json", desktopTorInputLimit("tor-profile.json"))
				var staged map[string]any
				if err != nil || json.Unmarshal(raw, &staged) != nil || staged["desktop_physical_egress"] != nil || staged["kill_switch_policy"] != kill {
					t.Fatal("staged dynamic policy acquired fixed authority or changed protection", err)
				}
				if !reflect.DeepEqual(before.External, f.a.profiles.Profiles[0].External) || !reflect.DeepEqual(entry, f.a.profiles.Profiles[1]) || before.DNSHost != f.a.profiles.Profiles[0].DNSHost || before.DNSProtocol != f.a.profiles.Profiles[0].DNSProtocol {
					t.Fatal("Direct connect substituted transport credentials, selected DNS or another private node")
				}
				if err := f.a.stopModeWithIntent(true); err != nil {
					t.Fatal(err)
				}
				if _, present := desktopNodeOwners.Load(f.a); present || !desktopNodeProcessExited(f.launch) {
					t.Fatal("Direct shutdown released an unfinished owned native process")
				}
			})
		}
	}
}
