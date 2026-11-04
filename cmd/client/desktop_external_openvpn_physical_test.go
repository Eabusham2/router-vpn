package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

func desktopRetainedOpenVPNFixture(t *testing.T, network, kill string) (common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	first, second := network, network
	if network == "mixed" {
		first, second = "tcp", "udp"
	}
	config := "# exact original OpenVPN import\r\nclient\ndev tun\n"
	for _, remote := range []nativeopenvpn.Remote{{Host: "203.0.113.20", Port: 1194, Network: first}, {Host: "203.0.113.21", Port: 443, Network: second}} {
		config += fmt.Sprintf("remote %s %d %s\n", remote.Host, remote.Port, remote.Network)
	}
	config += "auth-user-pass\nremote-cert-tls server\nverify-x509-name captured-provider.example name\npeer-fingerprint " + strings.Repeat("ab", 32) + "\ntun-mtu 1500\nmssfix 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
	profile, err := externalProfileFromCreateRequest(externalProfileCreateRequest{Name: "Captured direct OpenVPN", Protocol: "openvpn", ExpectedPublicIP: "203.0.113.88", StartLayer: common.StartLayerOff,
		OpenVPN: &nativeopenvpn.Profile{Config: config, Username: " captured user ", Password: " captured password "}})
	if err != nil {
		t.Fatal(err)
	}
	profile.KillSwitchPolicy, profile.KillSwitch, profile.IPv6Mode, profile.HomeLANAccess = kill, kill != "off", "on", true
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "https", "203.0.113.53", 5443
	profile.DNSServerName, profile.DNSPath = "selected.resolver.example", "/captured/query"
	profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU, profile.MultihopExecution = "manual", 1360, 9000, "local"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, launch
}

func TestDesktopExternalPhysicalOpenVPNKeepsOriginalProfileAndDerivedMailboxes(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, network := range []string{"tcp", "udp", "mixed"} {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(target+"/"+network+"/"+kill, func(t *testing.T) {
					profile, launch := desktopRetainedOpenVPNFixture(t, network, kill)
					owner := launch.external
					saved, _ := json.Marshal(profile)
					source, capture, config, expected := bytes.Clone(owner.source), bytes.Clone(owner.capture), bytes.Clone(launch.config), owner.expected
					if owner.selection != "local" || !owner.direct || owner.predecessor != "" || owner.profile.External.ResponseProbe != nil || owner.profile.External.OpenVPNResponseProbes != nil || owner.profile.External.OpenVPNPairing != nil {
						t.Fatal("direct import fabricated comparison or predecessor authority")
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil || owner.physical == nil {
						t.Fatal("direct Local OpenVPN did not acquire captured native transport", err)
					}
					meta, err := capturedDesktopExternalPhysical(owner)
					if err != nil || meta == nil || meta.TargetOS != target || meta.Protocol != "openvpn" || meta.RootType != "openvpn-client" || meta.KillSwitchPolicy != kill || meta.IPv6Mode != "on" || !meta.HomeLANAccess || meta.SOCKSUDPAssociationRequired ||
						owner.expected != expected || !bytes.Equal(source, owner.source) || !bytes.Equal(capture, owner.capture) ||
						meta.OriginalSourceSHA256 != expected.SourceSHA256 || meta.OriginalConfigSHA256 != expected.ConfigSHA256 ||
						string(config) != owner.physical.OriginalPolicy().Config() || string(launch.config) != owner.physical.Config() {
						t.Fatal("OpenVPN physical preparation changed original source/proof identity", meta, err)
					}
					after, _ := json.Marshal(profile)
					if !bytes.Equal(saved, after) || !reflect.DeepEqual(owner.profile.External.OpenVPN, profile.External.OpenVPN) {
						t.Fatal("OpenVPN changed saved source text or credentials")
					}
					physical, err := owner.physical.Capture()
					if err != nil || physical.ConfiguredMTU != 1360 || physical.SelectedDNS.Physical || len(physical.PhysicalRoots) != 1 || len(physical.PhysicalRoots[0].Destinations) != 2 {
						t.Fatal("OpenVPN lost selected MTU/DNS or exact tuple count", err)
					}
					var graph map[string]any
					if json.Unmarshal(launch.config, &graph) != nil {
						t.Fatal("invalid derived graph")
					}
					endpoint := taggedRuntimeItem(graph["endpoints"].([]any), mobilemultihop.ExternalFinalTag)
					remotes, err := nativeopenvpn.Remotes(endpoint)
					if err != nil || len(remotes) != 2 || remotes[0].Host != "203.0.113.20" || remotes[0].Port != 1194 || remotes[1].Host != "203.0.113.21" || remotes[1].Port != 443 {
						t.Fatal("native endpoint collapsed the ordered remotes", remotes, err)
					}
					first, second := network, network
					if network == "mixed" {
						first, second = "tcp", "udp"
					}
					if remotes[0].Network != first || remotes[1].Network != second {
						t.Fatal("OpenVPN provider networks crossed captured remote addresses")
					}
					measurement, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil || measurement.source != meta.SourceSHA256 || measurement.config != meta.ConfigSHA256 || measurement.node != expected.ExitID || measurement.session != expected.SessionID {
						t.Fatal("OpenVPN MTU/measurement mailbox adopted original graph identity", err)
					}
					resolver, err := capturedDesktopDNSRuntime(launch)
					if err != nil || resolver.source != meta.SourceSHA256 || resolver.config != meta.ConfigSHA256 || resolver.node != expected.ExitID {
						t.Fatal("OpenVPN DNS mailbox adopted another physical owner", err)
					}
					selected, _, _, err := desktopDNSExpectedEndpoints(launch)
					if err != nil || selected.Address != profile.DNSHost || selected.Port != profile.DNSPort || selected.Transport != profile.DNSProtocol {
						t.Fatal("OpenVPN selected resolver was substituted", selected, err)
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, target); err == nil {
						t.Fatal("a repeated preparation replaced the captured native owner")
					}
				})
			}
		}
	}
}

func TestDesktopExternalPhysicalOpenVPNKeepsUnsupportedTargetAndCaptureGuards(t *testing.T) {
	for _, target := range []string{"android", "unknown", ""} {
		t.Run(target, func(t *testing.T) {
			_, launch := desktopRetainedOpenVPNFixture(t, "mixed", "always")
			config, metadata := bytes.Clone(launch.config), bytes.Clone(launch.metadata)
			if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil || launch.external.physical != nil || !bytes.Equal(config, launch.config) || !bytes.Equal(metadata, launch.metadata) {
				t.Fatal("OpenVPN extended an unsupported target or rewrote legacy capture", target, err)
			}
		})
	}
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, fault := range []string{"off", "predecessor", "not-direct", "graph", "metadata", "source", "session", "proof-source", "proof-config"} {
			t.Run(target+"/"+fault, func(t *testing.T) {
				kill := "always"
				if fault == "off" {
					kill = "off"
				}
				_, launch := desktopRetainedOpenVPNFixture(t, "mixed", kill)
				switch fault {
				case "predecessor":
					launch.external.predecessor = "captured-predecessor"
				case "not-direct":
					launch.external.direct = false
				case "graph":
					launch.config = []byte(`{}`)
				case "metadata":
					launch.metadata = []byte(`{}`)
				case "source":
					launch.external.source = []byte(`{}`)
				case "session":
					launch.external.session = strings.Repeat("f", 32)
				case "proof-source":
					launch.external.expected.SourceSHA256 = strings.Repeat("f", 64)
				case "proof-config":
					launch.external.expected.ConfigSHA256 = strings.Repeat("f", 64)
				}
				config, metadata := bytes.Clone(launch.config), bytes.Clone(launch.metadata)
				err := prepareDesktopExternalPhysicalCaptured(launch, target)
				ineligible := fault == "off" || fault == "predecessor" || fault == "not-direct"
				if (err == nil) != ineligible || launch.external.physical != nil || !bytes.Equal(config, launch.config) || !bytes.Equal(metadata, launch.metadata) {
					t.Fatal("invalid OpenVPN capture acquired or replaced physical authority", fault, err)
				}
			})
		}
	}
}
