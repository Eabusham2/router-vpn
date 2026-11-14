package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopCONNECTCandidateSource(t *testing.T, protocol, host string) common.RouterProfile {
	t.Helper()
	request := createRequestFor(protocol)
	request.Server = host
	profile, err := externalProfileFromCreateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	profile.ID, profile.Name, profile.StartLayer = "connect-candidate", "Captured CONNECT", "off"
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "10.85.0.53", 5353
	return profile
}

func TestDesktopCONNECTCandidateCatalogPreservesCapturedSources(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, host := range []string{"203.0.113.40", "2001:db8::40"} {
				t.Run(mode+"/"+protocol+"/"+host, func(t *testing.T) {
					a, nodes := desktopNodeChainCaptureFixture(t, 3)
					installOrderedAWGAssets(t, a, nodes, []string{mode, mode, "shadowsocks"}, "off")
					for i := range a.profiles.Profiles {
						a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
					}
					control, _ := a.profileByIDLocked(a.profiles.SelectedID)
					selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
					if err != nil {
						t.Fatal(err)
					}
					selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
					if err != nil {
						t.Fatal(err)
					}
					launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "windows")
					if err != nil {
						t.Fatal(err)
					}
					profile := desktopCONNECTCandidateSource(t, protocol, host)
					a.profiles.Profiles = append(a.profiles.Profiles, profile)
					before, _ := json.Marshal(a.profiles)
					originalSource, originalConfig := launch.chain.input, string(launch.config)
					for _, position := range []int{0, 1} {
						catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, position, []string{profile.ID})
						if err != nil {
							t.Fatal("original CONNECT candidate rejected", err)
						}
						var inventory mobilemultihop.NodeChainCandidateInventory
						if err := json.Unmarshal([]byte(catalog.inventory), &inventory); err != nil || len(inventory.Inputs) != 1 {
							t.Fatal("candidate lost its complete private source", err)
						}
						var member struct{ Kind, Capture string }
						if err := json.Unmarshal([]byte(inventory.Inputs[0]), &member); err != nil || member.Kind != "routervpn-node-chain-connect-member" {
							t.Fatal("CONNECT candidate substituted an ordinary member", err)
						}
						var captured struct{ Profile common.RouterProfile }
						if err := json.Unmarshal([]byte(member.Capture), &captured); err != nil || !reflect.DeepEqual(captured.Profile.External, profile.External) ||
							captured.Profile.Endpoint != host || captured.Profile.DNSMode != "custom" || captured.Profile.DNSProtocol != "tcp" ||
							captured.Profile.DNSHost != profile.DNSHost || captured.Profile.DNSPort != 5353 || captured.Profile.StartLayer != "off" {
							t.Fatal("candidate changed credentials, TLS, endpoint or original DNS policy", err)
						}
						if len(catalog.assets) != 0 || len(catalog.files) != 0 || catalog.profiles[profile.ID] != publicProfileToken(profile) {
							t.Fatal("CONNECT candidate borrowed paired assets or lost its original profile")
						}
						for _, secret := range []string{"http-user", "http-secret", "https-user", "https-secret", host} {
							if strings.Contains(catalog.plan.Metadata(), secret) {
								t.Fatal("public candidate metadata exposed private source")
							}
						}
						row := desktopCandidateStatusFixture(t, catalog, profile.ID)
						if err := validateDesktopNodeChainCandidateStatus(catalog.plan, profile.ID, row, time.Now()); err != nil {
							t.Fatal("fifty TCP receipt rejected", err)
						}
						row.Results[0].Benchmark.Attempts = 49
						if validateDesktopNodeChainCandidateStatus(catalog.plan, profile.ID, row, time.Now()) == nil {
							t.Fatal("partial CONNECT candidate measurement accepted")
						}
					}
					after, _ := json.Marshal(a.profiles)
					if !bytes.Equal(before, after) || launch.chain.input != originalSource || string(launch.config) != originalConfig {
						t.Fatal("candidate source capture mutated the active path or private catalog")
					}
				})
			}
		}
	}
}

func TestDesktopCONNECTCandidateRejectsChangedOrUnownedSource(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, fault := range []string{"hostname", "endpoint", "zero-port", "layer", "paired-token", "paired-proof", "half-credential", "protocol-fields", "tls", "nil-caller", "cancelled", "aggregate"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				profile := desktopCONNECTCandidateSource(t, protocol, "203.0.113.40")
				proxy := profile.External.HTTPConnect
				if protocol == "https-connect" {
					proxy = profile.External.HTTPSConnect
				}
				ctx, total := context.Background(), 0
				switch fault {
				case "hostname":
					proxy.Host, profile.Endpoint = "uncaptured.invalid", "uncaptured.invalid"
				case "endpoint":
					profile.Endpoint = "203.0.113.41"
				case "zero-port":
					proxy.Port = 0
				case "layer":
					profile.StartLayer = "aes-256-gcm"
				case "paired-token":
					profile.APIToken = "borrowed-paired-token"
				case "paired-proof":
					profile.NodeProofID = strings.Repeat("b", 64)
				case "half-credential":
					proxy.Password = ""
				case "protocol-fields":
					if protocol == "https-connect" {
						profile.External.HTTPConnect = &common.ExternalHTTPConnectConfig{Host: profile.Endpoint, Port: 8080}
					} else {
						profile.External.HTTPSConnect = &common.ExternalHTTPConnectConfig{Host: profile.Endpoint, Port: 443, TLSServerName: "other.invalid"}
					}
				case "tls":
					if protocol == "https-connect" {
						proxy.TLSServerName = ""
					} else {
						proxy.TLSServerName = "foreign.invalid"
					}
				case "nil-caller":
					ctx = nil
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "aggregate":
					total = mobilemultihop.NodeChainInputLimit
				}
				capture := &desktopNodeChainCapture{}
				if input, err := capture.compileCandidateMember(ctx, profile, &total); err == nil || input != "" {
					t.Fatal("invalid CONNECT candidate acquired a source")
				} else if fault == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatal("candidate lost original cancellation", err)
				}
			})
		}
	}
}
