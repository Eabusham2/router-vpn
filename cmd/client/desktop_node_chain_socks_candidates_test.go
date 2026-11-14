package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestDesktopSOCKSCandidateKeepsTypedSourceAndReceipt(t *testing.T) {
	for _, target := range []string{"windows", "darwin", "linux"} {
		for _, host := range []string{"203.0.113.40", "2001:db8::40"} {
			for _, authenticated := range []bool{false, true} {
				name := target + "/" + host
				if authenticated {
					name += "/authenticated"
				} else {
					name += "/anonymous"
				}
				t.Run(name, func(t *testing.T) {
					a, launch := desktopNodeChainLaunchFixture(t, 3, target)
					profile := desktopCONNECTCandidateSource(t, "socks5", host)
					if !authenticated {
						profile.External.SOCKS5.Username, profile.External.SOCKS5.Password = "", ""
					}
					a.profiles.Profiles = append(a.profiles.Profiles, profile)
					before, _ := json.Marshal(a.profiles)
					originalInput, originalConfig := launch.chain.input, string(launch.config)
					catalog, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 0, []string{profile.ID})
					if err != nil {
						t.Fatal("original SOCKS candidate rejected", err)
					}
					var inventory mobilemultihop.NodeChainCandidateInventory
					if err := json.Unmarshal([]byte(catalog.inventory), &inventory); err != nil || len(inventory.Inputs) != 1 {
						t.Fatal("SOCKS candidate lost original source", err)
					}
					var member struct{ Kind, Capture string }
					if err := json.Unmarshal([]byte(inventory.Inputs[0]), &member); err != nil || member.Kind != "routervpn-node-chain-socks-member" {
						t.Fatal("SOCKS candidate substituted another typed member", err)
					}
					var captured struct{ Profile common.RouterProfile }
					if err := json.Unmarshal([]byte(member.Capture), &captured); err != nil || !reflect.DeepEqual(captured.Profile.External, profile.External) ||
						captured.Profile.DNSHost != profile.DNSHost || captured.Profile.DNSProtocol != "tcp" || captured.Profile.DNSPort != 5353 {
						t.Fatal("SOCKS candidate changed credentials or original DNS policy", err)
					}
					if len(catalog.assets) != 0 || len(catalog.files) != 0 {
						t.Fatal("SOCKS candidate borrowed a paired source")
					}
					for _, secret := range []string{"proxy-user", "proxy-secret", host} {
						if strings.Contains(catalog.plan.Metadata(), secret) {
							t.Fatal("SOCKS metadata exposed private candidate source")
						}
					}
					row := desktopCandidateStatusFixture(t, catalog, profile.ID)
					if err := validateDesktopNodeChainCandidateStatus(catalog.plan, profile.ID, row, time.Now()); err != nil {
						t.Fatal("complete SOCKS fifty TCP receipt rejected", err)
					}
					row.Measurement = "icmp"
					if validateDesktopNodeChainCandidateStatus(catalog.plan, profile.ID, row, time.Now()) == nil {
						t.Fatal("SOCKS candidate relabeled TCP timing as ICMP")
					}
					after, _ := json.Marshal(a.profiles)
					if !bytes.Equal(before, after) || launch.chain.input != originalInput || string(launch.config) != originalConfig {
						t.Fatal("SOCKS source capture changed the original path")
					}
					changed := cloneRouterProfile(profile)
					changed.External.SOCKS5.Username, changed.External.SOCKS5.Password = "replacement-user", "replacement-secret"
					a.profiles.Profiles[len(a.profiles.Profiles)-1] = changed
					replacement, err := captureDesktopNodeChainCandidateSources(context.Background(), a, launch, 0, []string{profile.ID})
					if err != nil || replacement.inventorySHA == catalog.inventorySHA || replacement.plan.CaptureSHA256() == catalog.plan.CaptureSHA256() || replacement.revision == catalog.revision {
						t.Fatal("new SOCKS credentials reused the original receipt source", err)
					}
				})
			}
		}
	}
}

func TestDesktopSOCKSCandidateKeepsOriginalRefusals(t *testing.T) {
	for _, fault := range []string{"hostname", "endpoint", "port", "layer", "paired-api", "paired-proof", "half-credential", "username-bound", "password-bound", "protocol-fields", "cancelled", "aggregate"} {
		t.Run(fault, func(t *testing.T) {
			profile := desktopCONNECTCandidateSource(t, "socks5", "203.0.113.40")
			proxy := profile.External.SOCKS5
			ctx, total := context.Background(), 0
			switch fault {
			case "hostname":
				proxy.Host, profile.Endpoint = "uncaptured.invalid", "uncaptured.invalid"
			case "endpoint":
				profile.Endpoint = "203.0.113.41"
			case "port":
				proxy.Port = 0
			case "layer":
				profile.StartLayer = "aes-256-gcm"
			case "paired-api":
				profile.RouterAPI = "https://borrowed.invalid"
			case "paired-proof":
				profile.NodeProofID = strings.Repeat("a", 64)
			case "half-credential":
				proxy.Password = ""
			case "username-bound":
				proxy.Username = strings.Repeat("u", 256)
			case "password-bound":
				proxy.Password = strings.Repeat("p", 256)
			case "protocol-fields":
				profile.External.HTTPConnect = &common.ExternalHTTPConnectConfig{Host: profile.Endpoint, Port: 8080}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "aggregate":
				total = mobilemultihop.NodeChainInputLimit
			}
			if input, err := (&desktopNodeChainCapture{}).compileCandidateMember(ctx, profile, &total); err == nil || input != "" {
				t.Fatal("invalid SOCKS candidate acquired source authority")
			}
		})
	}
}
