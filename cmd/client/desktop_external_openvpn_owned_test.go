//go:build go1.25

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
)

func TestDesktopWindowsExternalOpenVPNAuthorityKeepsOriginalImport(t *testing.T) {
	for _, protocol := range []string{"openvpn-tcp", "openvpn-udp", "openvpn-mixed"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				launch := f.connect(t, protocol)
				original := cloneRouterProfile(f.profiles[protocol])
				if err := validateDesktopWindowsExternalSource(original, launch); err != nil || !reflect.DeepEqual(original.External, launch.external.profile.External) {
					t.Fatal("public OpenVPN changed its complete original import", err)
				}
				measurement, err := capturedDesktopMeasurementRuntime(launch)
				meta := launch.external.physical.Metadata()
				if err != nil || measurement.source != meta.SourceSHA256 || measurement.config != meta.ConfigSHA256 || measurement.node != original.ID {
					t.Fatal("OpenVPN measurement lost its captured source", err)
				}
				selected, err := desktopProtectionSelectionFor(nil, launch.external.physical)
				if err != nil || selected.source != meta.SourceSHA256 || selected.config != meta.ConfigSHA256 || selected.profileID != original.ID {
					t.Fatal("OpenVPN protection selected another source", err)
				}
				observed := sessionTrackerFor(f.base.a).capture()
				lookups := 0
				lookup := func(context.Context, string) ([]string, error) { lookups++; return nil, errors.New("unowned resolver") }
				if proof := proveSelectedDNSWithLookup(context.Background(), f.base.a, observed, launch.mode, lookup); proof.Status != "passed" || lookups != 0 {
					t.Fatal("OpenVPN DNS ignored its captured proof", proof)
				}
				changes := map[string]func(*common.RouterProfile){
					"username": func(p *common.RouterProfile) { p.External.OpenVPN.Username += "-different" },
					"password": func(p *common.RouterProfile) { p.External.OpenVPN.Password += "-different" },
					"remote": func(p *common.RouterProfile) {
						p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, "198.51.100.25", "198.51.100.26", 1)
					},
					"trust": func(p *common.RouterProfile) {
						p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, strings.Repeat("ab", 32), strings.Repeat("cd", 32), 1)
					},
					"tls-name": func(p *common.RouterProfile) {
						p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, "captured-provider.example", "another-provider.example", 1)
					},
					"source-text": func(p *common.RouterProfile) {
						p.External.OpenVPN.Config = "# changed import\n" + p.External.OpenVPN.Config
					},
					"resolver": func(p *common.RouterProfile) {
						p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "198.51.100.53", 5353
					},
					"mtu": func(p *common.RouterProfile) { p.ManualMTU = 1320 },
				}
				for name, mutate := range changes {
					changed := cloneRouterProfile(original)
					mutate(&changed)
					if desktopOwnedNodeProfileToken(changed) == desktopOwnedNodeProfileToken(original) {
						t.Fatal("OpenVPN negative did not change source", name)
					}
					candidate := observed
					candidate.Profile = changed
					if validateDesktopWindowsExternalSource(changed, launch) == nil {
						t.Fatal("OpenVPN substitution adopted original runtime", name)
					}
					if proof := proveSelectedDNSWithLookup(context.Background(), f.base.a, candidate, launch.mode, lookup); proof.Status == "passed" || lookups != 0 {
						t.Fatal("OpenVPN DNS reused substituted import", name, proof)
					}
					if launch.external.windows.current(true) != nil || f.base.a.nodeProtection.active.external != launch.external.physical || !reflect.DeepEqual(f.profiles[protocol], original) {
						t.Fatal("rejected OpenVPN source changed its original owner", name)
					}
				}
			})
		})
	}
}
