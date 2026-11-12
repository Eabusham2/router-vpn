package mobilemultihop

import (
	"strings"
	"testing"
)

type desktopExecutionPhysicalWrapper struct {
	*DesktopNodeChainExecutionPhysicalPolicy
}

func TestDesktopNodeReadyDarwinRequiresClosedExecutionPolicy(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			source := desktopExecutionSource(t, execution, "https", true)
			_, prep, _ := desktopExecutionProjection(t, source, "darwin", desktopNodeTestSession, 1400)
			policy, err := prep.DesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			_, meta, capture, err := policy.PhysicalReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			transfer := strings.Repeat("b", 64)
			r := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
				SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
				DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "utun771", InterfaceIndex: 771,
				MTU: 1400, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
			raw, err := CanonicalDesktopNodeReadyRecord(r, policy, transfer)
			if err != nil {
				t.Fatal("sealed execution physical receipt rejected", err)
			}
			if _, err := ParseDesktopNodeReadyRecord(raw, policy, transfer); err != nil {
				t.Fatal(err)
			}
			if r.Validate(desktopExecutionPhysicalWrapper{policy}, transfer) == nil {
				t.Fatal("metadata wrapper borrowed exact execution authority")
			}
			local, err := policy.OriginalDesktopPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if r.Validate(local, transfer) == nil {
				t.Fatal("execution DNS receipt borrowed Local config")
			}
			for name, change := range map[string]func(*DesktopNodeReadyRecord){
				"dns":       func(r *DesktopNodeReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("f", 64) },
				"config":    func(r *DesktopNodeReadyRecord) { r.ConfigSHA256 = local.Metadata().ConfigSHA256 },
				"session":   func(r *DesktopNodeReadyRecord) { r.SessionID = strings.Repeat("f", 32) },
				"transfer":  func(r *DesktopNodeReadyRecord) { r.TransferSHA256 = strings.Repeat("f", 64) },
				"mtu":       func(r *DesktopNodeReadyRecord) { r.MTU++ },
				"interface": func(r *DesktopNodeReadyRecord) { r.InterfaceName = "router-vpn" },
			} {
				t.Run(name, func(t *testing.T) {
					changed := r
					change(&changed)
					if changed.Validate(policy, transfer) == nil {
						t.Fatal("foreign execution physical receipt accepted")
					}
				})
			}
		})
	}
}
