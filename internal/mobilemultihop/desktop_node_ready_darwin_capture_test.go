package mobilemultihop

import (
	"fmt"
	"strings"
	"testing"
)

func TestDesktopNodeReadyRecordBindsDarwinOriginalSelection(t *testing.T) {
	for _, mtu := range []int{0, 1392} {
		policy, transfer, record := desktopNodeReadyFixtureFor(t, mtu, "darwin")
		record.InterfaceName = "utun991"
		raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := ParseDesktopNodeReadyRecord(raw, policy, transfer)
		if err != nil || actual != record {
			t.Fatal("Darwin native receipt lost its exact sealed selection", err)
		}
		for name, mutate := range map[string]func(*DesktopNodeReadyRecord){
			"session":   func(r *DesktopNodeReadyRecord) { r.SessionID = strings.Repeat("f", 32) },
			"source":    func(r *DesktopNodeReadyRecord) { r.SourceSHA256 = strings.Repeat("f", 64) },
			"config":    func(r *DesktopNodeReadyRecord) { r.ConfigSHA256 = strings.Repeat("f", 64) },
			"selection": func(r *DesktopNodeReadyRecord) { r.TransferSHA256 = strings.Repeat("f", 64) },
			"dns":       func(r *DesktopNodeReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("f", 64) },
			"tun":       func(r *DesktopNodeReadyRecord) { r.InterfaceName = "unowned-tun" },
			"index":     func(r *DesktopNodeReadyRecord) { r.InterfaceIndex = 0 },
			"mtu":       func(r *DesktopNodeReadyRecord) { r.MTU++ },
			"time":      func(r *DesktopNodeReadyRecord) { r.ProvedAt = 0 },
			"query":     func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = 0 },
		} {
			t.Run(fmt.Sprintf("mtu-%d/%s", mtu, name), func(t *testing.T) {
				changed := record
				mutate(&changed)
				if _, err := CanonicalDesktopNodeReadyRecord(changed, policy, transfer); err == nil {
					t.Fatal("Darwin readiness substituted its captured native field")
				}
			})
		}
		for _, target := range []string{"windows", "linux"} {
			other, _, _ := desktopNodeReadyFixtureFor(t, mtu, target)
			if _, err := ParseDesktopNodeReadyRecord(raw, other, transfer); err == nil {
				t.Fatal("Darwin receipt accepted another platform's sealed native policy", target)
			}
		}
		if _, err := ParseDesktopNodeReadyRecord(append(raw, '\n'), policy, transfer); err == nil {
			t.Fatal("Darwin readiness admitted a noncanonical receipt")
		}
	}
}
