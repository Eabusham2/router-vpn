package main

import (
	"net"
	"testing"
)

func TestDesktopDarwinPairedReaderRequiresOriginalRetirement(t *testing.T) {
	old := desktopNodeMTURecord{Session: "original-session", Config: "original-config", Path: "original-path", Interface: "utun91", Index: 91, Reader: 4, MTU: 1376}
	next := old
	next.Interface = "utun92"
	next.Index = 92
	next.Reader++
	next.MTU = 1420
	links := []net.Interface{{Index: 92, Name: "utun92", MTU: 1420, Flags: net.FlagUp}}
	if err := validateDesktopMacOSPairedNodeReaderRetirement(old, next, links); err != nil {
		t.Fatal(err)
	}
	t.Run("pending-mutation-then-rollback", func(t *testing.T) {
		rollback := next
		rollback.Reader++
		rollback.MTU = old.MTU
		kernel := append([]net.Interface(nil), links...)
		kernel[0].MTU = rollback.MTU
		if err := validateDesktopMacOSPairedNodeReaderRetirement(old, rollback, kernel); err != nil {
			t.Fatal("authenticated pending rollback could not retire original", err)
		}
	})
	for _, scenario := range []string{"same-alias-fresh-index", "same-alias-rollback", "same-alias-old-reader-retained", "same-alias-rollback-old-reader-retained"} {
		t.Run(scenario, func(t *testing.T) {
			changed := next
			changed.Interface = old.Interface
			kernel := []net.Interface{{Index: changed.Index, Name: changed.Interface, MTU: changed.MTU, Flags: net.FlagUp}}
			rollback := scenario == "same-alias-rollback" || scenario == "same-alias-rollback-old-reader-retained"
			retained := scenario == "same-alias-old-reader-retained" || scenario == "same-alias-rollback-old-reader-retained"
			if rollback {
				changed.Reader++
				changed.MTU = old.MTU
				kernel[0].MTU = changed.MTU
			}
			if retained {
				kernel = append(kernel, net.Interface{Index: old.Index, Name: old.Interface, MTU: old.MTU, Flags: net.FlagUp})
			}
			err := validateDesktopMacOSPairedNodeReaderRetirement(old, changed, kernel)
			if (err != nil) != retained {
				t.Fatal("consistent same-alias successor lost original retirement requirement", scenario, err)
			}
		})
	}
	for name, mutate := range map[string]func(*desktopNodeMTURecord, *[]net.Interface){
		"old-reader-retained": func(_ *desktopNodeMTURecord, k *[]net.Interface) {
			*k = append(*k, net.Interface{Index: old.Index, Name: old.Interface})
		},
		"same-alias":      func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Interface = old.Interface },
		"same-index":      func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Index = old.Index },
		"stale-reader":    func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Reader = old.Reader },
		"foreign-session": func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Session += "-foreign" },
		"foreign-config":  func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Config += "-foreign" },
		"foreign-path":    func(n *desktopNodeMTURecord, _ *[]net.Interface) { n.Path += "-foreign" },
		"kernel-name":     func(_ *desktopNodeMTURecord, k *[]net.Interface) { (*k)[0].Name = "utun93" },
		"kernel-mtu":      func(_ *desktopNodeMTURecord, k *[]net.Interface) { (*k)[0].MTU++ },
		"kernel-down":     func(_ *desktopNodeMTURecord, k *[]net.Interface) { (*k)[0].Flags = 0 },
		"kernel-absent":   func(_ *desktopNodeMTURecord, k *[]net.Interface) { *k = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := next
			kernel := append([]net.Interface(nil), links...)
			mutate(&changed, &kernel)
			if validateDesktopMacOSPairedNodeReaderRetirement(old, changed, kernel) == nil {
				t.Fatal("unproved kernel successor accepted")
			}
		})
	}
}
