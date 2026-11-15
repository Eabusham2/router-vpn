package main

import (
	"net"
	"router-vpn/internal/mobilemultihop"
	"testing"
)

func TestDesktopDarwinOrdinaryReaderRequiresOriginalRetirement(t *testing.T) {
	for _, scenario := range []string{"same-alias", "renamed", "rollback", "old-index", "old-index-renamed", "same-index", "stale-reader", "kernel-name", "kernel-mtu", "kernel-down", "kernel-missing", "duplicate-index"} {
		t.Run(scenario, func(t *testing.T) {
			old := &mobilemultihop.DesktopNodeChainReadyRecord{InterfaceName: "utun91", InterfaceIndex: 91, Reader: 4}
			next := desktopNodeMTURecord{Interface: "utun91", Index: 92, Reader: 5, MTU: 1380}
			if scenario == "renamed" {
				next.Interface = "utun92"
			}
			if scenario == "rollback" {
				next.Reader++
				next.MTU = 1420
			}
			kernel := []net.Interface{{Name: next.Interface, Index: next.Index, MTU: next.MTU, Flags: net.FlagUp}}
			switch scenario {
			case "old-index":
				kernel = append(kernel, net.Interface{Name: old.InterfaceName, Index: 91})
			case "old-index-renamed":
				kernel = append(kernel, net.Interface{Name: "utun99", Index: 91})
			case "same-index":
				next.Index = 91
				kernel[0].Index = 91
			case "stale-reader":
				next.Reader = 4
			case "kernel-name":
				kernel[0].Name = "utun93"
			case "kernel-mtu":
				kernel[0].MTU++
			case "kernel-down":
				kernel[0].Flags = 0
			case "kernel-missing":
				kernel = nil
			case "duplicate-index":
				kernel = append(kernel, kernel[0])
			}
			err := validateDesktopMacOSOrdinaryReaderRetirement(old, next, kernel)
			if (err == nil) != (scenario == "same-alias" || scenario == "renamed" || scenario == "rollback") {
				t.Fatal("ordinary reader retirement verdict changed", scenario, err)
			}
		})
	}
}
