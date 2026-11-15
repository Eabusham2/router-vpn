package main

import (
	"errors"
	"net"
	"router-vpn/internal/mobilemultihop"
)

// Typed/execution changed-reader succession is proved by the retired kernel index and the
// exact fresh reader, including when the allocator reuses the original alias.
func validateDesktopMacOSTypedReaderRetirement(previous *mobilemultihop.DesktopNodeChainReadyRecord,
	live desktopNodeMTURecord, inventory []net.Interface) error {
	if previous == nil || previous.InterfaceIndex == 0 || previous.Reader == 0 ||
		!desktopNodeChainDarwinInterfaceName(previous.InterfaceName) || live.Reader <= previous.Reader ||
		live.Index < 1 || uint64(live.Index) > uint64(^uint32(0)) || live.Index == int(previous.InterfaceIndex) {
		return errors.New("macOS typed replacement lacks its original fresh kernel reader")
	}
	found := false
	for i := range inventory {
		link := &inventory[i]
		if link.Index == int(previous.InterfaceIndex) {
			return errors.New("macOS typed replacement retained its original kernel reader")
		}
		if link.Index == live.Index {
			if found || !desktopNodeChainDarwinInterfaceName(live.Interface) || link.Name != live.Interface || link.MTU != live.MTU || link.Flags&net.FlagUp == 0 || live.MTU < 1280 || live.MTU > 9000 {
				return errors.New("macOS typed successor differs from exact live kernel readback")
			}
			found = true
		}
	}
	if !found {
		return errors.New("macOS typed replacement lost its actual new utun reader")
	}
	return nil
}
