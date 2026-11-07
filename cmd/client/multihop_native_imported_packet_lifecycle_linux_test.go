package main

import "testing"

func TestDesktopImportedPacketDailyConnectRestoreAndOwnedTeardown(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) { desktopImportedDailyConnectRestoreAndOwnedTeardown(t, protocol) })
	}
}
