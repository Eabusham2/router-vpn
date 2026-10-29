//go:build !linux

package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestLocalControllerLinuxBootstrapCannotGrantAnotherPlatform(t *testing.T) {
	if err := validateLinuxOwnedStartup(nil); err != nil {
		t.Fatal("Linux-only startup guard changed ordinary platform startup", err)
	}
	if err := validateLinuxOwnedStartup(testLocalControllerOwner()); err == nil {
		t.Fatal("another platform accepted a fabricated Linux startup owner")
	}
	for _, arguments := range [][]string{{linuxOwnedControllerArgument}, {linuxOwnedControllerArgument, "--config=foreign"}, {"unexpected", linuxOwnedControllerArgument}} {
		owned, err := prepareLinuxOwnedController(arguments)
		if owned != nil || err == nil {
			t.Fatal("another platform manufactured the Linux privilege capability", arguments)
		}
	}
	if err := validateLinuxOwnedConfiguration(common.ClientConfig{Listen: linuxOwnedControllerAddress}); err == nil {
		t.Fatal("another platform accepted the Linux privileged configuration")
	}
	for _, arguments := range [][]string{nil, {"--verify-native-runtime"}, {"--mtu-owner-stop", "captured"}} {
		owned, err := prepareLinuxOwnedController(arguments)
		if owned != nil || err != nil {
			t.Fatal("Linux-only bootstrap changed an ordinary platform utility", arguments, err)
		}
	}
}
