//go:build linux

package main

import (
	"router-vpn/internal/common"
	"testing"
)

func TestDesktopLinuxWireGuardLayeredHysteriaRetainsBothSavedSources(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(layer, func(t *testing.T) { desktopLinuxPacketEntryRetainsBothSavedSources(t, "hysteria2", layer) })
	}
}
