package main

import (
	"context"
	"strings"
	"testing"
)

func TestDesktopDarwinImportedTrioIndependentLayers(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, entry := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, final := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, choice := range []string{"server", "auto"} {
					t.Run(mode+"/"+entry+"/"+final+"/"+choice, func(t *testing.T) {
						a, nodes := desktopNodeChainCaptureFixture(t, 3)
						installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
						installDesktopOrderedImportedCipher(t, a, nodes, "2022-blake3-aes-256-gcm", 32)
						a.profiles.Profiles[0].StartLayer = entry
						a.profiles.Profiles[2].StartLayer = final
						control, _ := a.profileByIDLocked(a.profiles.SelectedID)
						selected, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
						if err != nil {
							t.Fatal(err)
						}
						selected, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
						if err != nil || !desktopDarwinImportedTrioExecutionMembers(selected.Nodes, choice) {
							t.Fatal("original independent paired layers lost admission", err)
						}
						launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("b", 32), "darwin")
						if err != nil {
							t.Fatal(err)
						}
						execution, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
						if err != nil {
							t.Fatal("independent layers lost execution source", err)
						}
						_, meta, capture, err := execution.readPolicy()
						if err != nil || len(meta.Prefixes) != 3 || meta.Prefixes[0].StartLayer != entry || meta.Prefixes[1].StartLayer != "off" || meta.Prefixes[2].StartLayer != final || meta.Prefixes[1].NodeID != "" || len(capture.PhysicalRoots) != 1 || capture.SelectedDNS.Physical {
							t.Fatal("independent layers replaced original graph authority", err)
						}
						original, err := execution.physical.OriginalDesktopPolicy()
						if err != nil || original != launch.chain.policy || original.OriginalChain() != selected.Native.chain.chain {
							t.Fatal("independent layer execution replaced original captured pointer", err)
						}
					})
				}
			}
		}
	}
}
