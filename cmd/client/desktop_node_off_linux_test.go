//go:build linux

package main

import (
	"bytes"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

func TestDesktopSingleNodeOffLinuxRestoreRetainsCapturedSourceAndMTU(t *testing.T) {
	for _, mode := range []string{"wg", "shadowsocks"} {
		t.Run(mode, func(t *testing.T) {
			f, profile := linuxSealedRestoreFixtureWithGraph(t, false, mode, "off", "off")
			_, saved := captureLinuxSealedRestore(t, f, profile)
			source := bytes.Clone(saved.source)
			original := f.h.policy.OriginalProfile().Config()
			clear(f.h.source)
			f.h.policy = nil
			compiled, restored, err := saved.compiled(profile)
			if err != nil || restored.KillSwitchPolicy != "off" || restored.KillSwitch || compiled.Config() != original || !bytes.Equal(source, saved.source) {
				t.Fatal("Off restoration substituted source or captured policy", err)
			}
			next, err := mobilemultihop.NewDesktopNodePolicyWithMTU(compiled, strings.Repeat("d", 32), "linux", saved.mtu)
			if err != nil || next.Metadata().KillSwitchPolicy != "off" || next.Metadata().RestoredMTU != 1392 || next.OriginalProfile().Config() != original {
				t.Fatal("Off restoration lost original graph or measured MTU", err)
			}
			for _, fault := range []string{"credential", "protection"} {
				changed := cloneRouterProfile(profile)
				if fault == "credential" {
					changed.APIToken += "replacement"
				} else {
					changed.KillSwitchPolicy = "on-connect"
					changed.KillSwitch = true
				}
				if p, _, err := saved.compiled(changed); p != nil || err == nil {
					t.Fatal("Off restoration adopted replacement source", fault)
				}
			}
		})
	}
}
