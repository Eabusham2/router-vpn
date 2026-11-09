//go:build go1.25

package main

import "testing"

// The protected Windows launch derives a physical-policy graph from the original
// imported constructor. The actual MTU controller must retain both authorities;
// using the original graph as its running TUN config would bypass that policy.
func TestDesktopImportedMTUProtectedDerivedSourceCapture(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "wireguard"} {
		t.Run(protocol, func(t *testing.T) {
			f := newDesktopImportedOwnedFixture(t, protocol, "reality-vision", "always")
			f.stage(t)
			f.publish(t)
			if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			f.a.mu.Lock()
			f.a.state.Connected, f.a.state.Phase = true, "connected"
			f.a.mu.Unlock()
			runtime, handled, err := desktopImportedMTURuntime(f.operation, f.a)
			if err != nil || !handled || runtime == nil {
				t.Fatal("MTU did not capture the retained protected imported path", handled, err)
			}
			u, err := getDesktopImportedMTUUI(f.operation, f.a, runtime)
			if err != nil {
				t.Fatal("actual derived native graph could not construct its private MTU controller", err)
			}
			t.Cleanup(func() { desktopImportedMTUUIs.CompareAndDelete(f.a, u) })
			policy := f.launch.ownedNode.imported.policy
			if u.owner.config != policy.Config() || u.owner.config == f.selection.Native.configs[f.selection.ExitMode] ||
				u.owner.runtime.selection.Native != f.selection.Native || u.owner.record.Config != policy.Metadata().ConfigSHA256 ||
				u.owner.record.Session != policy.Metadata().SessionID || u.owner.policy.Proof != f.selection.Exit.NodeProofID {
				t.Fatal("MTU confused the original imported source with the running protected graph")
			}
			original, err := u.owner.CaptureContext(f.operation)
			if err != nil || original.MTU != u.owner.record.MTU || original.Session != f.launch.mtuSession {
				t.Fatal("MTU lost the derived graph's actual native reader", err)
			}
			f.launch.workspaceMu.Lock()
			f.launch.ownedNode.source = append([]byte(nil), f.launch.ownedNode.source...)
			f.launch.ownedNode.source[len(f.launch.ownedNode.source)-2] ^= 1
			f.launch.workspaceMu.Unlock()
			if _, err := u.owner.CaptureContext(f.operation); err == nil {
				t.Fatal("retained MTU controller accepted a changed original imported envelope")
			}
		})
	}
}
