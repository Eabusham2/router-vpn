package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeMultihopPacketRestoreRetainsProvedServerPeerAndExecution(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) { nativeMultihopPacketRestoreRetainsProvedServerPeerAndExecution(t, mode) })
	}
}

func nativeMultihopPacketRestoreRetainsProvedServerPeerAndExecution(t *testing.T, mode string) {
	t.Helper()
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newRetainedMultihopModeFixture(t, execution, mode)
			t.Setenv("HOMEVPN_ROOT", f.launch.root)
			manifest := filepath.Join(f.launch.root, "runtime", "native", "NATIVE-RUNTIME.json")
			if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			f.a.profiles.Profiles[2].EffectiveMTU = 9000 // not live path evidence
			snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(f.a.profiles), State: f.a.state, Runtime: f.a.cmd}
			plan, err := f.a.speedLabCaptureRestorePlan(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if plan.multihop == nil || plan.multihop.Native != f.selection.Native || plan.multihop.restoreMTU != 1280 || plan.request.Execution != execution || plan.request.Execution == "auto" || plan.multihop.Control.MultihopExecution != "auto" || plan.multihop.ExitMode != mode {
				t.Fatal("restore replaced the proved packet path or repeated Compare")
			}
			if execution == "server" {
				raw, _ := desktopRelays.Load(f.a)
				relay := raw.(*desktopRelayOwner)
				if plan.multihop.serverPacketPublic != relay.request.ExpectedPacketPublicKey || plan.multihop.serverPacketPublic == "" {
					t.Fatal("restoration dropped the authenticated server peer pin")
				}
				if nativeMultihopPQExitMode(mode) {
					if plan.multihop.serverPQIdentity != relay.request.ExpectedPQClientIdentity || plan.multihop.serverPQIdentity == "" {
						t.Fatal("restoration dropped the independently paired server PQ identity")
					}
					relay.serverPQIdentity = strings.Repeat("f", 64)
					if plan.multihop.serverPQIdentity == relay.serverPQIdentity {
						t.Fatal("restore retained a mutable PQ identity")
					}
				}
				relay.serverPacketPublic = testWGKey('y')
				if plan.multihop.serverPacketPublic == relay.serverPacketPublic {
					t.Fatal("restore retained mutable relay identity")
				}
			} else if plan.multihop.serverPacketPublic != "" || plan.multihop.serverPQIdentity != "" {
				t.Fatal("Local restore invented a server identity")
			}
		})
	}
}

func TestNativeMultihopPacketRestoreRejectsRetiredLeaseIdentity(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) { nativeMultihopPacketRestoreRejectsRetiredLeaseIdentity(t, mode) })
	}
}

func nativeMultihopPacketRestoreRejectsRetiredLeaseIdentity(t *testing.T, mode string) {
	t.Helper()
	faults := []string{"missing", "command", "unproved", "stale-capability", "expired", "request-pin", "receipt-pin", "entry", "exit", "local-key", "duplicate-peer"}
	if nativeMultihopPQExitMode(mode) {
		faults = append(faults, "pq-request-pin", "pq-receipt-pin", "pq-local-key", "pq-duplicate-peer", "pq-missing-server", "pq-malformed-server")
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			f := newRetainedMultihopModeFixture(t, "server", mode)
			raw, _ := desktopRelays.Load(f.a)
			relay := raw.(*desktopRelayOwner)
			switch fault {
			case "missing":
				desktopRelays.Delete(f.a)
			case "command":
				relay.command = &exec.Cmd{}
			case "unproved":
				relay.renewed = false
			case "stale-capability":
				relay.packetCapabilityReady = false
			case "expired":
				relay.expected.ExpiresAt = time.Now().Add(-time.Second)
			case "request-pin":
				relay.request.ExpectedPacketPublicKey = testWGKey('y')
			case "receipt-pin":
				relay.expected.ExpectedPacketPublicKey = testWGKey('y')
			case "entry":
				relay.request.EntryNodeID = f.selection.Exit.NodeProofID
			case "exit":
				relay.expected.ExitNodeID = f.selection.Entry.NodeProofID
			case "local-key":
				relay.localPacketPublic = testWGKey('y')
			case "duplicate-peer":
				relay.serverPacketPublic = relay.localPacketPublic
				relay.request.ExpectedPacketPublicKey = relay.localPacketPublic
				relay.expected.Request = relay.request
			case "pq-request-pin":
				relay.request.ExpectedPQClientIdentity = strings.Repeat("f", 64)
			case "pq-receipt-pin":
				relay.expected.ExpectedPQClientIdentity = strings.Repeat("f", 64)
			case "pq-local-key":
				relay.localPQIdentity = strings.Repeat("f", 64)
			case "pq-duplicate-peer":
				relay.serverPQIdentity = relay.localPQIdentity
				relay.request.ExpectedPQClientIdentity = relay.localPQIdentity
				relay.expected.Request = relay.request
			case "pq-missing-server":
				relay.serverPQIdentity = ""
			case "pq-malformed-server":
				relay.serverPQIdentity = strings.Repeat("E", 64)
				relay.request.ExpectedPQClientIdentity = relay.serverPQIdentity
				relay.expected.Request = relay.request
			}
			if _, err := captureNativeMultihopRestore(f.a, f.a.cmd, f.graph, f.selection.Control, f.selection.Entry, f.selection.Exit); err == nil {
				t.Fatal("unowned packet lease reached restore", fault)
			}
		})
	}
}

func TestNativeMultihopPacketUsesOwnedDNSInsteadOfKernelShortcut(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq"} {
		t.Run(mode, func(t *testing.T) { nativeMultihopPacketUsesOwnedDNSInsteadOfKernelShortcut(t, mode) })
	}
}

func nativeMultihopPacketUsesOwnedDNSInsteadOfKernelShortcut(t *testing.T, mode string) {
	t.Helper()
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newRetainedMultihopModeFixture(t, execution, mode)
			t.Setenv("HOMEVPN_ROOT", f.launch.root)
			observation := observedConnection{Profile: f.selection.Exit, RouterID: f.selection.Exit.ID, Connected: true, Phase: "connected"}
			calls := 0
			lookup := func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil }
			proof := proveSelectedDNSWithLookup(context.Background(), f.a, observation, mode, lookup)
			if proof.Status != "passed" || calls != 1 || proof.Host != f.selection.Exit.AdGuardIPv4 {
				t.Fatal("owned native packet DNS fell back to a kernel or different resolver", proof, calls)
			}
			observation.Profile.DNSMode, observation.Profile.DNSProtocol, observation.Profile.DNSHost, observation.Profile.DNSPort = "custom", "udp", "1.1.1.1", 53
			proof = proveSelectedDNSWithLookup(context.Background(), f.a, observation, mode, lookup)
			if proof.Status != "failed" || calls != 1 {
				t.Fatal("changed resolver reached lookup without owned policy proof", proof, calls)
			}
			observation.Profile = f.selection.Exit
			if err := os.WriteFile(filepath.Join(f.launch.directory, "sing-box.json"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			proof = proveSelectedDNSWithLookup(context.Background(), f.a, observation, mode, lookup)
			if proof.Status != "failed" || calls != 1 {
				t.Fatal("replaced native packet configuration used the kernel DNS shortcut", proof, calls)
			}
		})
	}
}
