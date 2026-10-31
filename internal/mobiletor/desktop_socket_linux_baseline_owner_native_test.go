//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func linuxBaselineRetentionFixture(t *testing.T, policy string) (*DesktopLinuxSocketPolicy, DesktopLinuxProtectionOwner) {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("Linux retained protection requires the explicit isolated namespace runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		t.Fatal(err)
	}
	capture := desktopSocketFixtureCapture()
	desktopLinuxKernelInstallBaseline(t, capture)
	iface, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		t.Fatal(err)
	}
	options := DesktopLinuxSocketOptions{Interfaces: []DesktopLinuxSocketInterface{{Name: iface.Name, Index: uint32(iface.Index), Address: netip.MustParseAddr("198.18.0.1")}}}
	source, err := NewDesktopLinuxSocketPolicy(context.Background(), capture, options)
	if source != nil {
		t.Cleanup(func() {
			if err := source.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	retained, err := source.RetainProtection(ctx, capture, policy)
	// The namespace fixture owns this test table. Capability Close never
	// removes it implicitly; explicit fixture cleanup stays separate.
	t.Cleanup(func() {
		if err := source.Close(context.Background()); err != nil {
			t.Error(err)
		}
		if retained != nil {
			if err := retained.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}
		if rows, err := desktopLinuxNFTRead(context.Background()); err != nil {
			t.Error(err)
		} else if len(rows) != 0 {
			if _, err := desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", desktopLinuxNFTTable}, ""); err != nil {
				t.Error(err)
			}
		}
	})
	if err != nil || retained == nil {
		t.Fatal("actual source did not retain its native baseline authority", err)
	}
	return source, retained
}

func TestDesktopLinuxGuardianKernelRetainedBaseline(t *testing.T) {
	t.Run("on-connect-and-always", func(t *testing.T) {
		for _, policy := range []string{"on-connect", "always"} {
			t.Run(policy, func(t *testing.T) {
				source, retained := linuxBaselineRetentionFixture(t, policy)
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				prepared, err := retained.Prepared(ctx)
				if err != nil || prepared.Capture != source.capture {
					t.Fatal("retention lost its prepared native source", err)
				}
				if second, err := source.RetainProtection(ctx, source.capture, policy); err == nil || second != nil {
					t.Fatal("one source created replacement baseline authority", second, err)
				}
				if err := retained.Release(ctx); err == nil {
					t.Fatal("live guardian authorized baseline removal")
				}
				if err := source.Close(ctx); err != nil {
					t.Fatal(err)
				}
				retired, err := retained.Retired(ctx)
				if err != nil || retired != prepared {
					t.Fatal("joined source lost its retained native baseline", retired, err)
				}
				cancelled, stop := context.WithCancel(ctx)
				stop()
				if err := retained.Release(cancelled); err == nil {
					t.Fatal("cancelled owner removed its native baseline")
				}
				for i := 0; i < 2; i++ {
					kept, err := retained.Disconnect(ctx)
					if err != nil || kept != (policy == "always") {
						t.Fatal("disconnect changed the captured On-connect/Always semantics", kept, err)
					}
				}
				if policy == "always" {
					if got, err := retained.Retired(ctx); err != nil || got != prepared {
						t.Fatal("Always disconnect lost its original closed baseline", got, err)
					}
					if err := retained.Release(ctx); err != nil {
						t.Fatal("explicit owned release did not remove the original Always table", err)
					}
				}
				if err := ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
					t.Fatal("acknowledged release lacked independent absence", err)
				}
				if err := retained.Release(ctx); err != nil {
					t.Fatal("idempotent removal lost its retained commit receipt", err)
				}
				if err := retained.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if err := retained.Release(ctx); err == nil {
					t.Fatal("closed retention regained mutation authority")
				}
			})
		}
	})
	t.Run("changed-baseline", func(t *testing.T) {
		source, retained := linuxBaselineRetentionFixture(t, "always")
		ctx := context.Background()
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, "add rule inet router_vpn_killswitch output accept\n")
		if err := retained.Release(ctx); err == nil {
			t.Fatal("changed native baseline authorized original removal")
		}
		rows, err := desktopLinuxNFTRead(ctx)
		if err != nil || len(rows) == 0 {
			t.Fatal("rejected removal changed the foreign native baseline", err)
		}
	})
	t.Run("same-name-replacement", func(t *testing.T) {
		source, retained := linuxBaselineRetentionFixture(t, "always")
		ctx := context.Background()
		before, err := retained.Prepared(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, "delete table inet router_vpn_killswitch\n")
		desktopLinuxKernelInstallBaseline(t, source.capture)
		if err := retained.Release(ctx); err == nil {
			t.Fatal("old retention removed a same-label native replacement")
		}
		rows, err := desktopLinuxNFTRead(ctx)
		if err != nil || len(rows) == 0 {
			t.Fatal("old owner erased replacement protection", err)
		}
		var handle uint64
		for _, row := range rows {
			if table, ok := row["table"].(map[string]any); ok {
				handle = desktopLinuxNumber(table["handle"])
			}
		}
		if handle == 0 || handle == before.TableHandle {
			t.Fatal("actual replacement fixture did not acquire a different kernel object")
		}
		if err := retained.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if rows, err := desktopLinuxNFTRead(ctx); err != nil || len(rows) == 0 {
			t.Fatal("retention teardown deleted a replacement table", err)
		}
	})
	t.Run("namespace-boundary-after-commit", func(t *testing.T) {
		source, retained := linuxBaselineRetentionFixture(t, "always")
		ctx := context.Background()
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := retained.Release(ctx); err != nil {
			t.Fatal(err)
		}
		desktopLinuxKernelInstallBaseline(t, source.capture)
		finished := make(chan error, 1)
		go func() {
			// Exiting while locked destroys this worker's native thread and
			// its private network namespace; it never re-enters Go's pool.
			runtime.LockOSThread()
			if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
				finished <- err
				return
			}
			if err := retained.Release(ctx); err == nil {
				finished <- nil
				return
			}
			finished <- syscall.EXDEV
		}()
		if err := <-finished; err != syscall.EXDEV {
			t.Fatal("changed native namespace substituted absence for the original replacement", err)
		}
		if err := retained.Release(ctx); err == nil {
			t.Fatal("original namespace accepted a replacement as committed absence")
		}
		if rows, err := desktopLinuxNFTRead(ctx); err != nil || len(rows) == 0 {
			t.Fatal("foreign namespace attempt changed the original replacement baseline", err)
		}
	})
}
