//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopLinuxGuardianKernelStandardNodeTransfer(t *testing.T) {
	for _, name := range []string{"original", "repeated-result", "cancelled-finish", "successor-lost-before", "successor-lost-after", "changed-inventory"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			lease, err := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			source := linuxStandardProtectionFixture(t, lease)
			reservation, err := source.ReserveNodeTransfer(ctx, strings.Repeat("a", 32), lease)
			if err != nil {
				t.Fatal(err)
			}
			if err = reservation.Exclusive(ctx); err != nil {
				t.Fatal("actual source reservation not exclusive", err)
			}
			destination := linuxNodeBaselineFixture(t, false)
			guardian := linuxNodeBaselineSource(t, destination, false)
			pin, err := destination.PinStandardTransfer(ctx, strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			if source.Release(ctx, lease) == nil || source.Close(ctx) == nil || destination.Release(ctx) == nil || destination.Close(ctx) == nil {
				t.Fatal("reserved original creator could be removed or discarded")
			}
			var snapshot DesktopLinuxNodeTransferSnapshot
			if err = pin.WithSnapshot(ctx, func(actual DesktopLinuxNodeTransferSnapshot) error { snapshot = actual; return nil }); err != nil {
				t.Fatal(err)
			}
			// Dispose deliberately corrupted objects only inside this disposable native
			// fixture after assertions. This does not turn failed production settlement
			// into a successful release or claim original absence.
			defer func() {
				destination.crossTransfer = ""
				source.baseline.crossTransfer = ""
				_ = source.Close(context.Background())
			}()
			if name == "changed-inventory" {
				snapshot.Record.TableHandle++
				if reservation.Commit(ctx, snapshot, lease) == nil {
					t.Fatal("foreign handle committed original removal")
				}
				if source.Current(ctx, lease) != nil {
					t.Fatal("foreign successor removed source")
				}
				return
			}
			if name == "successor-lost-before" {
				if err = guardian.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", destination.nft.TableName}, ""); err != nil {
					t.Fatal(err)
				}
				if reservation.Commit(ctx, snapshot, lease) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("lost successor deleted source")
				}
				return
			}
			if err = reservation.Commit(ctx, snapshot, lease); err != nil {
				t.Fatal("actual generation-bound cross-adapter removal", err)
			}
			if name == "successor-lost-after" {
				if err = guardian.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", destination.nft.TableName}, ""); err != nil {
					t.Fatal(err)
				}
				if committed, err := reservation.Finish(ctx); err == nil || committed || reservation.finished {
					t.Fatal("missing successor became completed transfer", committed, err)
				}
				return
			}
			if name == "repeated-result" {
				if err = reservation.Commit(ctx, snapshot, lease); err != nil {
					t.Fatal("exact actual removal retry", err)
				}
			}
			if name == "cancelled-finish" {
				cancelled, stop := context.WithCancel(ctx)
				stop()
				if _, err = reservation.Finish(cancelled); err == nil || reservation.finished || source.baseline.crossTransfer == "" {
					t.Fatal("cancelled finish discarded original pin", err)
				}
			}
			if committed, err := reservation.Finish(ctx); err != nil || !committed {
				t.Fatal("actual retained result did not settle", committed, err)
			}
			if err = pin.Resolve(ctx); err != nil {
				t.Fatal(err)
			}
			if err = guardian.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err = destination.ObserveClosed(ctx); err != nil {
				t.Fatal(err)
			}
			if err = destination.Release(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
