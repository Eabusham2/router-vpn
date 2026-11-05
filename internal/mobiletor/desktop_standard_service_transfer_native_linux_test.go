//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDesktopLinuxGuardianKernelStandardImageTransfer(t *testing.T) {
	for _, scenario := range []string{"original", "lost-ack-retry", "abort", "cancelled", "changed-successor", "successor-lost", "wrong-lease", "lease-reopen", "successor-lost-after", "changed-native-policy", "abort-before-successor-removal", "cancelled-result-after-removal"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			lease, err := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			source := linuxStandardProtectionFixture(t, lease)
			transfer, err := source.ReserveImageTransfer(ctx, strings.Repeat("9", 32), lease)
			if err != nil {
				t.Fatal(err)
			}
			defer transfer.lease.close()
			original, err := transfer.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = ReadDesktopLinuxClosedTransferExclusive(ctx, original); err != nil {
				t.Fatal(err)
			}
			if scenario == "lease-reopen" {
				name := lease.Name()
				if err = lease.Close(); err != nil {
					t.Fatal(err)
				}
				lease, err = os.OpenFile(name, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				if err = syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal("retained comparison descriptor kept cross-process mutation lock", err)
				}
			}
			destination := linuxStandardProtectionFixture(t, lease)
			// Both policies come from the actual original acknowledged creators.
			pin, err := destination.PinImagePredecessor(ctx, strings.Repeat("9", 32), lease)
			if err != nil {
				t.Fatal(err)
			}
			defer pin.lease.close()
			defer func() {
				source.baseline.crossTransfer = ""
				destination.baseline.crossTransfer = ""
				_ = source.Close(context.Background())
				_ = destination.Close(context.Background())
			}()
			successor, err := pin.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if source.Release(ctx, lease) == nil || source.Close(ctx) == nil || destination.Release(ctx, lease) == nil || destination.Close(ctx) == nil {
				t.Fatal("either pinned original could be discarded")
			}
			if err = ReadDesktopLinuxClosedTransferCurrent(ctx, original); err != nil {
				t.Fatal("actual source beside owned successor", err)
			}
			switch scenario {
			case "wrong-lease":
				wrong, e := os.OpenFile(t.TempDir()+"/foreign.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					t.Fatal(e)
				}
				defer wrong.Close()
				if transfer.Commit(ctx, successor, wrong) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("unrelated mutation lease removed original source")
				}
				return
			case "cancelled":
				expired, stop := context.WithCancel(ctx)
				stop()
				if transfer.Commit(expired, successor, lease) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("expired transfer removed original source")
				}
				return
			case "changed-successor":
				successor.NamespaceInode++
				if transfer.Commit(ctx, successor, lease) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("foreign successor removed original source")
				}
				return
			case "changed-native-policy":
				if _, err = desktopLinuxNFTCommand(ctx, []string{"add", "rule", "inet", destination.baseline.nft.TableName, "output", "accept"}, ""); err != nil {
					t.Fatal(err)
				}
				if transfer.Commit(ctx, successor, lease) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("changed actual successor policy removed source")
				}
				return
			case "successor-lost":
				if _, err = desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", destination.baseline.nft.TableName}, ""); err != nil {
					t.Fatal(err)
				}
				if transfer.Commit(ctx, successor, lease) == nil || source.Current(ctx, lease) != nil {
					t.Fatal("missing successor removed original source")
				}
				return
			case "abort", "abort-before-successor-removal":
				if err = pin.Resolve(ctx, original, false); err != nil {
					t.Fatal(err)
				}
				if scenario == "abort-before-successor-removal" {
					if committed, e := transfer.Finish(ctx); e == nil || committed || transfer.finished || source.baseline.crossTransfer != transfer.id {
						t.Fatal("premature abort discarded source pin before actual candidate removal", committed, e)
					}
				}
				if err = destination.Release(ctx, lease); err != nil {
					t.Fatal(err)
				}
				committed, e := transfer.Finish(ctx)
				if e != nil || committed || source.Current(ctx, lease) != nil {
					t.Fatal("abort failed to preserve original", committed, e)
				}
				next, e := source.ReserveImageTransfer(ctx, strings.Repeat("8", 32), lease)
				if e != nil {
					t.Fatal("next original reservation", e)
				}
				defer next.lease.close()
				if committed, e = transfer.Finish(ctx); e != nil || committed || source.baseline.crossTransfer != next.id {
					t.Fatal("old abort acknowledgement cleared replacement reservation", committed, e)
				}
				return
			}
			if err = transfer.Commit(ctx, successor, lease); err != nil {
				t.Fatal("actual conditional source removal", err)
			}
			if scenario == "cancelled-result-after-removal" {
				expired, stop := context.WithCancel(ctx)
				stop()
				for _, observe := range []func(context.Context) (bool, error){transfer.Result, transfer.Finish} {
					committed, e := observe(expired)
					if committed || !errors.Is(e, context.Canceled) || transfer.finished || source.baseline.crossTransfer != transfer.id {
						t.Fatal("expired post-removal observation lost retained original result", committed, e)
					}
				}
				// The next bounded read must recover the actual acknowledged
				// removal, never misclassify an expired read as a safe abort.
				committed, e := transfer.Result(ctx)
				if !committed || e != nil || transfer.finished || source.baseline.crossTransfer != transfer.id {
					t.Fatal("fresh original observation lost acknowledged removal", committed, e)
				}
			}
			if scenario == "successor-lost-after" {
				if _, err = desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", destination.baseline.nft.TableName}, ""); err != nil {
					t.Fatal(err)
				}
				if committed, e := transfer.Result(ctx); e == nil || committed {
					t.Fatal("lost successor converted to committed transfer", committed, e)
				}
				if committed, e := transfer.Finish(ctx); e == nil || committed || transfer.finished || source.baseline.crossTransfer != transfer.id {
					t.Fatal("lost successor released original pin", committed, e)
				}
				return
			}
			committed, err := transfer.Result(ctx)
			if err != nil || !committed {
				t.Fatal("actual original result", committed, err)
			}
			if err = pin.Resolve(ctx, original, true); err != nil {
				t.Fatal("actual source absence acknowledgement", err)
			}
			if committed, err = transfer.Finish(ctx); err != nil || !committed {
				t.Fatal("source finish after successor acknowledgement", committed, err)
			}
			if scenario == "lost-ack-retry" {
				if committed, err = transfer.Finish(ctx); err != nil || !committed {
					t.Fatal("source result retry", committed, err)
				}
				if err = pin.Resolve(ctx, original, true); err != nil {
					t.Fatal("lost ack retry", err)
				}
				newPin, e := destination.PinImagePredecessor(ctx, strings.Repeat("8", 32), lease)
				if e != nil {
					t.Fatal(e)
				}
				defer newPin.lease.close()
				if e = pin.Resolve(ctx, original, true); e != nil || destination.baseline.crossTransfer != newPin.id {
					t.Fatal("stale successor acknowledgement cleared next pin", e)
				}
				// This test owns the unused reservation; discharge it against the
				// same actual source absence before final original release.
				if e = newPin.Resolve(ctx, original, true); e != nil {
					t.Fatal(e)
				}
				if pin.Resolve(ctx, original, false) == nil {
					t.Fatal("committed pin accepted changed abort")
				}
			}
			if destination.Current(ctx, lease) != nil {
				t.Fatal("original successor not preserved after source removal")
			}
			if err = destination.Release(ctx, lease); err != nil {
				t.Fatal(err)
			}
		})
	}
}
