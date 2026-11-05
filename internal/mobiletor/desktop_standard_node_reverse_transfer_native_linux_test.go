//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopLinuxGuardianKernelNodeStandardTransfer(t *testing.T) {
	for _, scenario := range []string{"original", "lost-ack-retry", "abort", "cancelled", "changed-successor", "successor-lost"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			source := linuxNodeBaselineFixture(t, false)
			transfer, err := source.ReserveStandardTransfer(ctx, strings.Repeat("9", 32))
			if err != nil {
				t.Fatal(err)
			}
			original, err := transfer.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = ReadDesktopLinuxClosedTransferExclusive(ctx, original); err != nil {
				t.Fatal("original source exclusive read", err)
			}
			lease, err := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			destination := linuxStandardProtectionFixture(t, lease)
			// The fixture's literal endpoint is part of the actual creator's policy.
			pin, err := destination.PinNodePredecessor(ctx, strings.Repeat("9", 32), []netip.Addr{netip.MustParseAddr("198.18.0.2")}, lease)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				source.crossTransfer = ""
				destination.baseline.crossTransfer = ""
				_ = source.Close(context.Background())
				_ = destination.Close(context.Background())
			}()
			successor, err := pin.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if source.Release(ctx) == nil || source.Close(ctx) == nil || destination.Release(ctx, lease) == nil || destination.Close(ctx) == nil {
				t.Fatal("either pinned original could be discarded")
			}
			if err = ReadDesktopLinuxClosedTransferCurrent(ctx, original); err != nil {
				t.Fatal("actual source beside owned successor", err)
			}
			switch scenario {
			case "cancelled":
				expired, stop := context.WithCancel(ctx)
				stop()
				if transfer.Commit(expired, successor) == nil || source.ObserveClosed(ctx) != nil {
					t.Fatal("expired transfer removed original source")
				}
				return
			case "changed-successor":
				successor.NamespaceInode++
				if transfer.Commit(ctx, successor) == nil || source.ObserveClosed(ctx) != nil {
					t.Fatal("foreign successor removed original source")
				}
				return
			case "successor-lost":
				if _, err = desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", destination.baseline.nft.TableName}, ""); err != nil {
					t.Fatal(err)
				}
				if transfer.Commit(ctx, successor) == nil || source.ObserveClosed(ctx) != nil {
					t.Fatal("missing successor removed original source")
				}
				return
			case "abort":
				if err = pin.Resolve(ctx, original, false); err != nil {
					t.Fatal(err)
				}
				if err = destination.Release(ctx, lease); err != nil {
					t.Fatal(err)
				}
				committed, e := transfer.Finish(ctx)
				if e != nil || committed || source.ObserveClosed(ctx) != nil {
					t.Fatal("abort failed to preserve original", committed, e)
				}
				next, e := source.ReserveStandardTransfer(ctx, strings.Repeat("8", 32))
				if e != nil {
					t.Fatal("next original reservation", e)
				}
				if committed, e = transfer.Finish(ctx); e != nil || committed || source.crossTransfer != next.id {
					t.Fatal("old abort acknowledgement cleared replacement reservation", committed, e)
				}
				return
			}
			if err = transfer.Commit(ctx, successor); err != nil {
				t.Fatal("actual conditional source removal", err)
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
