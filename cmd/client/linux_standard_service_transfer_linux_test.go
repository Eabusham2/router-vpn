//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"router-vpn/internal/linuxprotection"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLinuxStandardServiceTransferRequiresNativeAndDurableSettlement(t *testing.T) {
	for _, name := range []string{"reserved", "entered", "committed", "aborted-before-native-finish", "aborted-pending-write", "settled-pending-write", "aborted", "settled"} {
		t.Run(name, func(t *testing.T) {
			transfer := &linuxStandardServiceTransfer{result: linuxStandardServiceTransferResponse{Phase: name}, nativeFinished: true}
			switch name {
			case "aborted-before-native-finish":
				transfer.result.Phase = "aborted"
				transfer.nativeFinished = false
			case "aborted-pending-write":
				transfer.result.Phase = "aborted"
				transfer.pendingPhase = "aborted"
			case "settled-pending-write":
				transfer.result.Phase = "settled"
				transfer.pendingPhase = "committed"
			}
			service := &linuxStandardService{transfer: transfer}
			done := name == "aborted" || name == "settled"
			if transfer.terminal() != done || service.transferPending() == done {
				t.Fatal("unfinished original native pin/write became terminal")
			}
		})
	}
}

// The explicit reply model tests controller synchronization only. Actual native
// transfer is mandatory in the installed namespace suite.
func TestLinuxStandardServiceTransferSerializesOriginalRecovery(t *testing.T) {
	for _, name := range []string{"held-current", "held-resolve", "held-commit", "concurrent-resolve"} {
		t.Run(name, func(t *testing.T) {
			operation, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			o := &linuxStandardServiceLaunch{app: &app{}, peer: &linuxStandardServicePeer{}, request: linuxStandardServiceRequest{Session: strings.Repeat("a", 32), ConfigSHA256: strings.Repeat("b", 64)}}
			q := linuxStandardServiceTransferRequest{ID: strings.Repeat("c", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), Destination: linuxprotection.NodeSelection{SessionID: strings.Repeat("d", 32), SourceSHA256: strings.Repeat("e", 64), ConfigSHA256: strings.Repeat("f", 64), Policy: "on-connect"}, ProfileID: "original", ProfileRevision: strings.Repeat("1", 64)}
			transfer := &linuxStandardServiceNodeTransfer{owner: o, host: &desktopLinuxNodeHost{}, operation: operation, request: q}
			o.transfer = transfer
			linuxStandardServiceOwners.Store(o.app, o)
			defer linuxStandardServiceOwners.Delete(o.app)
			calls := 0
			o.exchange = func(context.Context, linuxStandardServiceRequest, *os.File, func()) (linuxStandardServiceResponse, error) {
				calls++
				return linuxStandardServiceResponse{Transfer: &linuxStandardServiceTransferResponse{Intent: linuxprotection.StandardNodeTransfer{ID: q.ID, DeadlineNS: q.DeadlineNS, SourceSession: o.request.Session, SourceConfigSHA256: o.request.ConfigSHA256, SourceReceiptSHA256: strings.Repeat("2", 64), Destination: q.Destination, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision}, Phase: "aborted"}}, nil
			}
			if name == "concurrent-resolve" {
				var wg sync.WaitGroup
				for i := 0; i < 16; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := transfer.resolve(operation); err != nil {
							t.Error(err)
						}
						_ = transfer.journalIntent()
						_ = transfer.committed.Load()
						_ = transfer.resolved.Load()
					}()
				}
				wg.Wait()
				if calls != 1 || !transfer.resolved.Load() || transfer.committed.Load() {
					t.Fatal("original recovery was repeated or changed", calls)
				}
				return
			}
			transfer.mu.Lock()
			bounded, finish := context.WithTimeout(operation, 20*time.Millisecond)
			defer finish()
			var err error
			switch name {
			case "held-current":
				err = transfer.current(bounded, true)
			case "held-resolve":
				err = transfer.resolve(bounded)
			case "held-commit":
				err = transfer.commit(bounded, nil, linuxprotection.NodePreparedRecord{})
			}
			transfer.mu.Unlock()
			if !errors.Is(err, context.DeadlineExceeded) || calls != 0 || transfer.resolved.Load() || transfer.intent.Load() != nil {
				t.Fatal("lock wait extended original budget or published work", err, calls)
			}
		})
	}
}

func TestLinuxStandardServiceTransferKeepsOriginalStartupBudget(t *testing.T) {
	for _, name := range []string{"earlier-startup", "earlier-transfer", "cancelled-startup"} {
		t.Run(name, func(t *testing.T) {
			first := time.Now().Add(time.Second)
			second := first.Add(time.Second)
			startupDeadline, transferDeadline := first, second
			if name == "earlier-transfer" {
				startupDeadline, transferDeadline = second, first
			}
			startup, stop := context.WithDeadline(context.Background(), startupDeadline)
			defer stop()
			tx := &desktopLinuxNodeTransaction{startup: startup, standardTransfer: &linuxStandardServiceNodeTransfer{request: linuxStandardServiceTransferRequest{DeadlineNS: transferDeadline.UnixNano()}}}
			call, cancel, err := tx.startupCall(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			if actual, ok := call.Deadline(); !ok || !actual.Equal(first) {
				t.Fatal("transfer extended earlier original budget", actual, first)
			}
			if name == "cancelled-startup" {
				stop()
				select {
				case <-call.Done():
					if !errors.Is(call.Err(), context.Canceled) {
						t.Fatal(call.Err())
					}
				case <-time.After(time.Second):
					t.Fatal("transfer ignored original startup cancellation")
				}
			}
		})
	}
}
