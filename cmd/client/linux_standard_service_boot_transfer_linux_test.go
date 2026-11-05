//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/linuxprotection"
	"strings"
	"testing"
	"time"
)

func TestLinuxStandardServiceBootTransferRetainsExactSource(t *testing.T) {
	for _, name := range []string{"original", "replacement-boot", "engine-not-joined", "cleanup-pending", "wrong-session", "peer-close-pending", "peer-closed"} {
		t.Run(name, func(t *testing.T) {
			slot := &legacyExitProtectionSlot{detached: true}
			transfer := &linuxStandardServiceTransfer{slot: slot, request: linuxStandardServiceTransferRequest{Boot: true}, nativeFinished: true, result: linuxStandardServiceTransferResponse{Boot: true, Phase: "aborted"}}
			service := &linuxStandardService{boot: slot}
			switch name {
			case "replacement-boot":
				service.boot = &legacyExitProtectionSlot{detached: true}
			case "engine-not-joined":
				service.session = &linuxStandardServiceSession{}
			case "cleanup-pending":
				service.session = &linuxStandardServiceSession{joined: true, cleanupPending: true}
			case "wrong-session":
				transfer.session = &linuxStandardServiceSession{}
			case "peer-closed":
				transfer.bootPeerClosed = true
			}
			valid := name != "replacement-boot" && name != "engine-not-joined" && name != "cleanup-pending" && name != "wrong-session"
			if transfer.sourceJoined(service) != valid {
				t.Fatal("boot succession borrowed another creator/engine lifetime")
			}
			if transfer.terminal() != (name == "peer-closed") {
				t.Fatal("boot reservation forgot retained authenticated peer cleanup")
			}
		})
	}
}
func TestLinuxStandardServiceBootTransferUnsentAndCancelledCleanup(t *testing.T) {
	for _, name := range []string{"unsent", "cancelled", "replacement"} {
		t.Run(name, func(t *testing.T) {
			app := &app{}
			original := &linuxStandardServiceNodeTransfer{boot: &linuxStandardServiceBootTransferSource{app: app}}
			linuxStandardBootTransfers.Store(app, original)
			defer linuxStandardBootTransfers.Delete(app)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if name == "cancelled" {
				cancel()
			}
			var successor *linuxStandardServiceNodeTransfer
			if name == "replacement" {
				successor = &linuxStandardServiceNodeTransfer{}
				linuxStandardBootTransfers.Store(app, successor)
			}
			err := original.resolve(ctx)
			actual, present := linuxStandardBootTransfers.Load(app)
			switch name {
			case "unsent":
				if err != nil || present || !original.resolved.Load() {
					t.Fatal("unsent boot capture was not joined", err)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) || !present || actual != original || original.resolved.Load() {
					t.Fatal("cancelled cleanup discarded original capture", err)
				}
			case "replacement":
				if err == nil || !present || actual != successor || original.resolved.Load() {
					t.Fatal("old cleanup cleared successor", err)
				}
			}
		})
	}
}
func TestLinuxStandardServiceBootTransferSourceKindsRemainDistinct(t *testing.T) {
	owner := &linuxStandardServiceLaunch{request: linuxStandardServiceRequest{Session: strings.Repeat("a", 32), ConfigSHA256: strings.Repeat("b", 64)}}
	regular := &linuxStandardServiceNodeTransfer{owner: owner}
	boot := &linuxStandardServiceNodeTransfer{boot: &linuxStandardServiceBootTransferSource{}, request: linuxStandardServiceTransferRequest{Boot: true}}
	intent := bootTransferTestIntent()
	if regular.matchesSourceIntent(intent) {
		t.Fatal("active engine accepted unrelated boot source")
	}
	intent.SourceSession = owner.request.Session
	intent.SourceConfigSHA256 = owner.request.ConfigSHA256
	if !regular.matchesSourceIntent(intent) {
		t.Fatal("original active source rejected")
	}
	boot.owner = owner
	if boot.matchesSourceIntent(intent) {
		t.Fatal("boot source fabricated a simultaneous engine launch")
	}
}

func bootTransferTestIntent() linuxprotection.StandardNodeTransfer {
	return linuxprotection.StandardNodeTransfer{ID: strings.Repeat("c", 32), DeadlineNS: time.Now().Add(time.Minute).UnixNano(), SourceSession: strings.Repeat("d", 32), SourceConfigSHA256: strings.Repeat("e", 64), SourceReceiptSHA256: strings.Repeat("f", 64), Destination: linuxprotection.NodeSelection{SessionID: strings.Repeat("1", 32), SourceSHA256: strings.Repeat("2", 64), ConfigSHA256: strings.Repeat("3", 64), Policy: "on-connect"}, ProfileID: "control", ProfileRevision: strings.Repeat("4", 64)}
}
