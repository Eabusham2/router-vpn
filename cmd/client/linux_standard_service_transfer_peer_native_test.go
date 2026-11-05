//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
	"strings"
	"testing"
	"time"
)

// The original authenticated process/pidfd and service entrypoint are actual.
// No native policy is supplied: refusal must precede any creator acquisition.
func TestLinuxStandardServiceTransferRejectsUnadmittedReplay(t *testing.T) {
	for _, name := range []string{"history-full", "cancelled-full-history", "longer-inner-deadline", "late-original-deadline"} {
		t.Run(name, func(t *testing.T) {
			peer, _, _ := linuxStandardPeerFixture(t)
			ns, err := os.Stat("/proc/thread-self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			q := linuxStandardServiceTransferRequest{ID: strings.Repeat("a", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), Destination: linuxprotection.NodeSelection{SessionID: strings.Repeat("b", 32), SourceSHA256: strings.Repeat("c", 64), ConfigSHA256: strings.Repeat("d", 64), Policy: "on-connect"}, ProfileID: "original", ProfileRevision: strings.Repeat("e", 64)}
			request := linuxStandardServiceRequest{Schema: 1, Action: "transfer-reserve", Session: strings.Repeat("f", 32), BudgetMS: 5000, DeadlineNS: time.Now().Add(5 * time.Second).UnixNano(), Transfer: &q}
			s := &linuxStandardService{namespace: ns, gate: make(chan struct{}, 1), transferHistory: make(map[string]linuxStandardServiceTransferResponse)}
			s.gate <- struct{}{}
			s.session = &linuxStandardServiceSession{peer: peer, request: linuxStandardServiceRequest{Session: request.Session}}
			want := "history is full"
			if name == "history-full" || name == "cancelled-full-history" {
				for i := 0; i < 128; i++ {
					s.transferHistory[fmt.Sprint(i)] = linuxStandardServiceTransferResponse{}
				}
				if name == "cancelled-full-history" {
					cancel()
					want = "fixed original scope"
				}
			} else {
				original := q
				if name == "longer-inner-deadline" {
					q.DeadlineNS += int64(time.Minute)
					want = "exact original reservation"
				} else {
					original.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
					q = original
					want = "deadline exceeded"
				}
				s.transfer = &linuxStandardServiceTransfer{peer: peer, session: s.session, request: original, result: linuxStandardServiceTransferResponse{Intent: linuxprotection.StandardNodeTransfer{SourceSession: request.Session}}}
				request.Action = "transfer-commit"
			}
			retained := s.transfer
			out, err := s.transferRequest(ctx, peer, request)
			if err == nil || !strings.Contains(err.Error(), want) || s.transfer != retained || s.transfer != nil && s.transfer.native != nil || out != nil && out.Committed {
				t.Fatal("unadmitted request crossed original creator/deadline", out, err)
			}
		})
	}
}

// Native result is explicitly modeled as already positively finished here;
// original files, peer, process Stop, state removal and retry path are real.
// The separate namespace test must prove that actual native milestone.
type transferCloseRetryModel struct {
	legacyExitKernelProtection
	closes int
	saved  *legacyExitStateToken
}

func (p *transferCloseRetryModel) Close(ctx context.Context) error {
	p.closes++
	if err := p.legacyExitKernelProtection.Close(ctx); err != nil {
		return err
	}
	if p.closes == 1 && p.saved != nil {
		// Close only the original owned descriptor, then model the failed
		// saved-close return with an invalid descriptor. Never double-close
		// a live numeric FD that another goroutine might reuse.
		if err := p.saved.file.Close(); err != nil {
			return err
		}
		p.saved.file = os.NewFile(uintptr(1<<30), "explicit-invalid-saved-close-model")
		return nil
	}
	if p.closes == 1 {
		return errors.New("original native close completed before returned failure")
	}
	return nil
}
func TestLinuxStandardServiceTransferResumesFinishedNativeCleanup(t *testing.T) {
	for _, name := range []string{"native-close", "saved-close"} {
		t.Run(name, func(t *testing.T) {
			s, f, peer, request, ctx := standardNetworkSession(t, "on-connect")
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", false), nil); err != nil {
				t.Fatal(err)
			}
			slot := s.session.owner.protection
			lease, err := acquireLegacyExitMutationLease(ctx, s.root)
			if err != nil {
				t.Fatal(err)
			}
			if err = slot.kernel.Release(ctx, lease.lock); err != nil {
				lease.Close()
				t.Fatal(err)
			}
			slot.removed = true
			model := &transferCloseRetryModel{legacyExitKernelProtection: slot.kernel}
			slot.kernel = model
			q := linuxStandardServiceTransferRequest{ID: strings.Repeat("9", 32), DeadlineNS: time.Now().Add(time.Second).UnixNano(), Destination: linuxprotection.NodeSelection{SessionID: strings.Repeat("8", 32), SourceSHA256: strings.Repeat("7", 64), ConfigSHA256: strings.Repeat("6", 64), Policy: "on-connect"}, ProfileID: f.a.profiles.Profiles[0].ID, ProfileRevision: desktopOwnedNodeProfileToken(f.a.profiles.Profiles[0])}
			tr := &linuxStandardServiceTransfer{peer: peer, session: s.session, slot: slot, request: q, native: &mobiletor.DesktopLinuxStandardNodeTransfer{}, nativeFinished: true, result: linuxStandardServiceTransferResponse{Intent: linuxprotection.StandardNodeTransfer{ID: q.ID, SourceSession: request.Session}, Committed: true, Phase: "committed"}}
			s.transfer = tr
			s.transferHistory = make(map[string]linuxStandardServiceTransferResponse)
			if err = tr.persist(ctx, lease, "committed"); err != nil {
				lease.Close()
				t.Fatal(err)
			}
			lease.Close()
			if name == "saved-close" {
				model.saved = slot.saved
			}
			call := linuxStandardServiceRequest{Schema: 1, Action: "transfer-resolve", Session: request.Session, BudgetMS: 5000, DeadlineNS: time.Now().Add(5 * time.Second).UnixNano(), Transfer: &q}
			if _, err = s.transferRequest(ctx, peer, call); err == nil || !slot.stateRemoved || !s.transferPending() || tr.terminal() {
				t.Fatal("partial native close lost original pending cleanup", err)
			}
			response, err := s.transferRequest(ctx, peer, call)
			if err != nil || response == nil || !response.Committed || response.Phase != "settled" || !slot.closed || model.closes != 2 || s.transferPending() {
				t.Fatal("retry reopened deliberately retired source instead of original cleanup", response, err, model.closes)
			}
		})
	}
}
