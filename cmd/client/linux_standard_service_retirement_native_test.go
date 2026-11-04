//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
	"strings"
	"testing"
	"time"
)

func TestLinuxStandardServiceRetirementRequiresOriginalResultAndRouting(t *testing.T) {
	for _, scenario := range []string{"complete", "nonzero", "signal", "foreign-completion", "routing-route", "routing-rule", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			child := "complete"
			if scenario == "nonzero" {
				child = "exit-error"
			}
			s, f, observer := linuxStandardStartupFixture(t, child)
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
				t.Fatal("actual original engine startup", err)
			}
			owner := s.session.owner
			completion := owner.completion
			if completion == nil || completion.command != owner.command || completion.done != owner.done {
				t.Fatal("creating goroutine did not retain original result owner")
			}
			if scenario == "signal" {
				if err := owner.command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-owner.done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if scenario == "foreign-completion" {
				owner.completion = &linuxLegacyExitCompletion{command: &exec.Cmd{}, done: owner.done}
			}
			if strings.HasPrefix(scenario, "routing-") {
				observer.routingFailure = errors.New("original " + scenario + " remains")
			}
			stop := ctx
			if scenario == "cancelled" {
				cancelled, end := context.WithCancel(ctx)
				end()
				stop = cancelled
			}
			err := s.retire(stop, true)
			if scenario == "complete" {
				if err != nil || !s.session.joined || !owner.protection.removed || observer.retirementReads != 1 || completion.state == nil || completion.failure != nil {
					t.Fatal("complete original retirement was refused", err)
				}
				return
			}
			if err == nil || s.session.joined || !s.session.cleanupPending || owner.protection.removed || owner.receipt != nil {
				t.Fatal("failed native cleanup claimed Off/absence", err)
			}
			actual, present := legacyStandardExitOwners.Load(owner.app)
			if !present || actual != owner || s.session.owner != owner {
				t.Fatal("failed cleanup lost original retry owner")
			}
			if scenario == "nonzero" || scenario == "signal" {
				if completion.failure == nil || observer.retirementReads != 0 || !owner.processRetired {
					t.Fatal("native error/signal became successful cleanup", completion.failure, observer.retirementReads)
				}
				if retry := s.retire(ctx, true); retry == nil || owner.protection.removed {
					t.Fatal("original failed completion was forgotten by retry", retry)
				}
				return
			}
			if strings.HasPrefix(scenario, "routing-") && (completion.failure != nil || completion.state == nil || !completion.state.Success() || observer.retirementReads != 1) {
				t.Fatal("route refusal did not follow actual successful child join")
			}
			owner.completion = completion
			observer.routingFailure = nil
			if err := s.retire(ctx, true); err != nil || !s.session.joined || !owner.protection.removed {
				t.Fatal("same original evidence did not complete a fresh retry", err)
			}
		})
	}
}

// The first Stop reaches the actual same sealed child and its original result
// descriptor, then expires inside an explicit model native cleanup callback.
// A later Stop must recover that original child rather than kill/recreate it.
func TestLinuxStandardServiceRetirementRetriesOriginalLiveChild(t *testing.T) {
	s, f, observer := linuxStandardStartupFixture(t, "cleanup-retry")
	peer, _, _ := linuxStandardPeerFixture(t)
	request, directory := linuxStandardServiceRequestFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
		t.Fatal(err)
	}
	owner := s.session.owner
	command, originalPIDFD, completion := owner.command, owner.originalPIDFD, owner.completion
	short, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	err := s.retire(short, true)
	stop()
	if err == nil || owner.processRetired || owner.protection.removed || owner.receipt != nil || !s.session.cleanupPending {
		t.Fatal("expired native cleanup fabricated retirement", err)
	}
	select {
	case <-owner.done:
		t.Fatal("deadline killed the retained original child")
	default:
	}
	result, err := owner.native.cleanup.ReadResult(owner.native.captureSHA)
	// The caller and child share the exact deadline; wait only for the bounded
	// result publication, never for a replacement process or renewed attempt.
	until := time.Now().Add(time.Second)
	for err != nil && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
		result, err = owner.native.cleanup.ReadResult(owner.native.captureSHA)
	}
	if err != nil || result.Complete || result.Sequence != 1 {
		t.Fatal("original pending cleanup not observable", result, err)
	}
	if err := s.retire(ctx, true); err != nil {
		t.Fatal("fresh original Stop did not recover", err)
	}
	if owner.command != command || owner.originalPIDFD != originalPIDFD || owner.completion != completion || !owner.processRetired || !owner.protection.removed || !s.session.joined || observer.retirementReads != 1 {
		t.Fatal("retry replaced original child or cleanup authority")
	}
}

func TestLinuxStandardServiceRetirementBoundsOutstandingAttempts(t *testing.T) {
	for _, scenario := range []string{"unsettled", "settled-failures", "complete-retained", "foreign-failure"} {
		t.Run(scenario, func(t *testing.T) {
			file, err := standardengine.NewCleanupFile()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			n := &linuxStandardEngine{cleanup: file, captureSHA: strings.Repeat("a", 64)}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i := 1; i <= 80; i++ {
				err := n.requestCleanup(ctx)
				if scenario != "settled-failures" && i == 33 {
					if err == nil || len(n.cleanupRequests) != 32 || n.cleanupSequence != 32 {
						t.Fatal("unsettled original attempts were unbounded or forgotten", err)
					}
					return
				}
				if err != nil {
					t.Fatal("settled original failure blocked recoverable retry", i, err)
				}
				if len(n.cleanupRequests) > 32 {
					t.Fatal("unbounded attempt history")
				}
				if scenario == "unsettled" {
					continue
				}
				result := standardengine.CleanupResult{Schema: 1, CaptureSHA256: n.captureSHA, Sequence: n.cleanupSequence, DeadlineNS: n.cleanupDeadline, StartedNS: time.Now().UnixNano(), Authority: "request", Error: "actual original pending cleanup"}
				if scenario == "complete-retained" {
					result.Complete = true
					result.Error = ""
					result.Ledger = "actual complete original ledger"
				}
				if scenario == "foreign-failure" {
					result.DeadlineNS--
				}
				if err := file.WriteResult(result); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "settled-failures" || len(n.cleanupRequests) != 1 || n.cleanupSequence != 80 {
				t.Fatal("failed attempts were not settled under original evidence")
			}
		})
	}
}

func TestLinuxStandardServiceRetirementRejectsUnboundFinalResult(t *testing.T) {
	for _, scenario := range []string{"absent", "foreign-source", "unknown-attempt", "changed-deadline", "foreign-tun", "no-constructor", "startup-extension"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, _ := linuxStandardStartupFixture(t, "complete")
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
				t.Fatal(err)
			}
			owner := s.session.owner
			n := owner.native
			if err := n.requestCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := owner.command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case <-owner.done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			result, err := n.cleanup.ReadResult(n.captureSHA)
			if err != nil || !result.Complete {
				t.Fatal("original complete result absent", err)
			}
			original := result
			switch scenario {
			case "absent":
				if _, err := n.cleanup.File().WriteAt(make([]byte, 60<<10), 4096); err != nil {
					t.Fatal(err)
				}
			case "foreign-source":
				result.CaptureSHA256 = strings.Repeat("b", 64)
			case "unknown-attempt":
				result.Sequence++
			case "changed-deadline":
				result.DeadlineNS--
			case "foreign-tun", "no-constructor":
				receipt, err := desktopnetwork.ParseDesktopNetworkRetirementReceipt(result.Ledger)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "foreign-tun" {
					receipt.Incarnation = strings.Repeat("e", 32)
				} else {
					receipt = desktopnetwork.DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Objects: []desktopnetwork.DesktopNetworkObject{}}
				}
				result.Ledger, err = desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(receipt)
				if err != nil {
					t.Fatal(err)
				}
			case "startup-extension":
				raw, err := standardengine.ReadSealed(n.capture, 2048)
				if err != nil {
					t.Fatal(err)
				}
				capture, err := standardengine.DecodeCapture(raw, n.captureSHA)
				if err != nil {
					t.Fatal(err)
				}
				result.Sequence = 0
				result.Authority = "startup"
				result.StartupFailed = true
				result.DeadlineNS = capture.DeadlineNS + 1
				result.StartedNS = result.DeadlineNS - int64(time.Second)
			}
			if scenario != "absent" {
				if err := n.cleanup.WriteResult(result); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.retire(ctx, true); err == nil || s.session.joined || owner.receipt != nil || owner.protection.removed {
				t.Fatal("unbound final result fabricated native cleanup", scenario, err)
			}
			if err := n.cleanup.WriteResult(original); err != nil {
				t.Fatal(err)
			}
			if err := s.retire(ctx, true); err != nil || !s.session.joined {
				t.Fatal("original captured result could not finish retry", err)
			}
		})
	}
}
