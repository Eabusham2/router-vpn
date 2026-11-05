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
	"syscall"
	"testing"
	"time"
)

func standardMTUStopHistoryFixture(t *testing.T, publish bool) (context.Context, *linuxStandardServiceMTU, *standardengine.OperationFile) {
	t.Helper()
	ctx, m, child := standardMTUAdmissionPair(t)
	report, ready := standardMTUReportFixture(t)
	key := report.Command.Reservation.Key
	deadline, _ := ctx.Deadline()
	key.DeadlineNS = deadline.UnixNano()
	reservation, err := m.native.operations.Reserve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	report.Command.Reservation = reservation
	if err = m.native.operations.SubmitCommand(ctx, report.Command); err != nil {
		t.Fatal(err)
	}
	m.active = &linuxStandardServiceMTUOperation{command: report.Command, original: ready, reserved: true, submitted: true}
	owner := &linuxLegacyStandardExitOwner{native: m.native}
	m.native.owner = owner
	m.session = &linuxStandardServiceSession{owner: owner, mtu: m}
	m.native.mtuStopOwner = m
	original, err := desktopnetwork.ParseDesktopNetworkReceipt(ready)
	if err != nil {
		t.Fatal(err)
	}
	m.native.retainRoutingReceipt(original)
	if publish {
		for role, e := range report.Readers {
			if e == nil {
				continue
			}
			r := standardengine.OperationRole(role)
			if r != standardengine.OriginalReader {
				if err = child.BindReader(ctx, reservation, r, e.Binding); err != nil {
					t.Fatal(err)
				}
			}
			if len(e.Ready) != 0 {
				if err = child.PublishEvidence(ctx, reservation, r, standardengine.ReadyEvidence, e.Ready); err != nil {
					t.Fatal(err)
				}
			}
			if len(e.Retirement) != 0 {
				if err = child.PublishEvidence(ctx, reservation, r, standardengine.RetirementEvidence, e.Retirement); err != nil {
					t.Fatal(err)
				}
			}
		}
		report.Result.Digest = ""
		if err = child.PublishResult(ctx, reservation, report.Result); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, m, child
}

func TestLinuxStandardMTUStopHandsPendingCallToFD10(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "initial"
		if closed {
			name = "retry-closed-observer"
		}
		t.Run(name, func(t *testing.T) {
			ctx, m, child := standardMTUStopHistoryFixture(t, false)
			m.session.network = &linuxStandardServiceNetwork{closed: closed}
			bound, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			if err := m.drainForStop(bound); err != nil {
				t.Fatal("pending actual FD11 blocked original FD10 Stop", err)
			}
			cancelled, err := child.Cancelled(ctx, m.active.command.Reservation)
			if err != nil || !cancelled {
				t.Fatal("original native cancellation was not recorded", cancelled, err)
			}
			if m.active.ended || m.active.settled || m.active.report != nil || m.active.historyValid || m.native.routingReceipt.MTU != 1500 {
				t.Fatal("Stop handoff invented joined/adopted native history")
			}
			if deadline, err := child.ReadCleanupRequest(ctx, m.active.command.Reservation, 0); err != nil && !errors.Is(err, standardengine.ErrNoOperation) || deadline != 0 {
				t.Fatal("Stop renewed optimizer cleanup instead of using FD10", deadline, err)
			}
		})
	}
}

func TestLinuxStandardMTUStopRetainsActualJoinedHistory(t *testing.T) {
	for _, scenario := range []string{"joined", "missing", "changed-reservation", "torn-page", "replacement-session", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, m, child := standardMTUStopHistoryFixture(t, scenario != "missing")
			old := m.native.routingReceipt
			switch scenario {
			case "changed-reservation":
				m.active.command.Reservation.Key.ID = strings.Repeat("f", 32)
			case "torn-page":
				if _, err := child.File().WriteAt([]byte{0xff}, standardengine.OperationControlSize); err != nil {
					t.Fatal(err)
				}
			case "replacement-session":
				m.session.mtu = &linuxStandardServiceMTU{}
			case "expired":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			err := m.retainStoppedHistory(ctx)
			if scenario == "joined" {
				if err != nil || !m.active.historyValid || m.active.report == nil || m.active.ended || m.active.settled || m.native.routingReceipt.MTU != 1400 || len(m.native.mtuRetirements) != 1 {
					t.Fatal("actual cleanup history missing or became healthy settlement", err)
				}
				if err = m.retainStoppedHistory(ctx); err != nil || len(m.native.mtuRetirements) != 1 {
					t.Fatal("same original retry changed history", err)
				}
			} else if err == nil || m.active.historyValid || m.native.routingReceipt != old || len(m.native.mtuRetirements) != 0 {
				t.Fatal("unproved FD11 history changed final retirement authority", err)
			}
			if scenario == "expired" && !errors.Is(err, context.Canceled) {
				t.Fatal("caller expiry lost its identity", err)
			}
		})
	}
}

func TestLinuxStandardMTUControllerStopSignalsBeforeHistory(t *testing.T) {
	for _, scenario := range []string{"joined-history", "torn-cached-history"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, m, child := standardMTUStopHistoryFixture(t, false)
			peer, _, _ := linuxStandardPeerFixture(t)
			m.session.peer = peer
			m.session.request.Session = strings.Repeat("1", 32)
			namespace, err := os.Open("/proc/thread-self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			defer namespace.Close()
			info, err := namespace.Stat()
			if err != nil {
				t.Fatal(err)
			}
			observer := &linuxStandardStartupObserverFixture{}
			prepared := &linuxLegacyStandardExitOwner{command: &exec.Cmd{}, namespace: namespace, namespaceInfo: info}
			epoch := &linuxStandardRequestEpoch{owner: prepared, namespace: namespace, namespaceInfo: info, observer: observer, cancel: func() {}, mtuReceipt: m.ready, mtuBinding: m.current, mtuTransition: &linuxStandardControllerMTUTransition{key: m.active.command.Reservation.Key, original: m.ready}}
			prepared.requestEpoch = epoch
			a := &app{cmd: prepared.command, connectionContext: ctx}
			launch := &linuxStandardServiceLaunch{app: a, prepared: prepared, peer: peer, attempted: true, request: linuxStandardServiceRequest{Session: m.session.request.Session}}
			owner := &linuxStandardServiceMTUOwner{launch: launch, pending: &linuxStandardServiceMTURequest{ID: m.active.command.Reservation.Key.ID, MTU: m.active.command.MTU, DeadlineNS: m.active.command.Reservation.Key.DeadlineNS, Expected: &m.active.command.Reservation.Key.Original, Reservation: &m.active.command.Reservation}}
			launch.mtuOwner = owner
			linuxStandardServiceOwners.Store(a, launch)
			defer linuxStandardServiceOwners.Delete(a)
			stopped := false
			actions := []string{}
			service := &linuxStandardService{session: m.session}
			launch.exchange = func(call context.Context, request linuxStandardServiceRequest, _ *os.File, _ func()) (linuxStandardServiceResponse, error) {
				if call != ctx {
					t.Fatal("Stop renewed original caller")
				}
				actions = append(actions, request.Action)
				response := linuxStandardServiceResponse{authenticatedPeer: peer}
				if request.Action == "stop" {
					if stopped || observer.closed || epoch.mtuTransition == nil {
						t.Fatal("Stop lost original controller token before native join")
					}
					stopped = true
					// Explicit FD10 completion boundary model: the actual FD11 child pages are
					// published only when the real client sends its original service Stop.
					report, _ := standardMTUReportFixture(t)
					report.Command = m.active.command
					for role, e := range report.Readers {
						if e == nil {
							continue
						}
						r := standardengine.OperationRole(role)
						if r != standardengine.OriginalReader {
							if err := child.BindReader(ctx, report.Command.Reservation, r, e.Binding); err != nil {
								t.Fatal(err)
							}
						}
						if len(e.Ready) > 0 {
							if err := child.PublishEvidence(ctx, report.Command.Reservation, r, standardengine.ReadyEvidence, e.Ready); err != nil {
								t.Fatal(err)
							}
						}
						if len(e.Retirement) > 0 {
							if err := child.PublishEvidence(ctx, report.Command.Reservation, r, standardengine.RetirementEvidence, e.Retirement); err != nil {
								t.Fatal(err)
							}
						}
					}
					report.Result.Digest = ""
					if err := child.PublishResult(ctx, report.Command.Reservation, report.Result); err != nil {
						t.Fatal(err)
					}
					if err := m.retainStoppedHistory(ctx); err != nil {
						t.Fatal(err)
					}
					m.session.joined = true
					return response, nil
				}
				if !stopped {
					t.Fatal("controller waited for held native history before signaling FD10")
				}
				response.MTU, err = service.retiredMTUResponse(request, peer)
				if scenario == "torn-cached-history" && request.Action == "mtu-evidence" && err == nil {
					response.MTU.Evidence = append([]byte(nil), response.MTU.Evidence...)
					response.MTU.Evidence[0] ^= 0xff
				}
				return response, err
			}
			stop := &linuxStandardServiceStop{owner: launch, command: prepared.command, operation: ctx}
			launch.mu.Lock()
			sent, err := stop.stopPendingMTULocked(ctx, true)
			launch.mu.Unlock()
			if !sent || !stopped || len(actions) == 0 || actions[0] != "stop" {
				t.Fatal("actual original service Stop was not first", actions, err)
			}
			if scenario == "joined-history" {
				if err != nil || owner.pending != nil || epoch.mtuTransition != nil || !epoch.closed || !observer.closed || m.active.settled || m.active.ended {
					t.Fatal("joined original history was not consumed exclusively for retirement", err)
				}
			} else if err == nil || owner.pending == nil || epoch.mtuTransition == nil || epoch.closed || observer.closed {
				t.Fatal("torn cached evidence released original controller authority", err)
			}
		})
	}
}

func TestLinuxStandardMTUOrdinaryObservationUsesOriginalPhase(t *testing.T) {
	for _, action := range []string{"current", "observe", "dns-current"} {
		t.Run(action, func(t *testing.T) {
			s, f, observer := linuxStandardStartupFixture(t, "complete")
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
				t.Fatal(err)
			}
			n := s.session.owner.native
			report, ready := standardMTUReportFixture(t)
			key := report.Command.Reservation.Key
			key.CaptureSHA256 = n.captureSHA
			deadline, _ := ctx.Deadline()
			key.DeadlineNS = deadline.UnixNano()
			reservation, err := n.operations.Reserve(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			report.Command.Reservation = reservation
			if err = n.operations.SubmitCommand(ctx, report.Command); err != nil {
				t.Fatal(err)
			}
			m := &linuxStandardServiceMTU{session: s.session, native: n, active: &linuxStandardServiceMTUOperation{command: report.Command, original: ready, submitted: true, reserved: true}}
			s.session.mtu = m
			observer.failure = errors.New("ordinary observer must not read armed native transition")
			err = s.handle(ctx, peer, linuxStandardServiceRequest{Schema: 1, Action: action, Session: request.Session, BudgetMS: 12000, DeadlineNS: deadline.UnixNano()}, nil)
			if action == "dns-current" {
				// This fixture has no measured DNS proof. The phase exemption must still
				// execute its original receipt predicate, not fabricate DNS success.
				if err == nil || !strings.Contains(err.Error(), "no matching original DNS proof receipt") {
					t.Fatal("DNS observation skipped original receipt or used ordinary epoch", err)
				}
			} else if err != nil {
				t.Fatal("ordinary observation bypassed original retained phase", err)
			}
			if s.session.network.failure != nil {
				t.Fatal("ordinary observation invalidated armed original tracker")
			}
			genuine := errors.New("latched original network loss")
			s.session.network.failure = genuine
			err = s.handle(ctx, peer, linuxStandardServiceRequest{Schema: 1, Action: action, Session: request.Session, BudgetMS: 12000, DeadlineNS: deadline.UnixNano()}, nil)
			if !errors.Is(err, genuine) {
				t.Fatal("phase exception erased genuine original observer loss", err)
			}
			s.session.network.failure = nil
			observer.failure = nil
		})
	}
}

// The child and FD10 lifecycle are real. Native MTU evidence is an explicit
// model written into that child's captured FD11; this verifies the actual
// protection-release predicate, not a successful live TUN transition.
func TestLinuxStandardMTUStopRejectsHistoryBeforeGuardRelease(t *testing.T) {
	for _, scenario := range []string{"missing", "changed-reservation", "torn-page"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, observer := linuxStandardStartupFixture(t, "complete")
			peer, _, _ := linuxStandardPeerFixture(t)
			request, directory := linuxStandardServiceRequestFixture(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := s.handle(ctx, peer, request, []*os.File{directory}); err != nil {
				t.Fatal(err)
			}
			n := s.session.owner.native
			report, ready := standardMTUReportFixture(t)
			key := report.Command.Reservation.Key
			key.CaptureSHA256 = n.captureSHA
			deadline, _ := ctx.Deadline()
			key.DeadlineNS = deadline.UnixNano()
			r, err := n.operations.Reserve(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			report.Command.Reservation = r
			if err = n.operations.SubmitCommand(ctx, report.Command); err != nil {
				t.Fatal(err)
			}
			m := &linuxStandardServiceMTU{session: s.session, native: n, active: &linuxStandardServiceMTUOperation{command: report.Command, original: ready, settled: true}}
			s.session.mtu, n.mtuStopOwner = m, m
			if scenario == "changed-reservation" {
				m.active.command.Reservation.Key.ID = strings.Repeat("f", 32)
			}
			if scenario == "torn-page" {
				device, inode := n.operations.Identity()
				fd, err := syscall.Dup(int(n.operations.File().Fd()))
				if err != nil {
					t.Fatal(err)
				}
				child, err := standardengine.CaptureOperationFile(os.NewFile(uintptr(fd), "original-modeled-FD11-child"), device, inode, standardengine.OperationSize, standardengine.OperationLayout, n.captureSHA)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := child.Close(ctx); err != nil {
						t.Error(err)
					}
				}()
				for role, e := range report.Readers {
					if e == nil {
						continue
					}
					rrole := standardengine.OperationRole(role)
					if rrole != standardengine.OriginalReader {
						if err := child.BindReader(ctx, r, rrole, e.Binding); err != nil {
							t.Fatal(err)
						}
					}
					if len(e.Ready) > 0 {
						if err := child.PublishEvidence(ctx, r, rrole, standardengine.ReadyEvidence, e.Ready); err != nil {
							t.Fatal(err)
						}
					}
					if len(e.Retirement) > 0 {
						if err := child.PublishEvidence(ctx, r, rrole, standardengine.RetirementEvidence, e.Retirement); err != nil {
							t.Fatal(err)
						}
					}
				}
				report.Result.Digest = ""
				if err := child.PublishResult(ctx, r, report.Result); err != nil {
					t.Fatal(err)
				}
				if _, err := n.operations.File().WriteAt([]byte{0xff}, standardengine.OperationControlSize); err != nil {
					t.Fatal(err)
				}
			}
			err = s.retire(ctx, true)
			owner := s.session.owner
			if err == nil || owner.protection.removed || s.session.joined || !s.session.cleanupPending || observer.retirementReads != 0 {
				t.Fatal("unverified original FD11 history released actual guard", err)
			}
			if !owner.processRetired || owner.completion.state == nil || !owner.completion.state.Success() {
				t.Fatal("test did not reach successful original child join", err)
			}
			result, readErr := n.cleanup.ReadResult(n.captureSHA)
			if readErr != nil || !result.Complete {
				t.Fatal("test did not reach authenticated FD10 Complete", result, readErr)
			}
		})
	}
}
