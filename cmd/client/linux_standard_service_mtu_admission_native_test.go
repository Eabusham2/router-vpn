//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/standardengine"
)

// These use the actual inherited FD11 admission protocol and an explicitly
// modeled observer. No test below claims a successful native TUN measurement.
func standardMTUAdmissionPair(t *testing.T) (context.Context, *linuxStandardServiceMTU, *standardengine.OperationFile) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	report, ready := standardMTUReportFixture(t)
	parent, err := standardengine.NewOperationFile()
	closeOwned := func(owned *standardengine.OperationFile) {
		if owned != nil {
			t.Cleanup(func() {
				cleanup, finish := context.WithTimeout(context.Background(), time.Second)
				defer finish()
				if err := owned.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
		}
	}
	closeOwned(parent)
	if err != nil {
		t.Fatal(err)
	}
	capture := report.Command.Reservation.Key.CaptureSHA256
	if err := parent.BindCapture(ctx, capture); err != nil {
		t.Fatal(err)
	}
	device, inode := parent.Identity()
	fd, err := syscall.Dup(int(parent.File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	child, err := standardengine.CaptureOperationFile(os.NewFile(uintptr(fd), "original-service-mtu-test-child"), device, inode, standardengine.OperationSize, standardengine.OperationLayout, capture)
	closeOwned(child)
	if err != nil {
		t.Fatal(err)
	}
	m := &linuxStandardServiceMTU{native: &linuxStandardEngine{captureSHA: capture, operations: parent, tracker: &linuxStandardStartupObserverFixture{}}, ready: ready, current: report.Command.Reservation.Key.Original}
	return ctx, m, child
}

func TestLinuxStandardMTUUnsubmittedRecoveryFencesDelayedCommand(t *testing.T) {
	for _, scenario := range []string{"cancel-before-begin", "reserved-unsent", "uncertain-unsent", "uncertain-published"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, m, child := standardMTUAdmissionPair(t)
			if err := child.AcknowledgeLaunch(ctx, m.ready); err != nil {
				t.Fatal(err)
			}
			limit, _ := ctx.Deadline()
			run := standardengine.OperationRun{CaptureSHA256: m.native.captureSHA, ID: strings.Repeat("d", 32), WorkDeadlineNS: limit.UnixNano(), CleanupBudgetNS: int64(standardengine.OperationRunCleanupLimit), Original: m.current, OriginalMTU: 1500}
			if _, err := m.runRequest(ctx, "mtu-run-begin", &linuxStandardServiceMTURequest{Run: &run}); err != nil {
				t.Fatal(err)
			}

			report, _ := standardMTUReportFixture(t)
			key := report.Command.Reservation.Key
			deadline, _ := ctx.Deadline()
			key.DeadlineNS = deadline.UnixNano()
			q := &linuxStandardServiceMTURequest{Run: &run, ID: key.ID, DeadlineNS: key.DeadlineNS, Expected: &key.Original}
			var command standardengine.OperationCommand
			if scenario == "cancel-before-begin" {
				if err := m.rejectUnknown(ctx, q); err != nil {
					t.Fatal(err)
				}
				q.MTU = 1400
				if err := m.begin(ctx, q); err != nil {
					t.Fatal("exact delayed begin should recover its original rejection", err)
				}
			} else {
				reservation, err := m.native.operations.Reserve(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				command = standardengine.OperationCommand{Reservation: reservation, MTU: 1400}
				m.active = &linuxStandardServiceMTUOperation{command: command, original: m.ready, run: &run, reserved: true, noSubmission: scenario == "reserved-unsent"}
				m.remember(key.ID)
				if err := m.native.operations.BindOperationRun(ctx, command, run, false); err != nil {
					t.Fatal(err)
				}

				if scenario == "uncertain-published" {
					if err := m.native.operations.SubmitCommand(ctx, command); err != nil {
						t.Fatal(err)
					}
				}
				if err := m.poll(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "uncertain-published" {
				if scenario != "cancel-before-begin" && m.response().Settled {
					t.Fatal("unsubmitted run settled before controller observer")
				}
				// Explicit unchanged controller-observer model; there is no native worker to invent.
				controller := &linuxStandardStartupObserverFixture{}
				if err := controller.CurrentContext(ctx); err != nil {
					t.Fatal(err)
				}
				ack := *q
				ack.MTU = 0
				if err := m.acknowledgeRejection(ctx, &ack); err != nil {
					t.Fatal(err)
				}
			}
			response := m.response()
			actual, err := child.ReadCommand(ctx, 0)
			if scenario == "uncertain-published" {
				if err != nil || actual != command || response.Rejected != nil || !response.Pending || response.Settled || response.Result != nil {
					t.Fatal("uncertain write hid published work or invented joined evidence", response, actual, err)
				}
				return
			}
			if !errors.Is(err, standardengine.ErrNoOperation) || response.Rejected == nil || response.Rejected.ID != key.ID || response.Rejected.Expected != key.Original || response.Rejected.DeadlineNS != key.DeadlineNS || response.Pending || !response.Settled || response.Command != nil || response.Result != nil {
				t.Fatal("unsubmitted intent did not remain an exact worker-free rejection", response, actual, err)
			}
			if scenario != "cancel-before-begin" && m.native.operations.SubmitCommand(ctx, command) == nil {
				t.Fatal("delayed native command executed after permanent admission rejection")
			}
			closed, e := m.runRequest(ctx, "mtu-run-close", &linuxStandardServiceMTURequest{Run: &run})
			if e != nil || closed.RunState != standardengine.OperationRunClosing {
				t.Fatal("both actual unsubmitted observer acks did not permit closure", closed, e)
			}
			if e = child.AcknowledgeOperationRunClosure(ctx, run); e != nil {
				t.Fatal(e)
			}

		})
	}
}
