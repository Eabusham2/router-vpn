//go:build linux && routervpn_controller_privileged

package standardengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

func sharedRunFixture(t *testing.T) (context.Context, *OperationFile, *OperationFile, OperationRun) {
	t.Helper()
	ctx, p, c := operationPair(t)
	raw := "original-ready"
	if err := c.AcknowledgeLaunch(ctx, raw); err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	run := OperationRun{CaptureSHA256: p.capture, ID: fmt.Sprintf("%032x", 101), WorkDeadlineNS: deadline.UnixNano(), CleanupBudgetNS: int64(time.Second), Original: InitialReaderBinding(p.capture, raw), OriginalMTU: 1500}
	if err := p.BeginOperationRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	return ctx, p, c, run
}
func TestCleanupSharedRunClockIndependentAndSingle(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	unlock, err := p.lock(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	var deadlines [2]time.Time
	var failures [2]error
	for i, file := range []*OperationFile{p, c} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			call, end := context.WithTimeout(ctx, 100*time.Millisecond)
			defer end()
			deadlines[i], failures[i] = file.ActivateOperationRunCleanup(call, run)
		}()
	}
	wait.Wait()
	unlock()
	if failures[0] != nil || failures[1] != nil || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("parent/child cleanup did not share exact independent clock", deadlines, failures)
	}
	again, err := c.ActivateOperationRunCleanup(ctx, run)
	if err != nil || !again.Equal(deadlines[0]) {
		t.Fatal("later caller renewed shared clock", err)
	}
	expired, end := context.WithDeadline(ctx, again)
	defer end()
	<-expired.Done()
	if _, err := p.ActivateOperationRunCleanup(ctx, run); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired run cleanup renewed", err)
	}
}
func TestCleanupSharedRunClockCancellationAndHeldLock(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	unlock, err := p.lock(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	call, end := context.WithTimeout(ctx, 20*time.Millisecond)
	_, err = c.ActivateOperationRunCleanup(call, run)
	end()
	unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("clock ignored original held-lock deadline", err)
	}
	if _, present, err := p.OperationRunCleanupDeadline(ctx, run); err != nil || present {
		t.Fatal("failed observation activated cleanup", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := p.ActivateOperationRunCleanup(cancelled, run); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled clock admission mutated run", err)
	}
}
func TestCleanupSharedRunClosureAndStaleClock(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	next := run
	next.ID = fmt.Sprintf("%032x", 102)
	if err := p.BeginOperationRun(ctx, next); err == nil {
		t.Fatal("next run bypassed original child closure")
	}
	if err := p.RequestOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := p.BeginOperationRun(ctx, next); err == nil {
		t.Fatal("unacknowledged closure transferred run")
	}
	if err := c.AcknowledgeOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := p.BeginOperationRun(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ActivateOperationRunCleanup(ctx, run); err == nil {
		t.Fatal("old run activated replacement cleanup")
	}
	if err := p.RequestOperationRunClosure(ctx, run); err == nil {
		t.Fatal("old run closed replacement")
	}
	if _, present, err := p.OperationRunCleanupDeadline(ctx, next); err != nil || present {
		t.Fatal("stale request modified new clock", err)
	}
}
func TestCleanupSharedRunBindsCommandAndRestore(t *testing.T) {
	ctx, p, _, run := sharedRunFixture(t)
	r, err := p.Reserve(ctx, OperationKey{CaptureSHA256: p.capture, ID: fmt.Sprintf("%032x", 201), Sequence: 1, DeadlineNS: run.WorkDeadlineNS, Original: run.Original})
	if err != nil {
		t.Fatal(err)
	}
	command := OperationCommand{r, 1400}
	if err := p.BindOperationRun(ctx, command, run, true); err == nil {
		t.Fatal("fresh candidate used cleanup authority")
	}
	if err := p.BindOperationRun(ctx, command, run, false); err != nil {
		t.Fatal(err)
	}
	if err := p.RequestOperationRunClosure(ctx, run); err == nil {
		t.Fatal("unjoined reserved command closed run")
	}
	foreign := run
	foreign.OriginalMTU++
	if err := p.BindOperationRun(ctx, command, foreign, false); err == nil {
		t.Fatal("command rebound captured original MTU")
	}
	if err := p.SubmitCommand(ctx, command); err != nil {
		t.Fatal(err)
	}
	observed, cleanup, bound, err := p.CommandOperationRun(ctx, command)
	if err != nil || !bound || cleanup || observed != run {
		t.Fatal("command lost original run", err)
	}
}

func TestCleanupSharedRunShortAdmissionAndOriginalBounds(t *testing.T) {
	ctx, p, c := operationPair(t)
	if err := c.AcknowledgeLaunch(ctx, "original-ready"); err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	run := OperationRun{p.capture, fmt.Sprintf("%032x", 701), deadline.UnixNano(), int64(time.Second), InitialReaderBinding(p.capture, "original-ready"), 1500}
	short, end := context.WithTimeout(ctx, 50*time.Millisecond)
	defer end()
	if err := p.BeginOperationRun(short, run); err != nil {
		t.Fatal("short RPC admission replaced captured optimizer deadline", err)
	}
	if held, err := p.OperationRunRetained(ctx, run); err != nil || !held {
		t.Fatal("successful original run admission disappeared", err)
	}
	if _, err := p.ActivateOperationRunCleanup(ctx, run); err != nil {
		t.Fatal(err)
	}
	r, err := p.Reserve(ctx, OperationKey{p.capture, fmt.Sprintf("%032x", 702), 1, run.WorkDeadlineNS, run.Original})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BindOperationRun(ctx, OperationCommand{r, 1400}, run, false); err == nil {
		t.Fatal("fresh candidate followed activated cleanup")
	}
}
func TestCleanupSharedRunPreviousLayoutRefused(t *testing.T) {
	frame, err := operationFrame(6, make([]byte, 144), operationControlFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	frame[5] = 2
	if _, err := operationBody(frame, 6); err == nil {
		t.Fatal("layout2 frame acquired shared-clock layout3 authority")
	}
}

// This case inherits the same open-file-description into a real second process;
// process-region locks, rather than OFD locks or only a local mutex, arbitrate.
func TestCleanupSharedRunClockInheritedProcess(t *testing.T) {
	ctx, p, _, run := sharedRunFixture(t)
	device, inode := p.Identity()
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCleanupSharedRunClockProcessHelper$", "-test.count=1")
	child.Env = append(os.Environ(), "ROUTERVPN_CLOCK_HELPER=1", "ROUTERVPN_CLOCK_RUN="+string(raw), fmt.Sprintf("ROUTERVPN_CLOCK_DEVICE=%d", device), fmt.Sprintf("ROUTERVPN_CLOCK_INODE=%d", inode))
	child.ExtraFiles = []*os.File{p.File()}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var failures bytes.Buffer
	child.Stderr = &failures
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	reader := bufio.NewScanner(output)
	if !reader.Scan() || reader.Text() != "clock-ready" {
		t.Fatal("original child did not capture inherited FD11", reader.Text(), failures.String())
	}
	parentResult := make(chan time.Time, 1)
	parentError := make(chan error, 1)
	go func() {
		deadline, err := p.ActivateOperationRunCleanup(ctx, run)
		parentResult <- deadline
		parentError <- err
	}()
	if _, err := input.Write([]byte("activate\n")); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if !reader.Scan() {
		t.Fatal("original child omitted shared clock", failures.String())
	}
	stamp, err := strconv.ParseInt(reader.Text(), 10, 64)
	if err != nil {
		t.Fatal("invalid child clock", reader.Text(), failures.String())
	}
	deadline := <-parentResult
	if err := <-parentError; err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(time.Unix(0, stamp)) {
		t.Fatal("inherited processes activated distinct cleanup deadlines", deadline, stamp)
	}
	for reader.Scan() {
	}
	if err := child.Wait(); err != nil {
		t.Fatal("inherited clock helper failed", err, failures.String())
	}
	joined = true
}
func TestCleanupSharedRunClockProcessHelper(t *testing.T) {
	if os.Getenv("ROUTERVPN_CLOCK_HELPER") != "1" {
		return
	}
	var run OperationRun
	if err := json.Unmarshal([]byte(os.Getenv("ROUTERVPN_CLOCK_RUN")), &run); err != nil {
		t.Fatal(err)
	}
	device, err := strconv.ParseUint(os.Getenv("ROUTERVPN_CLOCK_DEVICE"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	inode, err := strconv.ParseUint(os.Getenv("ROUTERVPN_CLOCK_INODE"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CaptureOperationFile(os.NewFile(3, "captured-original-FD11"), device, inode, OperationSize, OperationLayout, run.CaptureSHA256)
	if err != nil {
		t.Fatal(err)
	}
	ctx, end := context.WithTimeout(context.Background(), 2*time.Second)
	defer end()
	defer c.Close(ctx)
	fmt.Println("clock-ready")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() || scanner.Text() != "activate" {
		t.Fatal("clock activation lost original parent")
	}
	deadline, err := c.ActivateOperationRunCleanup(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(deadline.UnixNano())
}

func TestCleanupSharedRunSettlementKeepsClock(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	command := sharedClockSubmit(t, ctx, p, run, 1, run.Original, 1400, false)
	deadline, err := p.ActivateOperationRunCleanup(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PublishJoinedEvidence(ctx, command.Reservation, OriginalReader, ReadyEvidence, []byte("original-ready")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishResult(ctx, command.Reservation, OperationResult{CurrentRole: OriginalReader, WorkerJoined: true, ReadyMask: 1, Failed: true}); err != nil {
		t.Fatal(err)
	}
	result, err := p.ReadResult(ctx, command.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	sharedClockSettle(t, ctx, p, command, result)
	after, present, err := p.OperationRunCleanupDeadline(ctx, run)
	if err != nil || !present || !after.Equal(deadline) {
		t.Fatal("transaction settlement cleared or renewed original run cleanup clock", err)
	}
}

func TestCleanupSharedRunAdmissionHistoryIsBounded(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	for i := 1; i < OperationTransactions; i++ {
		if err := p.RequestOperationRunClosure(ctx, run); err != nil {
			t.Fatal(err)
		}
		if err := c.AcknowledgeOperationRunClosure(ctx, run); err != nil {
			t.Fatal(err)
		}
		run.ID = fmt.Sprintf("%032x", 900+i)
		if err := p.BeginOperationRun(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.RequestOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := c.AcknowledgeOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
	next := run
	next.ID = fmt.Sprintf("%032x", 1001)
	if err := p.BeginOperationRun(ctx, next); err == nil {
		t.Fatal("empty runs bypassed bounded original admission history")
	}
	observed, state, err := p.ReadOperationRun(ctx)
	if err != nil || observed != run || state != OperationRunClosed {
		t.Fatal("capacity refusal replaced original closed run", err)
	}
}

func TestCleanupSharedRunUnsubmittedRequiresBothOriginalObservers(t *testing.T) {
	ctx, p, c, run := sharedRunFixture(t)
	key := OperationKey{p.capture, fmt.Sprintf("%032x", 1201), 1, run.WorkDeadlineNS, run.Original}
	r, err := p.Reserve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BindOperationRun(ctx, OperationCommand{r, 1400}, run, false); err != nil {
		t.Fatal(err)
	}
	if err := p.AcknowledgeUnsubmitted(ctx, r, ServiceObserver); err == nil {
		t.Fatal("unfenced reservation gained observer settlement")
	}
	if absent, err := p.AbortUnsubmitted(ctx, r); err != nil || !absent {
		t.Fatal(err)
	}
	if err := c.AcknowledgeUnsubmitted(ctx, r, ServiceObserver); err == nil {
		t.Fatal("native child invented original observer acknowledgement")
	}
	if err := p.AcknowledgeUnsubmitted(ctx, r, ServiceObserver); err != nil {
		t.Fatal(err)
	}
	if err := p.RequestOperationRunClosure(ctx, run); err == nil {
		t.Fatal("one observer closed rejected original run")
	}
	if err := c.PublishJoinedEvidence(ctx, r, OriginalReader, ReadyEvidence, []byte("original-ready")); err == nil {
		t.Fatal("aborted operation acquired synthetic Ready")
	}
	if err := p.AcknowledgeUnsubmitted(ctx, r, ControllerObserver); err != nil {
		t.Fatal(err)
	}
	if result, err := p.ReadResult(ctx, r); !errors.Is(err, ErrOperationPending) || result.WorkerJoined {
		t.Fatal("unsubmitted settlement fabricated native worker result", result, err)
	}
	next, err := p.Reserve(ctx, OperationKey{p.capture, fmt.Sprintf("%032x", 1202), 2, run.WorkDeadlineNS, run.Original})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BindOperationRun(ctx, OperationCommand{next, 1400}, run, false); err != nil {
		t.Fatal("rejected command replaced original current binding", err)
	}
	if absent, err := p.AbortUnsubmitted(ctx, next); err != nil || !absent {
		t.Fatal(err)
	}
	for _, role := range []ObserverRole{ServiceObserver, ControllerObserver} {
		if err := p.AcknowledgeUnsubmitted(ctx, next, role); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.RequestOperationRunClosure(ctx, run); err != nil {
		t.Fatal("both original observers could not close no-submission run", err)
	}
	if err := c.AcknowledgeOperationRunClosure(ctx, run); err != nil {
		t.Fatal(err)
	}
}
