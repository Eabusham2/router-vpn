//go:build linux

package standardengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

func recordRunSHA(b []byte) string {
	if bytes.Equal(b[424:456], make([]byte, 32)) {
		return ""
	}
	return hex.EncodeToString(b[424:456])
}
func validateRunExtension(b []byte) error {
	if len(b) != operationRecordBodySize || b[456] > 1 || !bytes.Equal(b[457:], make([]byte, 7)) || b[456] != 0 && recordRunSHA(b) == "" {
		return errors.New("operation changed captured run extension")
	}
	return nil
}
func (o *OperationFile) ReadOperationRun(ctx context.Context) (OperationRun, OperationRunState, error) {
	var run OperationRun
	frame, err := o.rawRead(ctx, operationRunOffset, operationControlFrameSize)
	if err != nil {
		return run, 0, err
	}
	if bytes.Equal(frame, make([]byte, len(frame))) {
		return run, 0, ErrNoOperation
	}
	body, err := o.read(ctx, 6, operationRunOffset, operationControlFrameSize)
	if err != nil {
		return run, 0, err
	}
	if len(body) != 144 || body[140] > byte(OperationRunClosed) || !bytes.Equal(body[141:], make([]byte, 3)) {
		return run, 0, errors.New("original run frame is noncanonical")
	}
	run = decodeOperationRun(body[:operationRunSize])
	raw, err := run.canonical()
	if err != nil || !bytes.Equal(raw, body[:operationRunSize]) || run.CaptureSHA256 != o.capture {
		return run, 0, errors.Join(err, errors.New("original run changed launch capture"))
	}
	return run, OperationRunState(body[140]), ctx.Err()
}
func (o *OperationFile) writeRun(ctx context.Context, run OperationRun, state OperationRunState) error {
	raw, err := run.canonical()
	if err != nil {
		return err
	}
	body := make([]byte, 144)
	copy(body, raw)
	body[140] = byte(state)
	return o.write(ctx, 6, body, operationRunOffset, operationControlFrameSize)
}
func (o *OperationFile) runRecords(ctx context.Context, run OperationRun, settled bool) (*OperationReservation, error) {
	sum, err := run.SHA256()
	if err != nil {
		return nil, err
	}
	var last *OperationReservation
	for slot := uint32(0); slot < OperationTransactions; slot++ {
		frame, err := o.rawRead(ctx, recordOffset(slot), operationRecordSize)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(frame, make([]byte, len(frame))) {
			continue
		}
		body, err := operationBody(frame, 4)
		if err != nil || len(body) != operationRecordBodySize {
			return nil, errors.Join(err, errors.New("run retained a torn transaction"))
		}
		r := OperationReservation{Slot: slot, Key: decodeOperationKey(body[4:140])}
		body, err = o.record(ctx, r)
		if err != nil {
			return nil, err
		}
		if recordRunSHA(body) != sum {
			continue
		}
		if settled && (body[374] != 1 || body[373] != 3) {
			return nil, errors.New("run closure preceded both original observer settlements")
		}
		if body[360] == 2 {
			if err := o.unsubmittedPagesAbsent(ctx, r); err != nil {
				return nil, err
			}
			// Both observers settled a proven no-submission tombstone. It has
			// no native result and cannot replace the prior actual current reader.
			continue
		}
		if settled {
			result, err := o.readResult(ctx, r)
			if err != nil || !result.WorkerJoined || result.Pending {
				return nil, errors.Join(err, errors.New("run closure retains pending native resources"))
			}
		}
		if last == nil || r.Key.Sequence > last.Key.Sequence {
			copy := r
			last = &copy
		}
	}
	return last, ctx.Err()
}

// BeginOperationRun receives the same actual initial reader/MTU captured by
// the two retained observers. It never supplies an observer or native handle.
func (o *OperationFile) BeginOperationRun(ctx context.Context, run OperationRun) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	unlockClock, err := o.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlockClock()
	if o.child || run.CaptureSHA256 != o.capture {
		return errors.New("run admission changed original parent")
	}
	if _, err := run.canonical(); err != nil {
		return err
	}
	now := time.Now()
	// Admission is a short authenticated RPC; the accepted optimizer lifetime
	// was captured separately by its original owner. Never extend its 45s cap.
	if !now.Before(time.Unix(0, run.WorkDeadlineNS)) || run.WorkDeadlineNS > now.Add(OperationRunWorkLimit).UnixNano() {
		return errors.New("run admission renewed original work deadline")
	}
	prior, state, err := o.ReadOperationRun(ctx)
	if err == nil {
		if prior == run && state == OperationRunOpen {
			return nil
		}
		if state != OperationRunClosed || prior.ID == run.ID {
			return errors.New("run transfer preceded original child closure")
		}
		last, e := o.runRecords(ctx, prior, true)
		if e != nil {
			return e
		}
		expected := prior.Original
		if last != nil {
			result, e := o.readResult(ctx, *last)
			if e != nil || result.CurrentRole == NoReader {
				return errors.Join(e, errors.New("run transfer has no retained current reader"))
			}
			expected, e = o.ReadBinding(ctx, *last, result.CurrentRole)
			if e != nil {
				return e
			}
		}
		if expected != run.Original {
			return errors.New("run transfer replaced actual settled reader")
		}
	} else if !errors.Is(err, ErrNoOperation) {
		return err
	} else {
		launch, err := o.read(ctx, 1, 0, operationControlFrameSize)
		if err != nil || len(launch) != 64 || hex.EncodeToString(launch[:32]) != o.capture || hex.EncodeToString(launch[32:]) != run.Original.InitialReceiptSHA256 {
			return errors.Join(err, errors.New("first run changed original startup Ready"))
		}
	}
	if o.seenRuns == nil {
		o.seenRuns = make(map[string]bool)
	}
	if o.seenRuns[run.ID] {
		return errors.New("original run ID cannot be reused")
	}
	if len(o.seenRuns) >= OperationTransactions {
		return errors.New("original run admission history reached retained capacity")
	}
	o.seenRuns[run.ID] = true // A failed publication remains an owned admission.
	sum, _ := run.SHA256()
	clock := make([]byte, 48)
	raw, _ := hex.DecodeString(sum)
	copy(clock, raw)
	if err := o.write(ctx, 7, clock, operationRunClockOffset, operationControlFrameSize); err != nil {
		return err
	}
	return o.writeRun(ctx, run, OperationRunOpen)
}
func (o *OperationFile) OperationRunCleanupDeadline(ctx context.Context, run OperationRun) (time.Time, bool, error) {
	current, state, err := o.ReadOperationRun(ctx)
	if err != nil || current != run || state == OperationRunClosed {
		return time.Time{}, false, errors.Join(err, errors.New("cleanup clock lost original open run"))
	}
	body, err := o.read(ctx, 7, operationRunClockOffset, operationControlFrameSize)
	sum, _ := run.SHA256()
	if err != nil || len(body) != 48 || hex.EncodeToString(body[:32]) != sum || !bytes.Equal(body[40:], make([]byte, 8)) {
		return time.Time{}, false, errors.Join(err, errors.New("cleanup clock changed original run"))
	}
	stamp := int64(binary.LittleEndian.Uint64(body[32:40]))
	if stamp < 0 {
		return time.Time{}, false, errors.New("cleanup deadline is invalid")
	}
	if stamp == 0 {
		return time.Time{}, false, nil
	}
	return time.Unix(0, stamp), true, ctx.Err()
}

// ActivateOperationRunCleanup uses only the cancellation lock/region. Either
// process can activate it once; all later callers receive the same timestamp.
func (o *OperationFile) ActivateOperationRunCleanup(ctx context.Context, run OperationRun) (time.Time, error) {
	unlock, err := o.lock(ctx, true)
	if err != nil {
		return time.Time{}, err
	}
	defer unlock()
	deadline, present, err := o.OperationRunCleanupDeadline(ctx, run)
	if err != nil {
		return time.Time{}, err
	}
	if present {
		if !time.Now().Before(deadline) {
			return time.Time{}, context.DeadlineExceeded
		}
		return deadline, ctx.Err()
	}
	bound, _ := ctx.Deadline()
	deadline = time.Now().Add(time.Duration(run.CleanupBudgetNS))
	if deadline.After(bound) {
		deadline = bound
	}
	if !time.Now().Before(deadline) {
		return time.Time{}, context.DeadlineExceeded
	}
	body := make([]byte, 48)
	sum, _ := run.SHA256()
	raw, _ := hex.DecodeString(sum)
	copy(body, raw)
	binary.LittleEndian.PutUint64(body[32:], uint64(deadline.UnixNano()))
	if err := o.write(ctx, 7, body, operationRunClockOffset, operationControlFrameSize); err != nil {
		return time.Time{}, err
	}
	return deadline, nil
}
func (o *OperationFile) validateCommandRun(ctx context.Context, command OperationCommand, run OperationRun, cleanup, admission bool) error {
	current, state, err := o.ReadOperationRun(ctx)
	if err != nil || current != run || state != OperationRunOpen {
		return errors.Join(err, errors.New("native command lost original active run"))
	}
	if command.Reservation.Key.CaptureSHA256 != run.CaptureSHA256 {
		return errors.New("native command changed run capture")
	}
	if cleanup {
		deadline, present, err := o.OperationRunCleanupDeadline(ctx, run)
		if err != nil {
			return err
		}
		if !present || admission && !time.Now().Before(deadline) || command.MTU != run.OriginalMTU || command.Reservation.Key.DeadlineNS > deadline.UnixNano() {
			return errors.New("cleanup command renewed run or changed original restore MTU")
		}
	} else {
		if command.Reservation.Key.DeadlineNS > run.WorkDeadlineNS || admission && !time.Now().Before(time.Unix(0, run.WorkDeadlineNS)) {
			return errors.New("native candidate renewed original run work")
		}
		if admission {
			_, active, err := o.OperationRunCleanupDeadline(ctx, run)
			if err != nil {
				return err
			}
			if active {
				return errors.New("native candidate followed original cleanup activation")
			}
		}
	}
	return ctx.Err()
}
func (o *OperationFile) BindOperationRun(ctx context.Context, command OperationCommand, run OperationRun, cleanupOnly bool) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child {
		return errors.New("child cannot bind parent run command")
	}
	if err := o.validateCommandRun(ctx, command, run, cleanupOnly, true); err != nil {
		return err
	}
	body, err := o.record(ctx, command.Reservation)
	if err != nil {
		return err
	}
	sum, _ := run.SHA256()
	if old := recordRunSHA(body); old != "" {
		if old != sum || body[456] == 1 != cleanupOnly {
			return errors.New("command run binding cannot be replaced")
		}
		return ctx.Err()
	}
	if body[360] != 0 {
		return errors.New("visible command cannot acquire a later run binding")
	}
	last, err := o.runRecords(ctx, run, true)
	if err != nil {
		return err
	}
	expected := run.Original
	if last != nil {
		result, e := o.readResult(ctx, *last)
		if e != nil || result.CurrentRole == NoReader {
			return errors.Join(e, errors.New("next run command has no joined current"))
		}
		expected, e = o.ReadBinding(ctx, *last, result.CurrentRole)
		if e != nil {
			return e
		}
	}
	if expected != command.Reservation.Key.Original {
		return errors.New("run command replaced settled current reader")
	}
	raw, _ := hex.DecodeString(sum)
	copy(body[424:456], raw)
	if cleanupOnly {
		body[456] = 1
	}
	return o.write(ctx, 4, body, recordOffset(command.Reservation.Slot), operationRecordSize)
}
func (o *OperationFile) CommandOperationRun(ctx context.Context, command OperationCommand) (OperationRun, bool, bool, error) {
	var run OperationRun
	body, err := o.record(ctx, command.Reservation)
	if err != nil {
		return run, false, false, err
	}
	sum := recordRunSHA(body)
	if sum == "" {
		return run, false, false, nil
	}
	run, _, err = o.ReadOperationRun(ctx)
	if err != nil {
		return run, false, true, err
	}
	actual, _ := run.SHA256()
	if actual != sum {
		return run, false, true, errors.New("native command belongs to another run")
	}
	cleanup := body[456] == 1
	return run, cleanup, true, o.validateCommandRun(ctx, command, run, cleanup, false)
}
func (o *OperationFile) RequestOperationRunClosure(ctx context.Context, run OperationRun) error {
	return o.operationRunClosure(ctx, run, false)
}
func (o *OperationFile) AcknowledgeOperationRunClosure(ctx context.Context, run OperationRun) error {
	return o.operationRunClosure(ctx, run, true)
}
func (o *OperationFile) operationRunClosure(ctx context.Context, run OperationRun, ack bool) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	unlockClock, err := o.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlockClock()
	if o.child != ack {
		return errors.New("run closure changed original process role")
	}
	current, state, err := o.ReadOperationRun(ctx)
	if err != nil || current != run {
		return errors.Join(err, errors.New("run closure changed original run"))
	}
	if _, err := o.runRecords(ctx, run, true); err != nil {
		return err
	}
	if ack {
		if state == OperationRunClosed {
			return nil
		}
		if state != OperationRunClosing {
			return errors.New("child closure lacks parent request")
		}
		return o.writeRun(ctx, run, OperationRunClosed)
	}
	if state == OperationRunClosing || state == OperationRunClosed {
		return nil
	}
	return o.writeRun(ctx, run, OperationRunClosing)
}

func (o *OperationFile) boundOperationRun(ctx context.Context, r OperationReservation) (OperationRun, bool, error) {
	var run OperationRun
	body, err := o.record(ctx, r)
	if err != nil {
		return run, false, err
	}
	sum := recordRunSHA(body)
	if sum == "" {
		return run, false, nil
	}
	run, state, err := o.ReadOperationRun(ctx)
	if err != nil {
		return run, true, err
	}
	actual, _ := run.SHA256()
	if actual != sum || state != OperationRunOpen {
		return run, true, errors.New("operation control belongs to another or closed run")
	}
	return run, true, nil
}

// OperationRunRetained is a bounded conservative admission query. True includes
// a write that may have begun but did not return success; that run remains Stop
// owned. An observation error must likewise never be treated as no admission.
func (o *OperationFile) OperationRunRetained(ctx context.Context, run OperationRun) (bool, error) {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return false, err
	}
	defer unlock()
	if o.child {
		return false, errors.New("run admission belongs to original parent")
	}
	if run.CaptureSHA256 != o.capture {
		return false, errors.New("run admission changed capture")
	}
	if o.seenRuns[run.ID] {
		return true, ctx.Err()
	}
	current, _, err := o.ReadOperationRun(ctx)
	if errors.Is(err, ErrNoOperation) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return current == run, ctx.Err()
}

// AcknowledgeUnsubmitted records one actual observer's completion after the
// permanent no-submission proof. Only the captured parent coordinator may call
// it, and only an authenticated original controller can supply its second ack.
// A tombstone never receives a synthetic worker result or receipt.
func (o *OperationFile) AcknowledgeUnsubmitted(ctx context.Context, r OperationReservation, role ObserverRole) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child || role > ControllerObserver {
		return errors.New("unsubmitted acknowledgement changed original observer")
	}
	body, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if body[360] != 2 || body[368] != 0 || recordRunSHA(body) == "" {
		return errors.New("unsubmitted acknowledgement omitted exact run tombstone")
	}
	if err := o.unsubmittedPagesAbsent(ctx, r); err != nil {
		return err
	}
	if body[374] == 1 {
		return ctx.Err()
	}
	if _, _, err := o.boundOperationRun(ctx, r); err != nil {
		return err
	}
	body[373] |= 1 << role
	if body[373] == 3 {
		body[374] = 1
	}
	return o.write(ctx, 4, body, recordOffset(r.Slot), operationRecordSize)
}

func (o *OperationFile) unsubmittedPagesAbsent(ctx context.Context, r OperationReservation) error {
	for index := 0; index < OperationReaders*2; index++ {
		page := int(r.Slot)*OperationReaders*2 + index
		raw, err := o.rawRead(ctx, int64(operationHeadersOffset+page*operationHeaderSize), operationHeaderSize)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, make([]byte, operationHeaderSize)) {
			return errors.New("unsubmitted operation retains native evidence header")
		}
	}
	return ctx.Err()
}
