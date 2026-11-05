//go:build linux

package standardengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

// The versioned record's spare bytes carry commands and settlement. The fixed
// evidence pages and their bounds are unchanged. Ack bits are evidence that the
// coordinator finished its two retained observers, never observer authority.
func validateOperationExtension(b []byte) error {
	if err := validateRunExtension(b); err != nil {
		return err
	}
	if b[360] == 2 {
		mtu := binary.LittleEndian.Uint32(b[364:368])
		if b[140] != 1 || !bytes.Equal(b[361:364], make([]byte, 3)) || mtu != 0 && (mtu < 576 || mtu > 9000) || !bytes.Equal(b[368:373], make([]byte, 5)) || b[373]&^byte(3) != 0 || b[374] > 1 || b[374] == 1 && b[373] != 3 || !bytes.Equal(b[375:424], make([]byte, 424-375)) || b[373] != 0 && recordRunSHA(b) == "" {
			return errors.New("unsubmitted tombstone gained native evidence")
		}
		return nil
	}
	if b[360] == 0 {
		if !bytes.Equal(b[360:424], make([]byte, 424-360)) {
			return errors.New("unsubmitted operation has settlement data")
		}
		return nil
	}
	mtu := binary.LittleEndian.Uint32(b[364:368])
	if b[360] != 1 || !bytes.Equal(b[361:364], make([]byte, 3)) || mtu < 576 || mtu > 9000 || b[368] > 1 || b[370]&^byte(7) != 0 || b[371]&^byte(7) != 0 || b[372]&^byte(7) != 0 || b[373]&^byte(3) != 0 || b[374] > 1 || b[375] != 0 || int64(binary.LittleEndian.Uint64(b[416:424])) < 0 {
		return errors.New("operation command or settlement is noncanonical")
	}
	if b[368] == 0 && !bytes.Equal(b[368:416], make([]byte, 48)) {
		return errors.New("unjoined operation has result data")
	}
	if b[368] == 1 && (b[370]&1 == 0 || b[369] > byte(RollbackReader) && b[369] != byte(NoReader) || binary.LittleEndian.Uint64(b[408:416]) == 0) {
		return errors.New("operation result omitted its joined native worker")
	}
	return nil
}

// AbortUnsubmitted proves absence while holding the same lock as publication,
// then permanently tombstones the reservation. It does not invent a worker or
// receipt. A complete published request must use actual cancellation and join;
// a torn/nonzero slot remains an error requiring original process cleanup.
// RequestCleanup admits only a bounded retry of already joined pending native
// resources. The existing FD10 Stop maximum also bounds this explicit request.
func (o *OperationFile) RequestCleanup(ctx context.Context, r OperationReservation) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child {
		return errors.New("native child cannot authorize its own cleanup retry")
	}
	result, err := o.readResult(ctx, r)
	if err != nil {
		return err
	}
	if !result.WorkerJoined || !result.Pending {
		return errors.New("cleanup retry requires joined pending original resources")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if b[373] != 0 || b[374] != 0 {
		return errors.New("acknowledged operation cannot request new cleanup")
	}
	request, err := o.read(ctx, 2, operationSlotSize, operationSlotSize)
	key, _ := r.Key.canonical()
	if err != nil || len(request) != 140 || binary.LittleEndian.Uint32(request) != r.Slot || !bytes.Equal(request[4:], key) {
		return errors.New("cleanup retry lost original outstanding command")
	}
	if run, bound, err := o.boundOperationRun(ctx, r); err != nil {
		return err
	} else if bound {
		deadline, present, err := o.OperationRunCleanupDeadline(ctx, run)
		if err != nil {
			return err
		}
		if !present || !time.Now().Before(deadline) {
			return errors.New("cleanup retry has no remaining original run clock")
		}
		previous := int64(binary.LittleEndian.Uint64(b[416:424]))
		if previous != 0 && previous != deadline.UnixNano() {
			return errors.New("cleanup retry changed original run deadline")
		}
		binary.LittleEndian.PutUint64(b[416:424], uint64(deadline.UnixNano()))
		return o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize)
	}
	previous := int64(binary.LittleEndian.Uint64(b[416:424]))
	if time.Now().Before(time.Unix(0, previous)) {
		return nil
	}
	deadline, _ := ctx.Deadline()
	if maximum := time.Now().Add(15 * time.Second); deadline.After(maximum) {
		deadline = maximum
	}
	if !time.Now().Before(deadline) || deadline.UnixNano() <= previous {
		return errors.New("cleanup retry has no new bounded original allowance")
	}
	binary.LittleEndian.PutUint64(b[416:424], uint64(deadline.UnixNano()))
	return o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize)
}

func (o *OperationFile) ReadCleanupRequest(ctx context.Context, r OperationReservation, after int64) (int64, error) {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if !o.child {
		return 0, errors.New("cleanup request read requires original native child")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return 0, err
	}
	deadline := int64(binary.LittleEndian.Uint64(b[416:424]))
	if deadline == 0 || deadline <= after {
		return 0, ErrNoOperation
	}
	if b[368] != 1 || b[370]&5 != 5 || b[373] != 0 || b[374] != 0 {
		return 0, ErrNoOperation
	}
	return deadline, nil
}

func (o *OperationFile) AbortUnsubmitted(ctx context.Context, r OperationReservation) (bool, error) {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return false, err
	}
	defer unlock()
	if o.child {
		return false, errors.New("native child cannot abort service admission")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return false, err
	}
	frame, err := o.rawRead(ctx, operationSlotSize, operationSlotSize)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(frame, make([]byte, operationSlotSize)) {
		request, err := operationBody(frame, 2)
		key, _ := r.Key.canonical()
		if err == nil && len(request) == 140 && binary.LittleEndian.Uint32(request) == r.Slot && bytes.Equal(request[4:], key) {
			return false, nil
		}
		return false, errors.New("admission absence cannot be proved from torn or foreign request")
	}
	if b[368] != 0 || b[140] != 1 {
		return false, errors.New("native operation evidence prevents unsubmitted abort")
	}
	if err := o.unsubmittedPagesAbsent(ctx, r); err != nil {
		return false, err
	}
	if b[360] == 2 {
		return true, ctx.Err()
	}
	b[360] = 2
	if err = o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize); err != nil {
		return false, err
	}
	return true, nil
}

func (o *OperationFile) SubmitCommand(ctx context.Context, command OperationCommand) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	r := command.Reservation
	if o.child || command.MTU < 576 || command.MTU > 9000 {
		return errors.New("invalid original service MTU command")
	}
	key, err := o.key(ctx, r.Key, true)
	if err != nil {
		return err
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if b[360] != 0 {
		return errors.New("operation command cannot be reused")
	}
	prior, err := o.rawRead(ctx, operationSlotSize, operationSlotSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(prior, make([]byte, operationSlotSize)) {
		return errors.New("original operation still awaits joined worker and both observers")
	}
	b[360] = 1
	binary.LittleEndian.PutUint32(b[364:368], uint32(command.MTU))
	if err = o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize); err != nil {
		return err
	}
	request := make([]byte, 140)
	binary.LittleEndian.PutUint32(request, r.Slot)
	copy(request[4:], key)
	return o.write(ctx, 2, request, operationSlotSize, operationSlotSize)
}

func (o *OperationFile) ReadCommand(ctx context.Context, afterSequence uint64) (OperationCommand, error) {
	var command OperationCommand
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return command, err
	}
	defer unlock()
	if !o.child {
		return command, errors.New("command read requires inherited native child")
	}
	frame, err := o.rawRead(ctx, operationSlotSize, operationSlotSize)
	if err != nil {
		return command, err
	}
	if bytes.Equal(frame, make([]byte, operationSlotSize)) {
		return command, ErrNoOperation
	}
	b, err := operationBody(frame, 2)
	if err != nil || len(b) != 140 {
		return command, errors.New("original command request is torn")
	}
	r := OperationReservation{binary.LittleEndian.Uint32(b), decodeOperationKey(b[4:])}
	// Expired admitted work still needs a joined no-mutation result. Its
	// deadline is checked by the worker, never renewed by this observation.
	if _, err = o.key(ctx, r.Key, false); err != nil {
		return command, err
	}
	record, err := o.record(ctx, r)
	if err != nil {
		return command, err
	}
	if record[360] != 1 || record[374] != 0 {
		return command, errors.New("request lacks original unsettled command")
	}
	if r.Key.Sequence <= afterSequence || r.Key.Sequence <= o.lastReadSequence {
		return command, ErrNoOperation
	}
	o.lastReadSequence = r.Key.Sequence
	return OperationCommand{r, int(binary.LittleEndian.Uint32(record[364:368]))}, nil
}

func (o *OperationFile) ReadBinding(ctx context.Context, r OperationReservation, role OperationRole) (ReaderBinding, error) {
	if role >= OperationReaders {
		return ReaderBinding{}, errors.New("unknown operation reader role")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return ReaderBinding{}, err
	}
	if b[140]&(1<<role) == 0 {
		return ReaderBinding{}, nil
	}
	return decodeBinding(b[144+int(role)*72 : 144+(int(role)+1)*72]), nil
}

func (o *OperationFile) resultDigest(ctx context.Context, r OperationReservation, b []byte) (string, error) {
	report := OperationReport{Command: OperationCommand{r, int(binary.LittleEndian.Uint32(b[364:368]))}, Result: decodeOperationResult(b)}
	for role := OperationRole(0); role < OperationReaders; role++ {
		if b[140]&(1<<role) == 0 {
			continue
		}
		e := &OperationReaderEvidence{Binding: decodeBinding(b[144+int(role)*72 : 144+(int(role)+1)*72])}
		report.Readers[role] = e
		for phase := ReadyEvidence; phase <= RetirementEvidence; phase++ {
			mask := b[371+int(phase)]
			if mask&(1<<role) == 0 {
				continue
			}
			raw, err := o.ReadEvidence(ctx, r, role, phase)
			if err != nil {
				return "", err
			}
			if phase == ReadyEvidence {
				e.Ready = raw
			} else {
				e.Retirement = raw
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return OperationResultDigest(report)
}

func decodeOperationResult(b []byte) OperationResult {
	return OperationResult{RunSHA256: recordRunSHA(b), CleanupOnly: b[456] == 1, CurrentRole: OperationRole(b[369]), Failed: b[370]&2 != 0, Pending: b[370]&4 != 0, WorkerJoined: b[370]&1 != 0, ReadyMask: b[371], RetirementMask: b[372], Digest: hex.EncodeToString(b[376:408]), Revision: binary.LittleEndian.Uint64(b[408:416])}
}

func (o *OperationFile) PublishResult(ctx context.Context, r OperationReservation, result OperationResult) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if !o.child || !result.WorkerJoined || result.Digest != "" {
		return errors.New("native result requires joined original worker")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if result.RunSHA256 != "" && result.RunSHA256 != recordRunSHA(b) || result.CleanupOnly && b[456] != 1 {
		return errors.New("native result replaced captured run binding")
	}
	if b[360] != 1 || b[373] != 0 || b[374] != 0 || b[368] != 0 && b[370]&4 == 0 {
		return errors.New("settled native result cannot be replaced")
	}
	if result.CurrentRole > RollbackReader && result.CurrentRole != NoReader || (result.ReadyMask|result.RetirementMask)&^b[140] != 0 {
		return errors.New("native result changed retained reader roles")
	}
	if result.CurrentRole != NoReader && (result.ReadyMask&(1<<result.CurrentRole) == 0 || result.RetirementMask&(1<<result.CurrentRole) != 0) {
		return errors.New("current native reader lacks Ready or is retired")
	}
	if !result.Pending {
		unretired := b[140] &^ result.RetirementMask
		want := byte(0)
		if result.CurrentRole != NoReader {
			want = 1 << result.CurrentRole
		}
		if unretired != want {
			return errors.New("native result omitted retained reader retirement")
		}
	}
	b[368], b[369], b[370] = 1, byte(result.CurrentRole), 1
	if result.Failed {
		b[370] |= 2
	}
	if result.Pending {
		b[370] |= 4
	}
	b[371], b[372] = result.ReadyMask, result.RetirementMask
	binary.LittleEndian.PutUint64(b[408:416], binary.LittleEndian.Uint64(b[408:416])+1)
	digest, err := o.resultDigest(ctx, r, b)
	if err != nil {
		return err
	}
	raw, _ := hex.DecodeString(digest)
	copy(b[376:408], raw)
	return o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize)
}

func (o *OperationFile) ReadResult(ctx context.Context, r OperationReservation) (OperationResult, error) {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return OperationResult{}, err
	}
	defer unlock()
	return o.readResult(ctx, r)
}

func (o *OperationFile) readResult(ctx context.Context, r OperationReservation) (OperationResult, error) {
	var result OperationResult
	b, err := o.record(ctx, r)
	if err != nil {
		return result, err
	}
	if b[368] == 0 {
		return result, ErrOperationPending
	}
	digest, err := o.resultDigest(ctx, r, b)
	if err != nil {
		if b[370]&4 != 0 {
			return result, errors.Join(ErrOperationPending, err)
		}
		return result, err
	}
	if digest != hex.EncodeToString(b[376:408]) {
		if b[370]&4 != 0 {
			return result, errors.Join(ErrOperationPending, errors.New("pending native cleanup is publishing additional original evidence"))
		}
		return result, errors.New("native result evidence digest changed")
	}
	after, err := o.record(ctx, r)
	if err != nil || !bytes.Equal(b, after) {
		return result, errors.New("native result changed during observation")
	}
	return decodeOperationResult(b), ctx.Err()
}

func (o *OperationFile) Acknowledge(ctx context.Context, r OperationReservation, role ObserverRole, digest string) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child || role > ControllerObserver {
		return errors.New("acknowledgement requires original service/controller")
	}
	result, err := o.readResult(ctx, r)
	if err != nil {
		return err
	}
	if result.Pending || !result.WorkerJoined || result.Digest != digest {
		return errors.New("observer did not acknowledge exact joined result")
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if b[374] != 0 {
		return errors.New("observer cannot acknowledge retired command")
	}
	b[373] |= 1 << role
	return o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize)
}

func (o *OperationFile) Settle(ctx context.Context, r OperationReservation, digest string) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child {
		return errors.New("native child cannot settle original observers")
	}
	result, err := o.readResult(ctx, r)
	if err != nil {
		return err
	}
	b, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if result.Pending || !result.WorkerJoined || result.Digest != digest || b[373] != 3 || b[374] != 0 {
		return errors.New("operation lacks joined worker and both original observer acknowledgements")
	}
	request, err := o.read(ctx, 2, operationSlotSize, operationSlotSize)
	key, _ := r.Key.canonical()
	if err != nil || len(request) != 140 || binary.LittleEndian.Uint32(request) != r.Slot || !bytes.Equal(request[4:], key) {
		return errors.New("settlement changed outstanding original command")
	}
	unlockCancel, err := o.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlockCancel()
	b[374] = 1
	if err = o.write(ctx, 4, b, recordOffset(r.Slot), operationRecordSize); err != nil {
		return err
	}
	// Persist settlement before clearing the outstanding slot. A partial clear
	// fails closed; it never frees the append-only transaction/evidence record.
	for _, offset := range []int64{2 * operationSlotSize, operationSlotSize} {
		if err = ctx.Err(); err != nil {
			return err
		}
		size := operationSlotSize
		if offset == 2*operationSlotSize {
			size = operationControlFrameSize
		} // Preserve the original run clock.
		if n, err := o.file.WriteAt(make([]byte, size), offset); err != nil || n != size {
			return errors.Join(err, io.ErrShortWrite)
		}
	}
	return ctx.Err()
}
