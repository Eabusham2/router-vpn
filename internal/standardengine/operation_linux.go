//go:build linux

package standardengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// A process-local mutex is required in addition to POSIX process locks:
// inherited duplicates share an open-file-description, and OFD locks alone
// cannot serialize parent and child. Separate cancellation locks never wait
// behind an operation's worker or work-region lock.
type operationLocks struct {
	work, cancel sync.Mutex
	refs         int
}

var operationRegistry = struct {
	sync.Mutex
	byIdentity map[[2]uint64]*operationLocks
}{byIdentity: make(map[[2]uint64]*operationLocks)}

type OperationFile struct {
	file             *os.File
	identity         syscall.Stat_t
	admission        error
	child            bool
	capture          string
	locks            *operationLocks
	closed           atomic.Bool
	lastReadSequence uint64
	seenRuns         map[string]bool
}

func (o *OperationFile) register() {
	operationRegistry.Lock()
	defer operationRegistry.Unlock()
	key := [2]uint64{o.identity.Dev, o.identity.Ino}
	o.locks = operationRegistry.byIdentity[key]
	if o.locks == nil {
		o.locks = &operationLocks{}
		operationRegistry.byIdentity[key] = o.locks
	}
	o.locks.refs++
}
func (o *OperationFile) unregister() {
	operationRegistry.Lock()
	defer operationRegistry.Unlock()
	o.locks.refs--
	if o.locks.refs == 0 {
		delete(operationRegistry.byIdentity, [2]uint64{o.identity.Dev, o.identity.Ino})
	}
}

// Every nonnil partial result owns its descriptor, including rejected captures.
func NewOperationFile() (owned *OperationFile, failure error) {
	defer func() {
		if owned != nil && failure != nil {
			owned.admission = failure
		}
	}()
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 319
	case "arm64":
		number = 279
	default:
		return nil, errors.New("operation file has no validated memfd ABI")
	}
	name, _ := syscall.BytePtrFromString("original-standard-operations")
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		return nil, errno
	}
	o := &OperationFile{file: os.NewFile(fd, "original-standard-operations")}
	if err := syscall.Fstat(int(fd), &o.identity); err != nil {
		return o, err
	}
	o.register()
	if err := o.file.Truncate(OperationSize); err != nil {
		return o, err
	}
	if err := o.file.Chmod(0600); err != nil {
		return o, err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, 7); errno != 0 {
		return o, errno
	}
	return o, o.Current()
}
func CaptureOperationFile(file *os.File, device, inode uint64, size int64, layout int, capture string) (owned *OperationFile, failure error) {
	defer func() {
		if owned != nil && failure != nil {
			owned.admission = failure
		}
	}()
	o := &OperationFile{file: file, child: true, capture: capture}
	if file == nil {
		return o, errors.New("operation capture omitted inherited FD11")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return o, err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		native = syscall.Fstat(int(fd), &o.identity)
		if native == nil {
			_, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, syscall.FD_CLOEXEC)
			if e != 0 {
				native = e
			}
		}
	})
	if o.identity.Ino != 0 {
		o.register()
	}
	if err != nil || native != nil {
		return o, errors.Join(err, native)
	}
	if device != o.identity.Dev || inode != o.identity.Ino || size != OperationSize || layout != OperationLayout || !digest(capture, 32) {
		o.admission = errors.New("operation descriptor differs from sealed launch capture")
		return o, o.admission
	}
	return o, o.Current()
}
func (o *OperationFile) File() *os.File {
	if o == nil {
		return nil
	}
	return o.file
}
func (o *OperationFile) Identity() (uint64, uint64) {
	if o == nil {
		return 0, 0
	}
	return o.identity.Dev, o.identity.Ino
}
func (o *OperationFile) Current() error {
	if o == nil || o.file == nil || o.closed.Load() {
		return errors.New("operation file lost original descriptor")
	}
	if o.admission != nil {
		return o.admission
	}
	raw, err := o.file.SyscallConn()
	if err != nil {
		return err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		var now syscall.Stat_t
		native = syscall.Fstat(int(fd), &now)
		if native != nil {
			return
		}
		seals, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, 1034, 0)
		if e != 0 || seals != 7 || now.Dev != o.identity.Dev || now.Ino != o.identity.Ino || now.Size != OperationSize || now.Nlink != 0 || now.Uid != 0 || now.Gid != 0 || now.Mode != syscall.S_IFREG|0600 {
			native = errors.New("operation file lost original identity, size, ownership or seals")
		}
	})
	return errors.Join(err, native)
}
func operationContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("operation requires original caller context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("operation requires original bounded caller")
	}
	return nil
}
func operationMutex(ctx context.Context, m *sync.Mutex) error {
	if err := operationContext(ctx); err != nil {
		return err
	}
	for {
		if m.TryLock() {
			if err := ctx.Err(); err != nil {
				m.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (o *OperationFile) lock(ctx context.Context, cancel bool) (func(), error) {
	if err := operationContext(ctx); err != nil {
		return nil, err
	}
	if o == nil || o.locks == nil {
		return nil, errors.New("operation has no retained lock identity")
	}
	mutex := &o.locks.work
	region := int64(0)
	if cancel {
		mutex = &o.locks.cancel
		region = 1
	}
	if err := operationMutex(ctx, mutex); err != nil {
		return nil, err
	}
	if err := o.Current(); err != nil {
		mutex.Unlock()
		return nil, err
	}
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart, Start: region, Len: 1}
	for {
		err := syscall.FcntlFlock(o.file.Fd(), syscall.F_SETLK, &lock)
		if err == nil {
			return func() {
				lock.Type = syscall.F_UNLCK
				_ = syscall.FcntlFlock(o.file.Fd(), syscall.F_SETLK, &lock)
				mutex.Unlock()
			}, nil
		}
		if err != syscall.EAGAIN && err != syscall.EACCES {
			mutex.Unlock()
			return nil, err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			mutex.Unlock()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Close has its own caller budget. It refuses replacement descriptors and never
// closes FD10 or settles a pending native owner. The process owner closes FD11
// only after child join, or after the child's retirement owner has completed.
func (o *OperationFile) Close(ctx context.Context) error {
	if o == nil || o.file == nil || o.closed.Load() {
		return nil
	}
	if err := operationContext(ctx); err != nil {
		return err
	}
	if o.locks != nil {
		if err := operationMutex(ctx, &o.locks.work); err != nil {
			return err
		}
		defer o.locks.work.Unlock()
		if err := operationMutex(ctx, &o.locks.cancel); err != nil {
			return err
		}
		defer o.locks.cancel.Unlock()
	}
	raw, err := o.file.SyscallConn()
	if err != nil {
		return err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		var now syscall.Stat_t
		native = syscall.Fstat(int(fd), &now)
		if native == nil && o.identity.Ino != 0 && (now.Dev != o.identity.Dev || now.Ino != o.identity.Ino) {
			native = errors.New("operation close refuses replacement descriptor")
		}
	})
	if err != nil || native != nil {
		return errors.Join(err, native)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := o.file.Close(); err != nil {
		return err
	}
	o.closed.Store(true)
	if o.locks != nil {
		o.unregister()
	}
	return nil
}
func (o *OperationFile) write(ctx context.Context, kind uint32, body []byte, offset int64, size int) error {
	if err := operationContext(ctx); err != nil {
		return err
	}
	if err := o.Current(); err != nil {
		return err
	}
	frame, err := operationFrame(kind, body, size)
	if err != nil {
		return err
	}
	if n, err := o.file.WriteAt(frame, offset); err != nil || n != len(frame) {
		return errors.Join(err, io.ErrShortWrite)
	}
	return errors.Join(ctx.Err(), o.Current())
}
func (o *OperationFile) rawRead(ctx context.Context, offset int64, size int) ([]byte, error) {
	if err := operationContext(ctx); err != nil {
		return nil, err
	}
	if err := o.Current(); err != nil {
		return nil, err
	}
	raw := make([]byte, size)
	if n, err := o.file.ReadAt(raw, offset); err != nil || n != size {
		return nil, errors.Join(err, io.ErrUnexpectedEOF)
	}
	return raw, errors.Join(ctx.Err(), o.Current())
}
func (o *OperationFile) read(ctx context.Context, kind uint32, offset int64, size int) ([]byte, error) {
	raw, err := o.rawRead(ctx, offset, size)
	if err != nil {
		return nil, err
	}
	again, err := o.rawRead(ctx, offset, size)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, again) {
		return nil, errors.New("operation frame changed during readback")
	}
	return operationBody(raw, kind)
}
func (o *OperationFile) BindCapture(ctx context.Context, capture string) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if o.child || o.capture != "" || !digest(capture, 32) {
		return errors.New("operation capture binding was reused or malformed")
	}
	o.capture = capture
	return ctx.Err()
}

// The authenticated Ready exchange is admitted only after this exact FD11
// launch receipt is present. This proves descriptor inheritance, not MTU authority.
func (o *OperationFile) AcknowledgeLaunch(ctx context.Context, initialReceipt string) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if !o.child || !digest(o.capture, 32) || len(initialReceipt) == 0 || len(initialReceipt) > 16<<10 {
		return errors.New("operation launch omitted actual startup receipt")
	}
	existing, err := o.rawRead(ctx, 0, operationControlFrameSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, make([]byte, operationControlFrameSize)) {
		return errors.New("operation launch acknowledgement cannot be replaced")
	}
	capture, _ := hex.DecodeString(o.capture)
	receipt := sha256.Sum256([]byte(initialReceipt))
	return o.write(ctx, 1, append(capture, receipt[:]...), 0, operationControlFrameSize)
}
func (o *OperationFile) VerifyLaunch(ctx context.Context, initialReceipt string) error {
	body, err := o.read(ctx, 1, 0, operationControlFrameSize)
	if err != nil {
		return err
	}
	capture, _ := hex.DecodeString(o.capture)
	receipt := sha256.Sum256([]byte(initialReceipt))
	if len(body) != 64 || !digest(o.capture, 32) || !bytes.Equal(body, append(capture, receipt[:]...)) {
		return errors.New("operation launch belongs to another capture or startup receipt")
	}
	return ctx.Err()
}
func (o *OperationFile) key(ctx context.Context, key OperationKey, work bool) ([]byte, error) {
	if err := operationContext(ctx); err != nil {
		return nil, err
	}
	raw, err := key.canonical()
	if err != nil {
		return nil, err
	}
	if key.CaptureSHA256 != o.capture || !digest(o.capture, 32) {
		return nil, errors.New("operation belongs to another original capture")
	}
	if work && !time.Now().Before(time.Unix(0, key.DeadlineNS)) {
		return nil, errors.New("operation original work deadline expired")
	}
	return raw, nil
}
func recordOffset(slot uint32) int64 {
	return int64(operationRecordsOffset + int(slot)*operationRecordSize)
}
func (o *OperationFile) record(ctx context.Context, r OperationReservation) ([]byte, error) {
	if r.Slot >= OperationTransactions {
		return nil, errors.New("operation reservation slot outside fixed capacity")
	}
	key, err := o.key(ctx, r.Key, false)
	if err != nil {
		return nil, err
	}
	body, err := o.read(ctx, 4, recordOffset(r.Slot), operationRecordSize)
	if err != nil {
		return nil, err
	}
	if len(body) != operationRecordBodySize || binary.LittleEndian.Uint32(body) != r.Slot || !bytes.Equal(body[4:140], key) || body[140]&^byte(7) != 0 || body[140]&1 == 0 || !bytes.Equal(body[141:144], []byte{0, 0, 0}) {
		return nil, errors.New("operation reservation differs from original key")
	}
	for role := 0; role < OperationReaders; role++ {
		raw := body[144+role*72 : 144+(role+1)*72]
		if body[140]&(1<<role) == 0 {
			if !bytes.Equal(raw, make([]byte, 72)) {
				return nil, errors.New("unbound operation role has evidence")
			}
			continue
		}
		binding := decodeBinding(raw)
		canonical, err := binding.canonical(role != 0)
		if err != nil || !bytes.Equal(raw, canonical) || role == 0 && binding != r.Key.Original {
			return nil, errors.New("operation role changed its captured binding")
		}
	}
	if err := validateOperationExtension(body); err != nil {
		return nil, err
	}
	return body, nil
}
func (o *OperationFile) Reserve(ctx context.Context, key OperationKey) (OperationReservation, error) {
	r := OperationReservation{Key: key}
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return r, err
	}
	defer unlock()
	raw, err := o.key(ctx, key, true)
	if err != nil {
		return r, err
	}
	deadline, _ := ctx.Deadline()
	if o.child || key.DeadlineNS > deadline.UnixNano() {
		return r, errors.New("operation reservation renewed work or used child authority")
	}
	for slot := uint32(0); slot < OperationTransactions; slot++ {
		frame, err := o.rawRead(ctx, recordOffset(slot), operationRecordSize)
		if err != nil {
			return r, err
		}
		if bytes.Equal(frame, make([]byte, operationRecordSize)) {
			r.Slot = slot
			body := make([]byte, operationRecordBodySize)
			binary.LittleEndian.PutUint32(body, slot)
			copy(body[4:], raw)
			body[140] = 1
			copy(body[144:], raw[64:])
			return r, o.write(ctx, 4, body, recordOffset(slot), operationRecordSize)
		}
		body, err := operationBody(frame, 4)
		if err != nil || len(body) != operationRecordBodySize {
			return r, errors.New("operation reservation history is torn")
		}
		prior := decodeOperationKey(body[4:140])
		if _, err := o.record(ctx, OperationReservation{slot, prior}); err != nil {
			return r, err
		}
		if key.Sequence <= prior.Sequence || key.ID == prior.ID {
			return r, errors.New("operation sequence or ID replayed")
		}
	}
	return r, errors.New("operation transaction capacity exhausted before construction")
}
func (o *OperationFile) BindReader(ctx context.Context, r OperationReservation, role OperationRole, binding ReaderBinding) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if !o.child || role == OriginalReader || role >= OperationReaders {
		return errors.New("operation cannot replace original or unknown reader")
	}
	raw, err := binding.canonical(true)
	if err != nil {
		return err
	}
	body, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if body[360] == 2 {
		return errors.New("aborted operation cannot acquire a native reader")
	}
	if body[140]&(1<<role) != 0 {
		return errors.New("operation reader binding cannot be replaced")
	}
	body[140] |= 1 << role
	copy(body[144+int(role)*72:], raw)
	return o.write(ctx, 4, body, recordOffset(r.Slot), operationRecordSize)
}
func (o *OperationFile) Submit(ctx context.Context, r OperationReservation) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	key, err := o.key(ctx, r.Key, true)
	if err != nil {
		return err
	}
	if o.child {
		return errors.New("operation child cannot submit work")
	}
	record, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if record[360] != 0 {
		return errors.New("operation reservation already belongs to a command or aborted admission")
	}
	frame, err := o.rawRead(ctx, operationSlotSize, operationSlotSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(frame, make([]byte, operationSlotSize)) {
		return errors.New("operation request remains retained until worker join and both original observer acknowledgements")
	}
	body := make([]byte, 140)
	binary.LittleEndian.PutUint32(body, r.Slot)
	copy(body[4:], key)
	return o.write(ctx, 2, body, operationSlotSize, operationSlotSize)
}
func (o *OperationFile) ReadRequest(ctx context.Context, afterSequence uint64) (OperationReservation, error) {
	var r OperationReservation
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return r, err
	}
	defer unlock()
	if !o.child {
		return r, errors.New("operation request requires inherited child")
	}
	body, err := o.read(ctx, 2, operationSlotSize, operationSlotSize)
	if err != nil {
		return r, err
	}
	if len(body) != 140 {
		return r, errors.New("operation request has invalid size")
	}
	r = OperationReservation{binary.LittleEndian.Uint32(body), decodeOperationKey(body[4:])}
	if r.Key.Sequence <= afterSequence || r.Key.Sequence <= o.lastReadSequence {
		return r, errors.New("operation request sequence replayed")
	}
	if _, err := o.key(ctx, r.Key, true); err != nil {
		return r, err
	}
	_, err = o.record(ctx, r)
	if err == nil {
		o.lastReadSequence = r.Key.Sequence
	}
	return r, err
}
func (o *OperationFile) Cancel(ctx context.Context, r OperationReservation) error {
	unlock, err := o.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlock()
	key, err := o.key(ctx, r.Key, false)
	if err != nil {
		return err
	}
	if o.child {
		return errors.New("operation child cannot substitute cancellation")
	}
	if _, err := o.record(ctx, r); err != nil {
		return err
	}
	if _, _, err := o.boundOperationRun(ctx, r); err != nil {
		return err
	}
	request, err := o.read(ctx, 2, operationSlotSize, operationSlotSize)
	if err != nil {
		return err
	}
	if len(request) != 140 || binary.LittleEndian.Uint32(request) != r.Slot || !bytes.Equal(request[4:], key) {
		return errors.New("operation cancellation does not name the original outstanding request")
	}

	frame, err := o.rawRead(ctx, 2*operationSlotSize, operationControlFrameSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(frame, make([]byte, operationControlFrameSize)) {
		body, err := operationBody(frame, 3)
		if err != nil || len(body) != 140 {
			return errors.New("operation cancellation history is torn")
		}
		prior := decodeOperationKey(body[4:])
		if prior.Sequence > r.Key.Sequence || prior.Sequence == r.Key.Sequence && prior != r.Key {
			return errors.New("operation cancellation replayed another key")
		}
	}
	body := make([]byte, 140)
	binary.LittleEndian.PutUint32(body, r.Slot)
	copy(body[4:], key)
	return o.write(ctx, 3, body, 2*operationSlotSize, operationControlFrameSize)
}
func (o *OperationFile) Cancelled(ctx context.Context, r OperationReservation) (bool, error) {
	if _, err := o.record(ctx, r); err != nil {
		return false, err
	}
	frame, err := o.rawRead(ctx, 2*operationSlotSize, operationControlFrameSize)
	if err != nil {
		return false, err
	}
	if bytes.Equal(frame, make([]byte, operationControlFrameSize)) {
		return false, nil
	}
	body, err := o.read(ctx, 3, 2*operationSlotSize, operationControlFrameSize)
	if err != nil {
		return false, err
	}
	if len(body) != 140 {
		return false, errors.New("operation cancellation has invalid size")
	}
	key := decodeOperationKey(body[4:])
	if key.Sequence < r.Key.Sequence {
		return false, nil
	}
	if binary.LittleEndian.Uint32(body) != r.Slot || key != r.Key {
		return false, errors.New("operation cancellation does not match original work")
	}
	return true, nil
}
func operationPage(r OperationReservation, role OperationRole, phase OperationPhase) (int, error) {
	if r.Slot >= OperationTransactions || role >= OperationReaders || phase > RetirementEvidence {
		return 0, errors.New("operation page outside fixed layout")
	}
	return int(r.Slot)*6 + int(role)*2 + int(phase), nil
}
func (o *OperationFile) PublishEvidence(ctx context.Context, r OperationReservation, role OperationRole, phase OperationPhase, receipt []byte) error {
	return o.publishEvidence(ctx, r, role, phase, receipt, false)
}

// PublishJoinedEvidence preserves actual native evidence after the worker has
// joined, including cancellation/rollback. It cannot grant late winner adoption.
// The retained worker calls this with a bounded read-only observation context;
// publishing joined evidence grants no further native work or cleanup time.
func (o *OperationFile) PublishJoinedEvidence(ctx context.Context, r OperationReservation, role OperationRole, phase OperationPhase, receipt []byte) error {
	return o.publishEvidence(ctx, r, role, phase, receipt, true)
}

func (o *OperationFile) publishEvidence(ctx context.Context, r OperationReservation, role OperationRole, phase OperationPhase, receipt []byte, joined bool) error {
	unlock, err := o.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	page, err := operationPage(r, role, phase)
	if err != nil {
		return err
	}
	if !o.child {
		return errors.New("operation evidence requires original child writer")
	}
	key, err := o.key(ctx, r.Key, phase == ReadyEvidence && !joined)
	if err != nil {
		return err
	}
	record, err := o.record(ctx, r)
	if err != nil {
		return err
	}
	if record[360] == 2 {
		return errors.New("aborted operation cannot acquire native evidence")
	}
	if record[140]&(1<<role) == 0 {
		return errors.New("operation page has no retained reader binding")
	}
	bindingRaw := record[144+int(role)*72 : 144+(int(role)+1)*72]
	binding := decodeBinding(bindingRaw)
	bound := 48 << 10
	if phase == ReadyEvidence {
		bound = 16 << 10
	}
	if len(receipt) == 0 || len(receipt) > bound {
		return errors.New("operation raw receipt exceeds phase bound")
	}
	if joined && phase == ReadyEvidence && role != OriginalReader && binding.InitialReceiptSHA256 == "" {
		// A partial native reader can expose its actual cached initial Ready
		// only during joined cleanup. Complete that empty digest once, retaining
		// the exact already-bound identity/generation. No acknowledged result or
		// published Ready may be changed by this completion.
		if record[373] != 0 || record[374] != 0 || record[368] != 0 && record[370]&4 == 0 {
			return errors.New("completed reader cannot gain another initial receipt")
		}
		binding.InitialReceiptSHA256 = SHA256(receipt)
		canonical, err := binding.canonical(true)
		if err != nil {
			return err
		}
		copy(bindingRaw, canonical)
		if err := o.write(ctx, 4, record, recordOffset(r.Slot), operationRecordSize); err != nil {
			return err
		}
	}
	if phase == ReadyEvidence && SHA256(receipt) != binding.InitialReceiptSHA256 {
		return errors.New("operation Ready differs from actual initial receipt")
	}
	headerOffset := int64(operationHeadersOffset + page*operationHeaderSize)
	old, err := o.rawRead(ctx, headerOffset, operationHeaderSize)
	if err != nil {
		return err
	}
	if !bytes.Equal(old, make([]byte, operationHeaderSize)) {
		if joined {
			prior, readErr := o.ReadEvidence(ctx, r, role, phase)
			if readErr == nil && bytes.Equal(prior, receipt) {
				return ctx.Err()
			}
		}
		return errors.New("operation evidence page cannot be replaced or reused")
	}
	payload := make([]byte, OperationPageSize)
	copy(payload, receipt)
	if err := ctx.Err(); err != nil {
		return err
	}
	if n, err := o.file.WriteAt(payload, int64(OperationControlSize+page*OperationPageSize)); err != nil || n != len(payload) {
		return errors.Join(err, io.ErrShortWrite)
	}
	body := make([]byte, 148)
	binary.LittleEndian.PutUint32(body, r.Slot)
	body[4] = byte(role)
	body[5] = byte(phase)
	keyDigest := sha256.Sum256(key)
	copy(body[8:], keyDigest[:])
	copy(body[40:], bindingRaw)
	binary.LittleEndian.PutUint32(body[112:], uint32(len(receipt)))
	sum := sha256.Sum256(payload)
	copy(body[116:], sum[:])
	return o.write(ctx, 5, body, headerOffset, operationHeaderSize)
}
func (o *OperationFile) ReadEvidence(ctx context.Context, r OperationReservation, role OperationRole, phase OperationPhase) ([]byte, error) {
	page, err := operationPage(r, role, phase)
	if err != nil {
		return nil, err
	}
	record, err := o.record(ctx, r)
	if err != nil {
		return nil, err
	}
	headerOffset := int64(operationHeadersOffset + page*operationHeaderSize)
	before, err := o.rawRead(ctx, headerOffset, operationHeaderSize)
	if err != nil {
		return nil, err
	}
	body, err := operationBody(before, 5)
	if err != nil {
		return nil, err
	}
	if len(body) != 148 {
		return nil, errors.New("operation page header has invalid size")
	}
	key, _ := r.Key.canonical()
	keyDigest := sha256.Sum256(key)
	bindingRaw := record[144+int(role)*72 : 144+(int(role)+1)*72]
	bindingMatches := bytes.Equal(body[40:112], bindingRaw)
	// A retirement captured before the partial reader exposed its cached Ready
	// keeps the empty initial digest, bound to the same identity/generation.
	if !bindingMatches && role != OriginalReader && phase == RetirementEvidence && bytes.Equal(body[40:80], bindingRaw[:40]) && bytes.Equal(body[80:112], make([]byte, 32)) {
		bindingMatches = true
	}
	if record[140]&(1<<role) == 0 || binary.LittleEndian.Uint32(body) != r.Slot || body[4] != byte(role) || body[5] != byte(phase) || body[6] != 0 || body[7] != 0 || !bytes.Equal(body[8:40], keyDigest[:]) || !bindingMatches {
		return nil, errors.New("operation page substituted key, role or reader")
	}
	count := int(binary.LittleEndian.Uint32(body[112:]))
	bound := 48 << 10
	if phase == ReadyEvidence {
		bound = 16 << 10
	}
	if count < 1 || count > bound {
		return nil, errors.New("operation page has invalid raw receipt bound")
	}
	payload, err := o.rawRead(ctx, int64(OperationControlSize+page*OperationPageSize), OperationPageSize)
	if err != nil {
		return nil, err
	}
	after, err := o.rawRead(ctx, headerOffset, operationHeaderSize)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(before, after) || !bytes.Equal(body[116:], sum[:]) || !bytes.Equal(payload[count:], make([]byte, OperationPageSize-count)) {
		return nil, errors.New("operation page is partial, torn or changed during readback")
	}
	if phase == ReadyEvidence && SHA256(payload[:count]) != decodeBinding(bindingRaw).InitialReceiptSHA256 {
		return nil, errors.New("operation Ready lost original receipt digest")
	}
	return payload[:count], ctx.Err()
}
