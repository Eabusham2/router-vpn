package standardengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// FD11 carries bounded evidence and operation identity, never authority to
// construct a reader, change MTU, or adopt an observer from serialized text.
const OperationFD = 11
const OperationLayout = 2
const OperationControlSize = 64 << 10

// Pages carry raw bounded evidence. They do not relax the native receipt
// parser's canonical limit (currently 16 KiB per reader, including retirement).
const OperationPageSize = 64 << 10
const OperationTransactions = 32
const OperationReaders = 3
const OperationSize = OperationControlSize + OperationTransactions*OperationReaders*2*OperationPageSize
const operationSlotSize = 1024
const operationRecordSize = 512
const operationHeaderSize = 240
const operationRecordsOffset = 3 * operationSlotSize
const operationHeadersOffset = operationRecordsOffset + OperationTransactions*operationRecordSize
const operationKeySize = 136
const operationBindingSize = 72
const operationEnvelopeSize = 48
const operationRecordBodySize = 424

var ErrNoOperation = errors.New("no new original operation")
var ErrOperationPending = errors.New("original operation worker has not published joined evidence")

const NoReader OperationRole = 255

type ObserverRole uint8

const (
	ServiceObserver ObserverRole = iota
	ControllerObserver
)

type OperationCommand struct {
	Reservation OperationReservation
	MTU         int
}

type OperationResult struct {
	CurrentRole                   OperationRole
	Failed, Pending, WorkerJoined bool
	ReadyMask, RetirementMask     uint8
	Digest                        string
	Revision                      uint64
}

type OperationReaderEvidence struct {
	Binding           ReaderBinding
	Ready, Retirement []byte
}

type OperationReport struct {
	Command OperationCommand
	Result  OperationResult
	Readers [OperationReaders]*OperationReaderEvidence
}

// OperationResultDigest is shared by the native writer and both independent
// observers. It validates serialized evidence identity only; each observer must
// additionally admit the exact native receipts on its already retained epoch.
func OperationResultDigest(report OperationReport) (string, error) {
	r, result := report.Command.Reservation, report.Result
	key, err := r.Key.canonical()
	if err != nil || r.Slot >= OperationTransactions || report.Command.MTU < 576 || report.Command.MTU > 9000 || !result.WorkerJoined || result.Revision == 0 || result.CurrentRole > RollbackReader && result.CurrentRole != NoReader || result.ReadyMask&^uint8(7) != 0 || result.RetirementMask&^uint8(7) != 0 {
		return "", errors.New("operation report omitted bounded joined identity")
	}
	frame := make([]byte, 160)
	copy(frame, key)
	binary.LittleEndian.PutUint32(frame[136:], r.Slot)
	binary.LittleEndian.PutUint32(frame[140:], uint32(report.Command.MTU))
	binary.LittleEndian.PutUint64(frame[144:], result.Revision)
	frame[152], frame[153], frame[154] = byte(result.CurrentRole), result.ReadyMask, result.RetirementMask
	if result.Failed {
		frame[155] = 1
	}
	if result.Pending {
		frame[156] = 1
	}
	hash := sha256.New()
	_, _ = hash.Write(frame)
	for role := OperationRole(0); role < OperationReaders; role++ {
		e := report.Readers[role]
		ready, retired := result.ReadyMask&(1<<role) != 0, result.RetirementMask&(1<<role) != 0
		if e == nil {
			if role == OriginalReader || ready || retired || result.CurrentRole == role {
				return "", errors.New("native report omitted retained reader")
			}
			_, _ = hash.Write([]byte{byte(role), 0})
			continue
		}
		binding, err := e.Binding.canonical(role != OriginalReader)
		if err != nil || role == OriginalReader && e.Binding != r.Key.Original || ready != (len(e.Ready) != 0) || retired != (len(e.Retirement) != 0) || len(e.Ready) > 16<<10 || len(e.Retirement) > 48<<10 || ready && SHA256(e.Ready) != e.Binding.InitialReceiptSHA256 {
			return "", errors.New("native report changed retained reader evidence")
		}
		if result.CurrentRole == role && (!ready || retired) || !result.Pending && result.CurrentRole != role && !retired {
			return "", errors.New("native report omitted original resource settlement")
		}
		_, _ = hash.Write([]byte{byte(role), 1})
		_, _ = hash.Write(binding)
		for _, raw := range [][]byte{e.Ready, e.Retirement} {
			sum := sha256.Sum256(raw)
			_, _ = hash.Write(sum[:])
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// InitialReaderBinding describes the original retained reader. It is not a
// capability to acquire a reader from a digest or a current interface name.
func InitialReaderBinding(captureSHA, ready string) ReaderBinding {
	return ReaderBinding{SHA256([]byte("standard-original-reader\x00" + captureSHA + "\x00" + ready)), 1, SHA256([]byte(ready))}
}

// ReaderBinding is a digest of an identity retained by the coordinator, not a
// reader lookup key. Generation and initial receipt belong to that exact reader.
type ReaderBinding struct {
	IdentitySHA256       string
	Generation           uint64
	InitialReceiptSHA256 string
}
type OperationKey struct {
	CaptureSHA256 string
	ID            string
	Sequence      uint64
	DeadlineNS    int64
	Original      ReaderBinding
}
type OperationRole uint8

const (
	OriginalReader OperationRole = iota
	CandidateReader
	RollbackReader
)

type OperationPhase uint8

const (
	ReadyEvidence OperationPhase = iota
	RetirementEvidence
)

// OperationReservation is append-only. No release/reset/reuse API exists: a
// later coordinator must join the worker and obtain BOTH original observers'
// acknowledgements before any such authority can be added.
type OperationReservation struct {
	Slot uint32
	Key  OperationKey
}

func (b ReaderBinding) canonical(allowAbsentReady bool) ([]byte, error) {
	if !digest(b.IdentitySHA256, 32) || b.Generation == 0 || (!digest(b.InitialReceiptSHA256, 32) && !(allowAbsentReady && b.InitialReceiptSHA256 == "")) {
		return nil, errors.New("operation reader lacks its original identity, generation or initial receipt")
	}
	raw := make([]byte, operationBindingSize)
	identity, _ := hex.DecodeString(b.IdentitySHA256)
	initial, _ := hex.DecodeString(b.InitialReceiptSHA256)
	copy(raw, identity)
	binary.LittleEndian.PutUint64(raw[32:], b.Generation)
	copy(raw[40:], initial)
	return raw, nil
}
func decodeBinding(raw []byte) ReaderBinding {
	initial := hex.EncodeToString(raw[40:72])
	if bytes.Equal(raw[40:72], make([]byte, 32)) {
		initial = ""
	}
	return ReaderBinding{hex.EncodeToString(raw[:32]), binary.LittleEndian.Uint64(raw[32:]), initial}
}
func (k OperationKey) canonical() ([]byte, error) {
	binding, err := k.Original.canonical(false)
	if err != nil || !digest(k.CaptureSHA256, 32) || !digest(k.ID, 16) || k.Sequence == 0 || k.DeadlineNS <= 0 {
		return nil, errors.New("operation omitted its original bounded key")
	}
	raw := make([]byte, operationKeySize)
	capture, _ := hex.DecodeString(k.CaptureSHA256)
	id, _ := hex.DecodeString(k.ID)
	copy(raw, capture)
	copy(raw[32:], id)
	binary.LittleEndian.PutUint64(raw[48:], k.Sequence)
	binary.LittleEndian.PutUint64(raw[56:], uint64(k.DeadlineNS))
	copy(raw[64:], binding)
	return raw, nil
}
func decodeOperationKey(raw []byte) OperationKey {
	return OperationKey{hex.EncodeToString(raw[:32]), hex.EncodeToString(raw[32:48]), binary.LittleEndian.Uint64(raw[48:]), int64(binary.LittleEndian.Uint64(raw[56:])), decodeBinding(raw[64:])}
}
func operationFrame(kind uint32, body []byte, size int) ([]byte, error) {
	if len(body) == 0 || len(body) > size-operationEnvelopeSize {
		return nil, errors.New("operation frame exceeds fixed bound")
	}
	frame := make([]byte, size)
	copy(frame, []byte{'R', 'V', 'O', 'P', 11, OperationLayout, 0, 0})
	binary.LittleEndian.PutUint32(frame[8:], kind)
	binary.LittleEndian.PutUint32(frame[12:], uint32(len(body)))
	copy(frame[operationEnvelopeSize:], body)
	sum := sha256.Sum256(frame)
	copy(frame[16:48], sum[:])
	return frame, nil
}
func operationBody(frame []byte, kind uint32) ([]byte, error) {
	if len(frame) < operationEnvelopeSize || !bytes.Equal(frame[:8], []byte{'R', 'V', 'O', 'P', 11, OperationLayout, 0, 0}) || binary.LittleEndian.Uint32(frame[8:]) != kind {
		return nil, errors.New("operation frame absent or has another layout/kind")
	}
	size := int(binary.LittleEndian.Uint32(frame[12:]))
	if size < 1 || size > len(frame)-operationEnvelopeSize {
		return nil, errors.New("operation frame has invalid length")
	}
	want := append([]byte(nil), frame[16:48]...)
	scratch := append([]byte(nil), frame...)
	clear(scratch[16:48])
	sum := sha256.Sum256(scratch)
	if !bytes.Equal(want, sum[:]) || !bytes.Equal(frame[operationEnvelopeSize+size:], make([]byte, len(frame)-operationEnvelopeSize-size)) {
		return nil, errors.New("operation frame is torn or noncanonical")
	}
	return append([]byte(nil), frame[operationEnvelopeSize:operationEnvelopeSize+size]...), nil
}
