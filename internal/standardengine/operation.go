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
const OperationLayout = 1
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
