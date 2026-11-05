package standardengine

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// OperationRun binds a single optimizer lifetime. Its reader and MTU must be
// supplied by both original observers' actual capture, never a public request.
// These fields describe that retained authority; they cannot create it.
type OperationRun struct {
	CaptureSHA256   string
	ID              string
	WorkDeadlineNS  int64
	CleanupBudgetNS int64
	Original        ReaderBinding
	OriginalMTU     int
}

const OperationRunWorkLimit = 45 * time.Second

const OperationRunCleanupLimit = 8 * time.Second
const operationRunSize = 140
const operationControlFrameSize = operationSlotSize / 2
const operationRunOffset = operationControlFrameSize
const operationRunClockOffset = 2*operationSlotSize + operationControlFrameSize

type OperationRunState uint8

const (
	OperationRunOpen OperationRunState = iota
	OperationRunClosing
	OperationRunClosed
)

func (r OperationRun) canonical() ([]byte, error) {
	if !digest(r.CaptureSHA256, 32) || !digest(r.ID, 16) || r.WorkDeadlineNS <= 0 || r.CleanupBudgetNS <= 0 || r.CleanupBudgetNS > int64(OperationRunCleanupLimit) || r.OriginalMTU < 1280 || r.OriginalMTU > 9000 {
		return nil, errors.New("operation run lost captured identity or bounded allowance")
	}
	binding, err := r.Original.canonical(false)
	if err != nil {
		return nil, err
	}
	b := make([]byte, operationRunSize)
	capture, _ := hex.DecodeString(r.CaptureSHA256)
	id, _ := hex.DecodeString(r.ID)
	copy(b, capture)
	copy(b[32:], id)
	binary.LittleEndian.PutUint64(b[48:], uint64(r.WorkDeadlineNS))
	binary.LittleEndian.PutUint64(b[56:], uint64(r.CleanupBudgetNS))
	copy(b[64:], binding)
	binary.LittleEndian.PutUint32(b[136:], uint32(r.OriginalMTU))
	return b, nil
}
func (r OperationRun) SHA256() (string, error) {
	b, err := r.canonical()
	if err != nil {
		return "", err
	}
	return SHA256(b), nil
}
func decodeOperationRun(b []byte) OperationRun {
	return OperationRun{CaptureSHA256: hex.EncodeToString(b[:32]), ID: hex.EncodeToString(b[32:48]), WorkDeadlineNS: int64(binary.LittleEndian.Uint64(b[48:])), CleanupBudgetNS: int64(binary.LittleEndian.Uint64(b[56:])), Original: decodeBinding(b[64:136]), OriginalMTU: int(binary.LittleEndian.Uint32(b[136:]))}
}
