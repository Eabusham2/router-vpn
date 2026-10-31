//go:build windows

package windowsprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

// BeginRecovery captures the complete, locked journal opened for the actual
// authenticated desktop and original Data directory. It does not accept a
// caller's record, PID, pathname, profile or BFE baseline. It opens no native
// policy owner; Run independently retires all old processes and observes the
// exact recorded alternatives before acknowledging its handover.
func (store *ProtectionJournal) BeginRecovery(ctx context.Context) (*JournalRecovery, error) {
	return store.beginRecovery(ctx, func(candidates []*mobiletor.DesktopWindowsProtectionTarget, callback func(context.Context, int) error) (journalRecoveryObservation, error) {
		return mobiletor.NewDesktopWindowsProtectionObservation(candidates, callback)
	})
}

// Only the native storage/process fixture injects BFE observation here. The
// exported entry always retains the real synchronous BFE transaction owner.
func (store *ProtectionJournal) beginRecovery(ctx context.Context,
	observe func([]*mobiletor.DesktopWindowsProtectionTarget, func(context.Context, int) error) (journalRecoveryObservation, error)) (*JournalRecovery, error) {
	if store == nil {
		return nil, errors.New("Windows journal recovery has no retained store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.verifyController(ctx); err != nil {
		return nil, err
	}
	if store.recovery != nil {
		return store.recovery, errors.New("Windows journal already retains its exact recovery operation")
	}
	if store.pending != nil || store.current.Incomplete || store.current.Record.Controller == store.controller {
		return nil, errors.New("Windows journal recovery requires a complete older-controller record")
	}
	if err := store.verifyObjects(); err != nil {
		return nil, err
	}
	selection, raw, err := store.readSelection()
	if err != nil || selection.Incomplete || selection.SHA256 != store.current.SHA256 || selection.Slot != store.current.Slot || !bytes.Equal(raw, store.currentBytes) {
		return nil, errors.Join(err, errors.New("Windows journal recovery changed its retained original head"))
	}
	processes, err := journalRecoveryProcesses(selection.Record)
	if err != nil {
		return nil, err
	}
	var request [16]byte
	if _, err := rand.Read(request[:]); err != nil {
		return nil, err
	}
	backend := &journalRecoveryNative{store: store}
	for _, recorded := range processes {
		backend.processes = append(backend.processes, &journalRetirementWitness{recorded: recorded})
	}
	owner, err := newJournalRecovery(selection, store.controller, hex.EncodeToString(request[:]), backend, observe)
	if owner != nil {
		backend.owner, store.recovery = owner, owner
	}
	return owner, err
}

type journalRecoveryNative struct {
	store     *ProtectionJournal
	owner     *JournalRecovery
	processes []*journalRetirementWitness
	snapshot  *journalProcessSnapshot
	retired   bool
	closed    bool
	closeErr  error
}

// verifyLocked deliberately proves the new desktop as well as the elevated
// controller. Its SID and exact Data/header identities are the originals
// already checked by OpenProtectionJournal, never the administrator's profile.
func (native *journalRecoveryNative) verifyLocked(ctx context.Context) error {
	store, owner := native.store, native.owner
	if store == nil || owner == nil || store.recovery != owner {
		return errors.New("Windows journal recovery lost its exclusive captured operation")
	}
	if err := store.verifyController(ctx); err != nil {
		return err
	}
	desktop, identity, err := journalProcessCapture(store.desktop)
	if err != nil || desktop != store.desktopCapture || identity != store.desktopIdentity {
		return errors.Join(err, errors.New("Windows journal recovery lost its original authenticated desktop"))
	}
	if err := store.verifyObjects(); err != nil {
		return err
	}
	if store.current.Incomplete || store.current.SHA256 != owner.head.SHA256 && (owner.durable == nil || store.current.SHA256 != owner.durable.Selection.SHA256) {
		return errors.New("Windows journal recovery changed its captured durable generation")
	}
	if store.pending != nil {
		if owner.adoption == nil {
			return errors.New("Windows journal recovery has an uncaptured pending write")
		}
		wanted, err := CanonicalJournalRecord(*owner.adoption)
		if err != nil || !bytes.Equal(store.pending.body, wanted) {
			return errors.New("Windows journal recovery changed its immutable pending bytes")
		}
		actual, err := journalReadRetained(store.slots[store.current.Slot], JournalRecordLimit)
		if err != nil || !bytes.Equal(actual, store.currentBytes) {
			return errors.Join(err, errors.New("Windows journal recovery lost its preceding complete slot"))
		}
		return ctx.Err()
	}
	selection, raw, err := store.readSelection()
	if err != nil || selection.Incomplete || selection.SHA256 != store.current.SHA256 || selection.Slot != store.current.Slot || !bytes.Equal(raw, store.currentBytes) {
		return errors.Join(err, errors.New("Windows journal recovery head changed outside its owned append"))
	}
	return ctx.Err()
}

func (native *journalRecoveryNative) verify(ctx context.Context) error {
	native.store.mu.Lock()
	defer native.store.mu.Unlock()
	return native.verifyLocked(ctx)
}

func (native *journalRecoveryNative) retire(ctx context.Context) error {
	if native.closed {
		return errors.New("Windows journal recovery process witnesses are closed")
	}
	if native.retired {
		return ctx.Err()
	}
	if err := native.verify(ctx); err != nil {
		return err
	}
	needSnapshot := false
	for _, witness := range native.processes {
		needSnapshot = needSnapshot || !witness.retired && witness.process == nil
	}
	if needSnapshot {
		if native.snapshot != nil {
			if err := native.snapshot.close(); err != nil {
				return err
			}
			native.snapshot = nil
		}
		var err error
		native.snapshot, err = captureJournalProcessSnapshot(ctx)
		if err != nil {
			return err // partial snapshot remains owned; errors never prove absence
		}
	}
	for _, witness := range native.processes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if witness.retired {
			continue
		}
		if witness.process == nil {
			if native.snapshot == nil || !native.snapshot.complete {
				return errors.New("Windows journal retirement has no complete process snapshot")
			}
			if !native.snapshot.pids[witness.recorded.PID] {
				witness.retired = true // positive absence in a complete native snapshot
				continue
			}
			var err error
			witness.process, err = windowscontroller.OpenProcess(witness.recorded.PID)
			if err != nil {
				return err // access denial or an exit race is not proof of absence
			}
		}
		if err := witness.prove(ctx); err != nil {
			return err
		}
	}
	native.retired = true
	return native.verify(ctx)
}

func (native *journalRecoveryNative) append(ctx context.Context, next JournalRecord) (JournalSelection, error) {
	store, owner := native.store, native.owner
	store.mu.Lock()
	defer store.mu.Unlock()
	if !native.retired || native.closed {
		return JournalSelection{}, errors.New("Windows journal handover preceded its independent process retirement")
	}
	if err := native.verifyLocked(ctx); err != nil {
		return JournalSelection{}, err
	}
	if next.Controller != store.controller || CheckJournalRecoveryTransition(owner.head.Record, next) != nil {
		return JournalSelection{}, errors.New("Windows journal native adoption changed its captured transition")
	}
	body, err := CanonicalJournalRecord(next)
	if err != nil {
		return JournalSelection{}, err
	}
	digest, _ := JournalRecordSHA256(body)
	if store.current.SHA256 == digest && store.pending == nil {
		return cloneJournalSelection(store.current), store.verifyController(ctx)
	}
	if store.current.SHA256 != owner.head.SHA256 {
		return JournalSelection{}, errors.New("Windows journal adoption cannot replace another acknowledged generation")
	}
	return store.appendCanonicalLocked(ctx, owner.head.SHA256, next, body)
}

func (native *journalRecoveryNative) close() error {
	var failure error
	if native.snapshot != nil {
		if err := native.snapshot.close(); err != nil {
			failure = errors.Join(failure, err)
		} else {
			native.snapshot = nil
		}
	}
	for _, witness := range native.processes {
		if witness.process != nil {
			if err := witness.process.Close(); err != nil {
				failure = errors.Join(failure, err)
			} else {
				witness.process = nil
			}
		}
	}
	if native.closeErr == nil {
		native.closeErr = failure
	}
	if failure == nil && native.closeErr == nil {
		native.closed = true
	}
	return errors.Join(native.closeErr, failure)
}

func (native *journalRecoveryNative) finish(ctx context.Context, owner *JournalRecovery) error {
	store := native.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if owner != native.owner || !native.retired || !native.closed || native.closeErr != nil || owner.durable == nil ||
		store.pending != nil || store.current.SHA256 != owner.durable.Selection.SHA256 {
		return errors.New("Windows journal recovery has no fully joined durable handover")
	}
	if err := native.verifyLocked(ctx); err != nil {
		return err
	}
	store.recovery = nil
	return nil
}

type journalRetirementWitness struct {
	recorded Controller
	process  *windowscontroller.Process
	retired  bool
}

func (witness *journalRetirementWitness) prove(ctx context.Context) error {
	process := witness.process
	if process == nil || process.PID() != witness.recorded.PID {
		return errors.New("Windows journal retirement lost its retained process handle")
	}
	started, err := process.StartTimeUTCTicks()
	if err != nil {
		return err
	}
	if started != witness.recorded.StartTimeUTCTicks {
		// A new creation under this PID cannot revive the recorded process.
		// Retain this query-only reference through adoption; never signal it.
		witness.retired = true
		return ctx.Err()
	}
	identity, err := process.Identity()
	if err != nil || !identity.Primary || identity.SID != witness.recorded.SID ||
		identity.AuthenticationID != witness.recorded.AuthenticationID || identity.SessionID != witness.recorded.SessionID {
		return errors.Join(err, errors.New("Windows journal retirement changed its recorded primary process token"))
	}
	if process.Alive() == nil {
		return errors.New("Windows journal recovery still has a live recorded controller or engine")
	}
	// Alive's error alone cannot prove exit. Wait must observe the retained
	// kernel object's signalled state; access/handle/cancellation errors fail.
	if _, err := process.Wait(ctx); err != nil {
		return err
	}
	witness.retired = true
	return ctx.Err()
}

type journalProcessSnapshot struct {
	handle   syscall.Handle
	pids     map[uint32]bool
	complete bool
	closeErr error
}

// Toolhelp supplies a stable native process list. No failed OpenProcess call
// is treated as absence: a missing PID must be absent from this fully read
// snapshot. The handle remains owned on enumeration or close failure.
// https://learn.microsoft.com/windows/win32/toolhelp/snapshots-of-the-system
func captureJournalProcessSnapshot(ctx context.Context) (*journalProcessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	snapshot := &journalProcessSnapshot{handle: handle, pids: make(map[uint32]bool)}
	entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
	err = syscall.Process32First(handle, &entry)
	for count := 0; err == nil; count++ {
		if err := ctx.Err(); err != nil {
			return snapshot, err
		}
		if count >= 65536 || snapshot.pids[entry.ProcessID] {
			return snapshot, errors.New("Windows journal process snapshot is unbounded or repeats an identity")
		}
		snapshot.pids[entry.ProcessID] = true
		entry.Size = uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))
		err = syscall.Process32Next(handle, &entry)
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) || !snapshot.pids[uint32(os.Getpid())] {
		return snapshot, errors.Join(err, errors.New("Windows journal process snapshot did not reach its complete native end"))
	}
	snapshot.complete = true
	return snapshot, ctx.Err()
}

func (snapshot *journalProcessSnapshot) close() error {
	if snapshot == nil || snapshot.handle == 0 {
		return nil
	}
	if snapshot.closeErr != nil {
		return snapshot.closeErr
	}
	if err := syscall.CloseHandle(snapshot.handle); err != nil {
		snapshot.closeErr = err
		return err
	}
	snapshot.handle = 0
	return nil
}
