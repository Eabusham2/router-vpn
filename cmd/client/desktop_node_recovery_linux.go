//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// Empty recovery is a new, authenticated controller's ownership of these
// exact old files after native protection is independently proved absent.
// It accepts a settled empty checkpoint or an already-requested On-connect
// release whose joined controller, engine and guardian are now absent. It
// never reconstructs a native baseline, adopts an engine,
// changes a saved policy, or signals a process named by a journal. The session
// gate serializes every retry; its journalErr blocks competing admission until
// the captured deletion and every original descriptor close have completed.
type desktopLinuxEmptyJournalRecovery struct {
	session    *desktopLinuxNodeSession
	journal    *desktopLinuxNodeJournal
	original   linuxprotection.ParentRecord
	checkpoint linuxprotection.JournalSelection
	openErr    error
	ready      bool
}

func (a *app) initializeDesktopNodeRecovery() error {
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil {
		return nil // Unprivileged utilities have no installed native authority.
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	p := parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		return err
	}
	_, statErr := p.installationAnchor.Lstat(desktopLinuxNodeJournalDirectory)
	p.gate <- struct{}{}
	if errors.Is(statErr, os.ErrNotExist) {
		// Missing saved files do not prove native policy or tunnel absence.
		// Existing legacy startup keeps its separate protection owner.
		return parent.Current(ctx)
	}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	if err := session.enter(ctx); err != nil {
		return err
	}
	defer func() { session.gate <- struct{}{} }()
	if err := session.currentLocked(ctx); err != nil {
		return err
	}
	if err := session.beginEmptyRecoveryLocked(ctx); err != nil {
		return errors.Join(statErr, err)
	}
	if statErr != nil {
		// An uncertain initial lookup cannot become an implicit empty state.
		// Keep the actual captured open for teardown and refuse admission.
		session.emptyRecovery.openErr = statErr
		return statErr
	}
	return session.finishEmptyRecoveryLocked(ctx, false)
}

// The retained session owns even a partial open. A retry cannot discard its
// lock or use a newly discovered path in place of the original descriptor.
func (s *desktopLinuxNodeSession) beginEmptyRecoveryLocked(ctx context.Context) error {
	if err := s.currentLocked(ctx); err != nil {
		return err
	}
	if s.active != nil || s.predecessor != nil || s.off != nil || s.journal != nil || s.journalErr != nil || s.emptyRecovery != nil {
		return errors.New("Linux startup recovery cannot replace an existing captured session")
	}
	recovery := &desktopLinuxEmptyJournalRecovery{session: s}
	s.emptyRecovery = recovery
	s.journalErr = errors.New("Linux startup must finish its captured empty checkpoint recovery")
	recovery.journal, recovery.openErr = openDesktopLinuxNodeJournal(ctx, s.parent)
	if recovery.journal != nil {
		recovery.original = recovery.journal.header.Creator
		recovery.checkpoint = recovery.journal.current
		recovery.checkpoint.Record = linuxprotection.CloneRecord(recovery.journal.current.Record)
	}
	return recovery.openErr
}

// A subsequent protected Connect may finish only the same accepted recovery.
// It cannot reopen another journal after a partial or ambiguous original open.
func (a *app) resumeDesktopLinuxEmptyRecovery(ctx context.Context) error {
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil
	}
	p, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || p == nil {
		return errors.New("Linux empty recovery belongs to another native controller")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	session := p.session
	p.gate <- struct{}{}
	if session == nil {
		return nil
	}
	if err := session.enter(ctx); err != nil {
		return err
	}
	defer func() { session.gate <- struct{}{} }()
	if session.emptyRecovery == nil || session.emptyRecovery.ready {
		return nil
	}
	return session.finishEmptyRecoveryLocked(ctx, false)
}

func checkDesktopLinuxEmptyRecoveryCreator(original, current linuxprotection.ParentRecord) error {
	if original.Validate() != nil || current.Validate() != nil || original.Generation == current.Generation ||
		original.ProcessID == current.ProcessID || original.ProcProcessID == current.ProcProcessID || original.StartTicks > current.StartTicks ||
		original.BootID != current.BootID || original.CallerUID != current.CallerUID ||
		original.InstallationAnchor != current.InstallationAnchor || original.InstallLock != current.InstallLock || original.ProcessLock != current.ProcessLock ||
		original.NetworkNamespace != current.NetworkNamespace || original.PIDNamespace != current.PIDNamespace {
		return errors.New("Linux empty recovery changed its original creator, stable locks, caller, boot or namespaces")
	}
	return nil
}

// This comparison identifies the exact processes which must be absent; it
// creates no process or rule authority. A complete release intent is written
// only after the original source and engine joined, and requests an empty
// result. A crash after its native removal but before the final journal write
// may therefore finish the same empty-file cleanup after independent proof.
// Always, saved Off, prepared successors and partial records remain retained.
func checkDesktopLinuxEmptyRecoveryCheckpoint(original, current linuxprotection.ParentRecord, checkpoint linuxprotection.JournalSelection) ([]int, error) {
	r := checkpoint.Record
	if checkDesktopLinuxEmptyRecoveryCreator(original, current) != nil || checkpoint.Incomplete ||
		r.Validate() != nil || r.Controller != original {
		return nil, errors.New("Linux recovery requires its complete original controller checkpoint")
	}
	pids := []int{original.ProcessID}
	if r.Phase == "settled" && r.Intent == nil && reflect.DeepEqual(r.Committed, linuxprotection.JournalState{}) {
		return pids, nil
	}
	target, intent := r.Committed.Target, r.Intent
	if r.Phase != "intent" || target == nil || r.Committed.Engine != nil || target.Policy != "on-connect" ||
		target.Native.TableName == "" || intent == nil || intent.Action != "release" || intent.Preparation != nil ||
		intent.RequestID != target.Native.Capture.SessionID || intent.ProfileID != r.Committed.ProfileID ||
		intent.ProfileRevision != r.Committed.ProfileRevision || intent.ResultProfileRevision != r.Committed.ProfileRevision ||
		!reflect.DeepEqual(intent.Candidate, linuxprotection.JournalState{}) {
		return nil, errors.New("Linux recovery preserves nonempty, incomplete or unresolved original protection records")
	}
	guardian := target.Guardian
	if guardian.BootID != original.BootID || guardian.NetworkNamespace != original.NetworkNamespace || guardian.PIDNamespace != original.PIDNamespace ||
		guardian.StartTicks < original.StartTicks || guardian.StartTicks > current.StartTicks ||
		guardian.ProcessID == original.ProcessID || guardian.ProcessID == current.ProcessID ||
		guardian.ProcProcessID == original.ProcProcessID || guardian.ProcProcessID == current.ProcProcessID ||
		guardian.ParentProcessID == original.ProcessID || guardian.ParentProcessID == current.ProcessID {
		return nil, errors.New("Linux release recovery lost its recorded same-boot engine and guardian identities")
	}
	return append(pids, guardian.ParentProcessID, guardian.ProcessID), nil
}

// pidfd_open is used only as an independent *absence* observation. A live,
// zombie or reused PID is rejected; its returned descriptor is closed without
// signaling, waiting, adopting or comparing it into authority. ESRCH is the
// sole successful result. The original authenticated parent brackets the read
// and fixes the calling thread's PID namespace, boot and process lifetime.
func (r *desktopLinuxEmptyJournalRecovery) observeExitedProcesses(ctx context.Context, retiring bool) error {
	if err := r.current(ctx, retiring); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("Linux empty recovery requires its proved native pidfd ABI")
	}
	pids, err := checkDesktopLinuxEmptyRecoveryCheckpoint(r.original, r.session.parent.record, r.checkpoint)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		if err := r.current(ctx, retiring); err != nil {
			return err
		}
		descriptor, _, errno := syscall.Syscall(434, uintptr(pid), 0, 0) // Linux __NR_pidfd_open on x64/ARM64.
		if errno == 0 {
			file := os.NewFile(descriptor, "linux-empty-journal-live-process-observation")
			if file == nil {
				return errors.New("Linux empty recovery lost its rejected live-process descriptor")
			}
			return errors.Join(errors.New("Linux recovery cannot prove every recorded controller, engine and guardian has exited"), file.Close())
		}
		if errno != syscall.ESRCH {
			return os.NewSyscallError("pidfd_open original journal process", errno)
		}
	}
	return r.current(ctx, retiring)
}

func (r *desktopLinuxEmptyJournalRecovery) current(ctx context.Context, retiring bool) error {
	if r == nil || r.session == nil || r.journal == nil || r.openErr != nil || ctx == nil || ctx.Err() != nil {
		return errors.New("Linux empty recovery lost its complete original open and bounded owner")
	}
	s, j := r.session, r.journal
	if s.emptyRecovery != r || s.closed || s.released || s.active != nil || s.predecessor != nil || s.off != nil || s.journal != nil ||
		!sameDesktopLinuxParentCapture(s.parent, j.parent) || r.original != j.header.Creator ||
		checkDesktopLinuxEmptyRecoveryCreator(r.original, s.parent.record) != nil || !reflect.DeepEqual(r.checkpoint, j.current) {
		return errors.New("Linux empty recovery cannot replace its captured session, files or controller")
	}
	var err error
	if retiring {
		err = s.parent.retirementCurrent(ctx)
	} else {
		err = s.parent.Current(ctx)
	}
	if err != nil {
		return err
	}
	a, p := s.parent.app, s.parent.parent
	a.mu.Lock()
	_, duplicate := desktopNodeOwners.Load(a)
	unused := !duplicate && a.cmd == nil && !a.state.Connected && (a.state.Mode == "" || a.state.Mode == "off")
	a.mu.Unlock()
	if !unused {
		return errors.New("Linux empty recovery cannot retire a running or replacement application path")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if p.session != s || p.stopping && !retiring {
		return errors.New("Linux empty recovery lost its exact current session registration")
	}
	if _, owned := p.dependents[s]; !owned {
		return errors.New("Linux empty recovery lost its original session owner")
	}
	if _, owned := p.dependents[j]; owned == j.released {
		return errors.New("Linux empty recovery changed its original journal registration")
	}
	for dependent := range p.dependents {
		if dependent != s && dependent != j {
			return errors.New("Linux empty recovery cannot inherit another live native dependent")
		}
	}
	return ctx.Err()
}

func (r *desktopLinuxEmptyJournalRecovery) removalCurrent(ctx context.Context, retiring bool) error {
	if err := r.observeExitedProcesses(ctx, retiring); err != nil {
		return err
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	return r.current(ctx, retiring)
}

// The caller owns the session gate from the first accepted open through each
// retry. Only the two complete original checkpoints described above enter
// deletion. An error retains this capability and journalErr in the same session.
func (s *desktopLinuxNodeSession) finishEmptyRecoveryLocked(ctx context.Context, retiring bool) (failure error) {
	r := s.emptyRecovery
	if r == nil || r.ready {
		return nil
	}
	defer func() {
		if failure != nil {
			s.journalErr = errors.Join(errors.New("Linux empty checkpoint recovery remains pending"), failure)
		}
	}()
	if r.openErr != nil {
		return r.openErr
	}
	if err := r.current(ctx, retiring); err != nil {
		return err
	}
	j := r.journal
	if j.removal == nil || !j.removal.complete {
		if j.removal == nil {
			if err := j.enter(ctx); err != nil {
				return err
			}
		} else {
			// A rejected Close permanently cancels ordinary journal work.
			// Its accepted removal still retains these exact descriptors,
			// parent and progress. Like terminal cleanup, join that original
			// gate without reviving the journal's mutation lifetime.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-j.gate:
			}
		}
		err := r.removeLocked(ctx, retiring)
		j.gate <- struct{}{}
		if err != nil {
			return err
		}
	}
	if err := r.removalCurrent(ctx, retiring); err != nil {
		return err
	}
	if err := j.Close(ctx); err != nil {
		return err
	}
	if err := r.removalCurrent(ctx, retiring); err != nil {
		return err
	}
	p := s.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	_, err := p.installationAnchor.Lstat(desktopLinuxNodeJournalDirectory)
	p.gate <- struct{}{}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("Linux empty recovery preserves a replacement journal directory"))
	}
	if err := r.current(ctx, retiring); err != nil {
		return err
	}
	r.ready = true
	s.journalErr = nil
	return nil
}

func (r *desktopLinuxEmptyJournalRecovery) removeLocked(ctx context.Context, retiring bool) error {
	j := r.journal
	if j.removal == nil {
		if !j.initialized || j.closed || j.released || j.ctx.Err() != nil || j.pending != nil {
			return errors.New("Linux recovery requires its original complete and unused journal")
		}
		if _, err := checkDesktopLinuxEmptyRecoveryCheckpoint(r.original, r.session.parent.record, r.checkpoint); err != nil {
			return err
		}
		if err := j.verifyObjects(); err != nil {
			return err
		}
		selection, body, err := j.readSelection()
		if err != nil || selection.Incomplete || selection.SHA256 != j.current.SHA256 || selection.Slot != j.current.Slot || !bytes.Equal(body, j.currentBytes) {
			return errors.Join(err, errors.New("Linux empty recovery changed its captured complete checkpoint"))
		}
		if err := r.removalCurrent(ctx, retiring); err != nil {
			return err
		}
		removal := &desktopLinuxNodeJournalRemoval{recovery: r}
		for index, file := range []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile, j.lock} {
			body, err := j.readFile(file, linuxprotection.JournalRecordLimit)
			if err != nil {
				return err
			}
			removal.files[index] = desktopLinuxNodeJournalRemovalFile{owner: file, body: body}
		}
		j.removal = removal
	}
	if j.removal.recovery != r {
		return errors.New("Linux empty recovery cannot replay another accepted removal")
	}
	return j.finishEmptyCheckpointRemoval(ctx, r, retiring)
}
