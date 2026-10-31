//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"syscall"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

const desktopLinuxNodeJournalDirectory = "router-vpn-client.node-journal-v1"
const desktopLinuxNodeJournalHeader = "files.json"
const desktopLinuxNodeJournalLock = "journal.lock"

var desktopLinuxNodeJournalSlots = [2]string{"slot-0.json", "slot-1.json"}

type desktopLinuxNodeJournalFile struct {
	file     *os.File
	identity linuxprotection.NativeObject
	name     string
}

type desktopLinuxNodeJournalAppend struct {
	record linuxprotection.JournalRecord
	body   []byte
	digest string
	slot   int
}

// The journal owns only descriptors opened relative to the actual retained
// installation anchor. It is registered with that parent before construction
// can fail, so parent teardown joins even an incompletely opened journal.
// It does not reconstruct a parent from a header or adopt decoded nft state.
type desktopLinuxNodeJournal struct {
	parent                        *desktopLinuxNodeParentCapture
	ctx                           context.Context
	cancel                        context.CancelFunc
	gate                          chan struct{}
	anchor, root                  *os.Root
	directory                     *os.File
	rootIdentity                  linuxprotection.NativeObject
	headerFile, lock              *desktopLinuxNodeJournalFile
	slots                         [2]*desktopLinuxNodeJournalFile
	header                        linuxprotection.JournalHeader
	headerBytes, lockBytes        []byte
	current                       linuxprotection.JournalSelection
	currentBytes                  []byte
	pending                       *desktopLinuxNodeJournalAppend
	initialized, closed, released bool
	closeErr                      error
}

func newDesktopLinuxNodeJournal(ctx context.Context, parent *desktopLinuxNodeParentCapture) (*desktopLinuxNodeJournal, error) {
	if ctx == nil || ctx.Err() != nil || parent == nil || parent.parent == nil || parent.Current(ctx) != nil {
		return nil, errors.New("Linux journal requires its original authenticated installed parent")
	}
	lifetime, cancel := context.WithCancel(parent.lifetime)
	j := &desktopLinuxNodeJournal{parent: parent, ctx: lifetime, cancel: cancel, gate: make(chan struct{}, 1)}
	p := parent.parent
	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case <-lifetime.Done():
		cancel()
		return nil, lifetime.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		cancel()
		return nil, err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[j] = struct{}{}
	// Keep the child's construction gate entered until the entire constructor
	// returns. A concurrent parent Close retains and waits for this same owner.
	anchor, ctxErr := p.installationAnchor.OpenRoot(".")
	j.anchor = anchor
	p.gate <- struct{}{}
	if ctxErr != nil {
		j.gate <- struct{}{}
		return j, ctxErr
	}
	return j, nil
}

// Creation never derives native absence from private storage. The matching
// nft reader checks before creation and after the durable initial checkpoint.
func createDesktopLinuxNodeJournal(ctx context.Context, parent *desktopLinuxNodeParentCapture) (_ *desktopLinuxNodeJournal, failure error) {
	j, err := newDesktopLinuxNodeJournal(ctx, parent)
	if err != nil {
		return j, err
	}
	defer func() { j.gate <- struct{}{} }()
	ctx, stop := j.operation(ctx)
	defer stop()
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return j, err
	}
	if err := j.parent.Current(ctx); err != nil {
		return j, err
	}
	if err := j.anchor.Mkdir(desktopLinuxNodeJournalDirectory, 0700); err != nil {
		return j, err
	}
	if err := j.openRoot(); err != nil {
		return j, err
	}
	if err := j.verifyInventory(false); err != nil {
		return j, err
	}
	j.lock, err = j.openFile(desktopLinuxNodeJournalLock, true)
	if err != nil {
		return j, err
	}
	if err := j.lockExclusive(); err != nil {
		return j, err
	}
	j.headerFile, err = j.openFile(desktopLinuxNodeJournalHeader, true)
	if err != nil {
		return j, err
	}
	for index, name := range desktopLinuxNodeJournalSlots {
		j.slots[index], err = j.openFile(name, true)
		if err != nil {
			return j, err
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return j, err
	}
	j.header = linuxprotection.JournalHeader{Schema: 1, Kind: "routervpn-owned-nft-journal-files", JournalID: hex.EncodeToString(nonce[:]),
		Creator: parent.record, Root: j.rootIdentity, Header: j.headerFile.identity, Lock: j.lock.identity,
		Slots: [2]linuxprotection.NativeObject{j.slots[0].identity, j.slots[1].identity}}
	j.headerBytes, err = linuxprotection.CanonicalJournalHeader(j.header)
	if err != nil {
		return j, err
	}
	j.lockBytes, err = linuxprotection.JournalLockBytes(j.header.JournalID)
	if err != nil {
		return j, err
	}
	initial := linuxprotection.JournalRecord{Schema: linuxprotection.JournalRecordSchema, Kind: linuxprotection.JournalRecordKind,
		JournalID: j.header.JournalID, Sequence: 1, Controller: parent.record, Phase: "settled"}
	body, err := linuxprotection.CanonicalJournalRecord(initial)
	if err != nil {
		return j, err
	}
	for _, write := range []struct {
		file *desktopLinuxNodeJournalFile
		body []byte
	}{
		{j.lock, j.lockBytes}, {j.slots[0], body}, {j.slots[1], nil}, {j.headerFile, j.headerBytes},
	} {
		if err := j.checkParent(ctx); err != nil {
			return j, err
		}
		if err := j.writeFile(write.file, write.body); err != nil {
			return j, err
		}
	}
	if err := j.directory.Sync(); err != nil {
		return j, err
	}
	// The new directory entry itself belongs to the stable /opt anchor, not
	// the package directory which an installer later copies and replaces.
	anchorDirectory, err := j.anchor.Open(".")
	if err != nil {
		return j, err
	}
	if err := errors.Join(anchorDirectory.Sync(), anchorDirectory.Close()); err != nil {
		return j, err
	}
	j.initialized = true
	if err := j.verifyObjects(); err != nil {
		return j, err
	}
	j.current, j.currentBytes, err = j.readSelection()
	if err != nil || j.current.Incomplete || j.current.Record.Sequence != 1 {
		return j, errors.Join(err, errors.New("Linux journal did not read back its exact initial durable state"))
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return j, err
	}
	return j, j.checkParent(ctx)
}

// Open captures existing comparison files under the new actual parent. It
// grants no process/native recovery: ordinary Append still requires the exact
// creator in the selected record, including its original generation and boot.
func openDesktopLinuxNodeJournal(ctx context.Context, parent *desktopLinuxNodeParentCapture) (*desktopLinuxNodeJournal, error) {
	j, err := newDesktopLinuxNodeJournal(ctx, parent)
	if err != nil {
		return j, err
	}
	defer func() { j.gate <- struct{}{} }()
	ctx, stop := j.operation(ctx)
	defer stop()
	if err := j.openRoot(); err != nil {
		return j, err
	}
	if err := j.verifyInventory(true); err != nil {
		return j, err
	}
	j.lock, err = j.openFile(desktopLinuxNodeJournalLock, false)
	if err != nil {
		return j, err
	}
	if err := j.lockExclusive(); err != nil {
		return j, err
	}
	j.headerFile, err = j.openFile(desktopLinuxNodeJournalHeader, false)
	if err != nil {
		return j, err
	}
	for index, name := range desktopLinuxNodeJournalSlots {
		j.slots[index], err = j.openFile(name, false)
		if err != nil {
			return j, err
		}
	}
	j.headerBytes, err = j.readFile(j.headerFile, linuxprotection.JournalHeaderLimit)
	if err != nil {
		return j, err
	}
	j.header, err = linuxprotection.ParseJournalHeader(j.headerBytes)
	if err != nil {
		return j, err
	}
	j.lockBytes, err = linuxprotection.JournalLockBytes(j.header.JournalID)
	if err != nil {
		return j, err
	}
	j.initialized = true
	if err := j.verifyObjects(); err != nil {
		return j, err
	}
	j.current, j.currentBytes, err = j.readSelection()
	if err != nil {
		return j, err
	}
	return j, j.checkParent(ctx)
}

func (j *desktopLinuxNodeJournal) checkParent(ctx context.Context) error {
	if j == nil || ctx == nil || ctx.Err() != nil || j.ctx == nil || j.ctx.Err() != nil || j.closed || j.parent == nil {
		return errors.New("Linux journal lost its live captured parent operation")
	}
	return j.parent.Current(ctx)
}

func (j *desktopLinuxNodeJournal) operation(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(j.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (j *desktopLinuxNodeJournal) openRoot() error {
	entry, err := j.anchor.Lstat(desktopLinuxNodeJournalDirectory)
	if err != nil || !entry.IsDir() || !ownedDesktopInfo(entry) || entry.Mode().Perm() != 0700 {
		return errors.Join(err, errors.New("Linux journal root is not its protected sibling directory"))
	}
	j.root, err = j.anchor.OpenRoot(desktopLinuxNodeJournalDirectory)
	if err != nil {
		return err
	}
	info, err := j.root.Stat(".")
	if err != nil || !os.SameFile(info, entry) {
		return errors.Join(err, errors.New("Linux journal directory changed while retaining it"))
	}
	j.rootIdentity, err = desktopLinuxNodeObjectOf(info)
	if err != nil {
		return err
	}
	j.directory, err = j.root.Open(".")
	return err
}

func (j *desktopLinuxNodeJournal) openFile(name string, create bool) (*desktopLinuxNodeJournalFile, error) {
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := j.root.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	owned := &desktopLinuxNodeJournalFile{file: file, name: name}
	info, err := file.Stat()
	if err == nil {
		owned.identity, err = desktopLinuxNodeObjectOf(info)
	}
	if err != nil {
		return owned, err
	}
	return owned, j.verifyFile(owned)
}

func (j *desktopLinuxNodeJournal) verifyFile(owned *desktopLinuxNodeJournalFile) error {
	if owned == nil || owned.file == nil {
		return errors.New("Linux journal lost a retained file descriptor")
	}
	info, err := owned.file.Stat()
	if err != nil {
		return err
	}
	identity, identityErr := desktopLinuxNodeObjectOf(info)
	native, ok := info.Sys().(*syscall.Stat_t)
	entry, pathErr := j.root.Lstat(owned.name)
	if identityErr != nil || pathErr != nil || !ok || native.Nlink != 1 || !info.Mode().IsRegular() || !ownedDesktopInfo(info) ||
		info.Mode().Perm() != 0600 || identity != owned.identity || !entry.Mode().IsRegular() || !os.SameFile(info, entry) {
		return errors.Join(identityErr, pathErr, errors.New("Linux journal file changed its private retained inode"))
	}
	return nil
}

func (j *desktopLinuxNodeJournal) lockExclusive() error {
	if err := j.verifyFile(j.lock); err != nil {
		return err
	}
	raw, err := j.lock.file.SyscallConn()
	if err != nil {
		return err
	}
	var locked error
	err = raw.Control(func(fd uintptr) { locked = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) })
	return errors.Join(err, locked)
}

func (j *desktopLinuxNodeJournal) verifyInventory(complete bool) error {
	if j.directory == nil {
		return errors.New("Linux journal lost its retained directory inventory")
	}
	// A fresh relative descriptor reads the same already-retained directory;
	// it never resolves a later absolute install or journal pathname.
	directory, err := j.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(6)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	want := []string{}
	if complete {
		want = []string{desktopLinuxNodeJournalHeader, desktopLinuxNodeJournalLock, desktopLinuxNodeJournalSlots[0], desktopLinuxNodeJournalSlots[1]}
	}
	sort.Strings(names)
	sort.Strings(want)
	if len(names) != len(want) {
		return errors.New("Linux journal contains incomplete or unrelated file ownership")
	}
	for index, name := range want {
		if names[index] != name {
			return errors.New("Linux journal contains a foreign or legacy file")
		}
	}
	return nil
}

func (j *desktopLinuxNodeJournal) verifyObjects() error {
	if !j.initialized || j.closed || j.anchor == nil || j.root == nil || j.directory == nil || j.header.Validate() != nil {
		return errors.New("Linux journal has no complete retained native storage owner")
	}
	anchor, err := j.anchor.Stat(".")
	anchorID, identityErr := desktopLinuxNodeObjectOf(anchor)
	if err != nil || identityErr != nil || anchorID != j.parent.record.InstallationAnchor || anchorID != j.header.Creator.InstallationAnchor ||
		j.header.Creator.CallerUID != j.parent.record.CallerUID || j.header.Creator.InstallLock != j.parent.record.InstallLock ||
		j.header.Creator.ProcessLock != j.parent.record.ProcessLock {
		return errors.Join(err, identityErr, errors.New("Linux journal lost its original anchor, user or stable controller locks"))
	}
	root, rootErr := j.root.Stat(".")
	rootID, rootIdentityErr := desktopLinuxNodeObjectOf(root)
	path, pathErr := j.anchor.Lstat(desktopLinuxNodeJournalDirectory)
	directory, directoryErr := j.directory.Stat()
	if rootErr != nil || rootIdentityErr != nil || pathErr != nil || directoryErr != nil || rootID != j.rootIdentity || rootID != j.header.Root ||
		!root.IsDir() || !ownedDesktopInfo(root) || root.Mode().Perm() != 0700 || !path.IsDir() || !os.SameFile(root, path) || !os.SameFile(root, directory) {
		return errors.Join(rootErr, rootIdentityErr, pathErr, directoryErr, errors.New("Linux journal sibling directory was replaced"))
	}
	for _, owned := range []*desktopLinuxNodeJournalFile{j.headerFile, j.lock, j.slots[0], j.slots[1]} {
		if err := j.verifyFile(owned); err != nil {
			return err
		}
	}
	if j.headerFile.identity != j.header.Header || j.lock.identity != j.header.Lock || j.slots[0].identity != j.header.Slots[0] || j.slots[1].identity != j.header.Slots[1] {
		return errors.New("Linux journal files differ from their immutable native identities")
	}
	if err := j.verifyInventory(true); err != nil {
		return err
	}
	for _, original := range []struct {
		file *desktopLinuxNodeJournalFile
		body []byte
	}{{j.headerFile, j.headerBytes}, {j.lock, j.lockBytes}} {
		body, err := j.readFile(original.file, linuxprotection.JournalHeaderLimit)
		if err != nil || !bytes.Equal(body, original.body) {
			return errors.Join(err, errors.New("Linux journal immutable identity bytes changed"))
		}
	}
	return nil
}

func (j *desktopLinuxNodeJournal) readFile(file *desktopLinuxNodeJournalFile, limit int) ([]byte, error) {
	if err := j.verifyFile(file); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.NewSectionReader(file.file, 0, int64(limit+1)))
	if err != nil || len(body) > limit {
		return nil, errors.Join(err, errors.New("Linux journal file exceeds its bounded native read"))
	}
	return body, j.verifyFile(file)
}

func (j *desktopLinuxNodeJournal) writeFile(file *desktopLinuxNodeJournalFile, body []byte) error {
	if len(body) > linuxprotection.JournalRecordLimit {
		return errors.New("Linux journal write exceeds its fixed bound")
	}
	if err := j.verifyFile(file); err != nil {
		return err
	}
	for written := 0; written < len(body); {
		n, err := file.file.WriteAt(body[written:], int64(written))
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		written += n
	}
	if err := file.file.Truncate(int64(len(body))); err != nil {
		return err
	}
	if err := file.file.Sync(); err != nil {
		return err
	}
	actual, err := j.readFile(file, linuxprotection.JournalRecordLimit)
	if err != nil || !bytes.Equal(actual, body) {
		return errors.Join(err, errors.New("Linux journal did not read back its exact flushed bytes"))
	}
	return nil
}

func (j *desktopLinuxNodeJournal) readSelection() (linuxprotection.JournalSelection, []byte, error) {
	var bodies [2][]byte
	for index, file := range j.slots {
		body, err := j.readFile(file, linuxprotection.JournalRecordLimit)
		if err != nil {
			return linuxprotection.JournalSelection{}, nil, err
		}
		bodies[index] = body
	}
	selection, err := linuxprotection.SelectJournalRecord(j.header.JournalID, bodies)
	if err != nil {
		return linuxprotection.JournalSelection{}, nil, err
	}
	return selection, append([]byte(nil), bodies[selection.Slot]...), nil
}

func (j *desktopLinuxNodeJournal) enter(ctx context.Context) error {
	if j == nil || ctx == nil || j.ctx == nil || j.gate == nil {
		return errors.New("Linux journal operation has no captured native owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-j.ctx.Done():
		return j.ctx.Err()
	case <-j.gate:
	}
	return nil
}

func (j *desktopLinuxNodeJournal) Snapshot(ctx context.Context) (linuxprotection.JournalSelection, error) {
	if err := j.enter(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	defer func() { j.gate <- struct{}{} }()
	if err := j.checkParent(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	if j.pending != nil {
		return linuxprotection.JournalSelection{}, errors.New("Linux journal still owns an unacknowledged durable append")
	}
	if err := j.verifyObjects(); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	selection, body, err := j.readSelection()
	if err != nil || !bytes.Equal(body, j.currentBytes) || selection.SHA256 != j.current.SHA256 || selection.Slot != j.current.Slot || selection.Incomplete != j.current.Incomplete {
		return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("Linux journal changed without its captured durable transaction"))
	}
	return selection, j.checkParent(ctx)
}

// Append changes comparison data only. Native mutation/admission must retain
// its own real operation and callback barrier. A cancelled ACK cannot erase a
// completed durable intent: the returned selection identifies what was saved.
func (j *desktopLinuxNodeJournal) Append(ctx context.Context, previous string, next linuxprotection.JournalRecord) (linuxprotection.JournalSelection, error) {
	if err := j.enter(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	defer func() { j.gate <- struct{}{} }()
	if err := j.checkParent(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	next = linuxprotection.CloneRecord(next)
	body, err := linuxprotection.CanonicalJournalRecord(next)
	if err != nil || j.current.Incomplete || next.Controller != j.parent.record || previous != j.current.SHA256 ||
		linuxprotection.CheckJournalTransition(j.current.Record, next) != nil {
		return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("Linux journal append changed its exact creator, prior digest or complete state"))
	}
	if err := j.verifyObjects(); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	if j.pending == nil {
		selection, actual, err := j.readSelection()
		if err != nil || selection.Incomplete || selection.SHA256 != previous || !bytes.Equal(actual, j.currentBytes) {
			return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("Linux journal append lost its preceding complete slot"))
		}
		digest, err := linuxprotection.JournalRecordSHA256(body)
		if err != nil {
			return linuxprotection.JournalSelection{}, err
		}
		j.pending = &desktopLinuxNodeJournalAppend{record: next, body: append([]byte(nil), body...), digest: digest, slot: 1 - j.current.Slot}
	} else if !bytes.Equal(j.pending.body, body) {
		return linuxprotection.JournalSelection{}, errors.New("Linux journal cannot replace its exact pending durable append")
	}
	old, err := j.readFile(j.slots[j.current.Slot], linuxprotection.JournalRecordLimit)
	if err != nil || !bytes.Equal(old, j.currentBytes) {
		return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("Linux pending append lost its last acknowledged slot"))
	}
	if err := j.checkParent(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	if err := j.writeFile(j.slots[j.pending.slot], j.pending.body); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	if err := j.verifyObjects(); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	selection, actual, err := j.readSelection()
	if err != nil || selection.Incomplete || selection.Slot != j.pending.slot || selection.SHA256 != j.pending.digest || !bytes.Equal(actual, j.pending.body) {
		return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("Linux journal append did not prove its complete durable successor"))
	}
	j.current, j.currentBytes = selection, append([]byte(nil), actual...)
	j.pending = nil
	selection.Record = linuxprotection.CloneRecord(selection.Record)
	return selection, j.checkParent(ctx)
}

// Close joins before releasing the stable journal lock. It never removes the
// directory or rewrites an ambiguous pending slot; restart must prove recovery.
// A real close error is sticky and cannot become a successful public Stop.
func (j *desktopLinuxNodeJournal) Close(ctx context.Context) error {
	if j == nil {
		return nil
	}
	if ctx == nil || j.cancel == nil || j.gate == nil || j.parent == nil || j.parent.parent == nil {
		return errors.New("Linux journal close requires its bounded retained owner")
	}
	j.cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-j.gate:
	}
	defer func() { j.gate <- struct{}{} }()
	if !j.closed {
		for _, file := range []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile} {
			if file != nil && file.file != nil {
				if err := file.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					j.closeErr = errors.Join(j.closeErr, err)
					return err
				}
				file.file = nil
			}
		}
		if j.closeErr != nil {
			return j.closeErr
		}
		if j.directory != nil {
			if err := j.directory.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				j.closeErr = err
				return err
			}
			j.directory = nil
		}
		if j.root != nil {
			if err := j.root.Close(); err != nil {
				j.closeErr = err
				return err
			}
			j.root = nil
		}
		if j.anchor != nil {
			if err := j.anchor.Close(); err != nil {
				j.closeErr = err
				return err
			}
			j.anchor = nil
		}
		if j.lock != nil && j.lock.file != nil {
			if err := j.lock.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				j.closeErr = err
				return err
			}
			j.lock.file = nil
		}
		j.closed = true
	}
	if j.closeErr != nil {
		return j.closeErr
	}
	if !j.released {
		if err := j.parent.parent.releaseDependent(ctx, j); err != nil {
			return err
		}
		j.released = true
	}
	return nil
}
