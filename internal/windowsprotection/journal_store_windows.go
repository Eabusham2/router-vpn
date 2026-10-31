//go:build windows

package windowsprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

const (
	journalDirectoryName = "RouterVPN-Owned-WFP-Journal-v1"
	journalHeaderName    = "files.json"
	journalLockName      = "journal.lock"
)

var journalSlotNames = [2]string{"slot-0.json", "slot-1.json"}

// ProtectionJournal retains an administrative, machine-derived directory and
// an exclusive stable file lock. The original desktop user and private Data
// directory are captured separately from the elevated controller identity.
// No caller-selected path, imported header or decoded target creates this owner.
//
// This store acknowledges durable comparison records only. Opening it does
// not adopt a previous process or grant native BFE recovery/removal authority.
// An ordinary Append cannot change the controller creation identity; process
// restart recovery needs a separate independently proved adoption operation.
type ProtectionJournal struct {
	mu              sync.Mutex
	api             *protectionNativeAPI
	self, desktop   *windowscontroller.Process
	identity        windowscontroller.TokenIdentity
	controller      Controller
	desktopCapture  Controller
	desktopIdentity windowscontroller.TokenIdentity
	data            *protectionObject
	dataPins        []*protectionObject
	pins            []*protectionObject
	root            *protectionObject
	file            *protectionObject
	lock            *protectionObject
	slots           [2]*protectionObject
	header          journalHeader
	headerBytes     []byte
	lockBytes       []byte
	current         JournalSelection
	currentBytes    []byte
	pending         *journalPendingAppend
	recovery        *JournalRecovery
	initialized     bool
	closed          bool
	closeErr        error
}

type journalPendingAppend struct {
	record JournalRecord
	body   []byte
	digest string
	slot   int
}

// CreateProtectionJournal begins only at independently proved initial BFE
// absence. The desktop process and Data directory must be the handles retained
// by the authenticated native controller, not values read from a request.
func CreateProtectionJournal(ctx context.Context, desktop *windowscontroller.Process, data *os.File) (*ProtectionJournal, error) {
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	return createProtectionJournal(ctx, paths.ProgramData, desktop, data, mobiletor.ReadDesktopWindowsProtectionExpectation)
}

// OpenProtectionJournal acquires and proves the existing protected files. Its
// snapshot remains comparison data: old controllers/engines and the exact BFE
// outcome must still be independently retired/proved before restart adoption.
func OpenProtectionJournal(ctx context.Context, desktop *windowscontroller.Process, data *os.File) (*ProtectionJournal, error) {
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	return openProtectionJournal(ctx, paths.ProgramData, desktop, data)
}

func journalProcessCapture(process *windowscontroller.Process) (Controller, windowscontroller.TokenIdentity, error) {
	if process == nil || process.PID() == 0 {
		return Controller{}, windowscontroller.TokenIdentity{}, errors.New("journal has no retained process identity")
	}
	if err := process.Alive(); err != nil {
		return Controller{}, windowscontroller.TokenIdentity{}, err
	}
	identity, err := process.Identity()
	if err != nil || !identity.Primary {
		return Controller{}, identity, errors.Join(err, errors.New("journal process has no actual primary token"))
	}
	started, err := process.StartTimeUTCTicks()
	if err != nil {
		return Controller{}, identity, err
	}
	capture := Controller{PID: process.PID(), StartTimeUTCTicks: started, SID: identity.SID,
		AuthenticationID: identity.AuthenticationID, SessionID: identity.SessionID}
	if err := capture.Validate(); err != nil {
		return Controller{}, identity, err
	}
	return capture, identity, process.Alive()
}

func journalIdentity(file *protectionObject) journalObjectIdentity {
	return journalObjectIdentity{VolumeSerial: file.identity.VolumeSerialNumber,
		FileIndex: uint64(file.identity.FileIndexHigh)<<32 | uint64(file.identity.FileIndexLow)}
}

func journalVolume(api *protectionNativeAPI, file *protectionObject) (string, error) {
	canonical, err := protectionFinalPath(api, file)
	if err != nil {
		return "", err
	}
	_, root, err := protectionLocalPath(canonical)
	if err != nil || len(root) != len(protectionVolumePrefix)+38 || !strings.EqualFold(root[:len(protectionVolumePrefix)], protectionVolumePrefix) {
		return "", errors.Join(err, errors.New("journal has no independently retained local volume"))
	}
	return strings.ToLower(root[len(protectionVolumePrefix) : len(protectionVolumePrefix)+36]), nil
}

// Retain through SyscallConn.Control so concurrent os.File.Close cannot cause
// a reused raw handle to be duplicated as the original private directory.
func journalRetainData(api *protectionNativeAPI, data *os.File) (*protectionObject, error) {
	if data == nil {
		return nil, errors.New("journal has no retained original Data directory")
	}
	raw, err := data.SyscallConn()
	if err != nil {
		return nil, err
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	var handle syscall.Handle
	var duplicateErr error
	if err := raw.Control(func(original uintptr) {
		duplicateErr = syscall.DuplicateHandle(current, syscall.Handle(original), current, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	}); err != nil {
		return nil, err
	}
	if duplicateErr != nil {
		return nil, duplicateErr
	}
	file := &protectionObject{handle: handle, directory: true}
	file.identity, err = protectionObjectIdentity(handle, true)
	if err == nil {
		file.path, err = protectionFinalPath(api, file)
	}
	return file, err
}

// machineDirectory and the initial read callback are private native-fixture
// boundaries. Production uses MachineDirectories and the real BFE reader.
func newProtectionJournal(ctx context.Context, machineDirectory string, desktop *windowscontroller.Process, data *os.File) (*ProtectionJournal, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("journal capture requires a live controller operation")
	}
	api, err := protectionNative()
	if err != nil {
		return nil, err
	}
	store := &ProtectionJournal{api: api}
	store.self, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return store, err
	}
	store.controller, store.identity, err = journalProcessCapture(store.self)
	if err != nil || !store.identity.Elevated || !store.identity.Administrator {
		return store, errors.Join(err, errors.New("journal storage requires the retained elevated controller"))
	}
	var originalIdentity windowscontroller.TokenIdentity
	store.desktopCapture, originalIdentity, err = journalProcessCapture(desktop)
	if err != nil || originalIdentity.SessionID != store.identity.SessionID {
		return store, errors.Join(err, errors.New("journal lost its original authenticated desktop session"))
	}
	store.desktop, err = windowscontroller.OpenProcess(store.desktopCapture.PID)
	if err != nil {
		return store, err
	}
	retained, identity, err := journalProcessCapture(store.desktop)
	if err != nil || retained != store.desktopCapture || identity != originalIdentity {
		return store, errors.Join(err, errors.New("journal desktop capture changed its retained creation identity"))
	}
	store.desktopIdentity = identity
	if err := desktop.Alive(); err != nil {
		return store, err
	}
	store.data, err = journalRetainData(api, data)
	if err != nil {
		return store, err
	}
	store.dataPins, _, err = pinProtectionDirectory(api, store.data.path)
	if err != nil || len(store.dataPins) == 0 || !sameProtectionObject(store.data.identity, store.dataPins[len(store.dataPins)-1].identity) {
		return store, errors.Join(err, errors.New("journal original Data directory changed while retaining ancestry"))
	}
	store.pins, _, err = pinProtectionDirectory(api, machineDirectory)
	if err != nil {
		return store, err
	}
	if err := store.verifyController(ctx); err != nil {
		return store, err
	}
	return store, nil
}

func createProtectionJournal(ctx context.Context, machineDirectory string, desktop *windowscontroller.Process, data *os.File,
	read func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error) (*ProtectionJournal, error) {
	store, err := newProtectionJournal(ctx, machineDirectory, desktop, data)
	if err != nil {
		return store, err
	}
	if read == nil {
		return store, errors.New("journal creation has no independent initial protection read")
	}
	if err := read(ctx, nil); err != nil {
		return store, err
	}
	machine := store.pins[len(store.pins)-1].path
	store.root, err = createProtectionDirectory(store.api, filepath.Join(machine, journalDirectoryName))
	if err != nil {
		return store, err
	}
	if err := store.verifyInventory(false); err != nil {
		return store, err
	}
	// This lock is deliberately stable. A crash releases its exclusive kernel
	// handle, not its pathname; reopening requires the immutable header's file ID.
	store.lock, err = createProtectionFile(store.api, filepath.Join(store.root.path, journalLockName), false)
	if err != nil {
		return store, err
	}
	store.file, err = createProtectionFile(store.api, filepath.Join(store.root.path, journalHeaderName), false)
	if err != nil {
		return store, err
	}
	for index, name := range journalSlotNames {
		store.slots[index], err = createProtectionFile(store.api, filepath.Join(store.root.path, name), false)
		if err != nil {
			return store, err
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return store, err
	}
	store.header = journalHeader{Schema: 1, Kind: "routervpn-owned-wfp-journal-files", JournalID: hex.EncodeToString(nonce[:]),
		DesktopSID: store.desktopCapture.SID, Data: journalIdentity(store.data), Root: journalIdentity(store.root), Header: journalIdentity(store.file),
		Lock: journalIdentity(store.lock), Slots: [2]journalObjectIdentity{journalIdentity(store.slots[0]), journalIdentity(store.slots[1])}}
	store.header.MachineVolume, err = journalVolume(store.api, store.root)
	if err != nil {
		return store, err
	}
	store.header.DataVolume, err = journalVolume(store.api, store.data)
	if err != nil {
		return store, err
	}
	store.headerBytes, err = canonicalJournalHeader(store.header)
	if err != nil {
		return store, err
	}
	initial := JournalRecord{Schema: JournalRecordSchema, Kind: JournalRecordKind, JournalID: store.header.JournalID,
		Sequence: 1, Controller: store.controller, Phase: "settled"}
	body, err := CanonicalJournalRecord(initial)
	if err != nil {
		return store, err
	}
	store.lockBytes = journalLockBytes(store.header.JournalID)
	for _, write := range []struct {
		file *protectionObject
		body []byte
	}{{store.lock, store.lockBytes}, {store.slots[0], body}, {store.slots[1], nil}, {store.file, store.headerBytes}} {
		if err := store.verifyController(ctx); err != nil {
			return store, err
		}
		if err := journalWriteRetained(write.file, write.body); err != nil {
			return store, err
		}
	}
	store.initialized = true
	if err := store.verifyObjects(); err != nil {
		return store, err
	}
	store.current, store.currentBytes, err = store.readSelection()
	if err != nil || store.current.Incomplete || store.current.Record.Sequence != 1 {
		return store, errors.Join(err, errors.New("new journal did not prove its exact initial durable state"))
	}
	return store, store.verifyController(ctx)
}

func openProtectionJournal(ctx context.Context, machineDirectory string, desktop *windowscontroller.Process, data *os.File) (*ProtectionJournal, error) {
	store, err := newProtectionJournal(ctx, machineDirectory, desktop, data)
	if err != nil {
		return store, err
	}
	machine := store.pins[len(store.pins)-1].path
	store.root, err = openProtectionObject(filepath.Join(machine, journalDirectoryName), true,
		syscall.FILE_LIST_DIRECTORY|protectionReadAttributes|protectionReadControl, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
	if err != nil {
		return store, err
	}
	if err := verifyProtectionSecurity(store.api, store.root.handle, true); err != nil {
		return store, err
	}
	// No CREATE, truncation, ACL repair or deletion occurs on the reopen path.
	store.lock, err = openProtectionObject(filepath.Join(store.root.path, journalLockName), false,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE|protectionReadControl, 0)
	if err != nil {
		return store, err
	}
	store.file, err = openProtectionObject(filepath.Join(store.root.path, journalHeaderName), false,
		syscall.GENERIC_READ|protectionReadControl, 0)
	if err != nil {
		return store, err
	}
	for index, name := range journalSlotNames {
		store.slots[index], err = openProtectionObject(filepath.Join(store.root.path, name), false,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE|protectionReadControl, 0)
		if err != nil {
			return store, err
		}
	}
	// Check every native owner and ACL before interpreting the immutable header.
	for _, file := range []*protectionObject{store.root, store.file, store.lock, store.slots[0], store.slots[1]} {
		if err := store.verifyObject(file, true); err != nil {
			return store, err
		}
	}
	store.headerBytes, err = journalReadRetained(store.file, journalHeaderLimit)
	if err != nil {
		return store, err
	}
	store.header, err = parseJournalHeader(store.headerBytes)
	if err != nil {
		return store, err
	}
	store.lockBytes = journalLockBytes(store.header.JournalID)
	store.initialized = true
	if err := store.verifyObjects(); err != nil {
		return store, err
	}
	store.current, store.currentBytes, err = store.readSelection()
	if err != nil {
		return store, err
	}
	return store, store.verifyController(ctx)
}

func journalLockBytes(id string) []byte {
	return []byte("RouterVPN-owned-WFP-journal-lock/1\n" + id + "\n")
}

func (store *ProtectionJournal) verifyController(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || store == nil || store.closed || store.self == nil || store.controller.PID != uint32(os.Getpid()) {
		return errors.New("journal storage lost its live captured controller operation")
	}
	actual, identity, err := journalProcessCapture(store.self)
	if err != nil || actual != store.controller || identity != store.identity || !identity.Elevated || !identity.Administrator {
		return errors.Join(err, errors.New("journal storage changed its captured elevated process token"))
	}
	return ctx.Err()
}

func (store *ProtectionJournal) verifyObject(file *protectionObject, administrative bool) error {
	if err := file.verify(); err != nil {
		return err
	}
	if administrative {
		if err := verifyProtectionSecurity(store.api, file.handle, file.directory); err != nil {
			return err
		}
	}
	current, err := openProtectionObject(file.path, file.directory, protectionReadAttributes|protectionReadControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if current != nil {
		if err == nil && !sameProtectionObject(file.identity, current.identity) {
			err = errors.New("journal pathname no longer names its captured native object")
		}
		err = errors.Join(err, current.close())
	}
	return err
}

func (store *ProtectionJournal) verifyInventory(complete bool) error {
	if store.root == nil {
		return errors.New("journal has no retained root inventory")
	}
	if err := store.root.verify(); err != nil {
		return err
	}
	directory, err := os.Open(store.root.path)
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(6)
	closeErr := directory.Close()
	if closeErr != nil || readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	wanted := map[string]bool{}
	if complete {
		wanted = map[string]bool{journalHeaderName: true, journalLockName: true, journalSlotNames[0]: true, journalSlotNames[1]: true}
	}
	if len(names) != len(wanted) {
		return errors.New("journal directory contains incomplete or unknown ownership")
	}
	for _, name := range names {
		if !wanted[name] {
			return errors.New("journal directory contains another file or legacy recovery record")
		}
		delete(wanted, name)
	}
	return store.root.verify()
}

func (store *ProtectionJournal) verifyObjects() error {
	if !store.initialized || store.closed || store.data == nil || store.root == nil || store.file == nil || store.lock == nil || store.slots[0] == nil || store.slots[1] == nil {
		return errors.New("journal has no complete retained file owner")
	}
	for _, file := range append(append([]*protectionObject(nil), store.pins...), store.dataPins...) {
		if err := file.verify(); err != nil {
			return err
		}
	}
	if err := store.verifyObject(store.data, false); err != nil {
		return err
	}
	for _, file := range []*protectionObject{store.root, store.file, store.lock, store.slots[0], store.slots[1]} {
		if err := store.verifyObject(file, true); err != nil {
			return err
		}
	}
	if err := store.verifyInventory(true); err != nil {
		return err
	}
	machineVolume, err := journalVolume(store.api, store.root)
	if err != nil {
		return err
	}
	dataVolume, err := journalVolume(store.api, store.data)
	if err != nil {
		return err
	}
	expected := journalHeader{Schema: 1, Kind: "routervpn-owned-wfp-journal-files", JournalID: store.header.JournalID,
		DesktopSID: store.desktopCapture.SID, MachineVolume: machineVolume, DataVolume: dataVolume, Data: journalIdentity(store.data),
		Root: journalIdentity(store.root), Header: journalIdentity(store.file), Lock: journalIdentity(store.lock),
		Slots: [2]journalObjectIdentity{journalIdentity(store.slots[0]), journalIdentity(store.slots[1])}}
	if store.header != expected || store.header.validate() != nil {
		return errors.New("journal header differs from retained original-user, directory or file identities")
	}
	for _, item := range []struct {
		file  *protectionObject
		body  []byte
		limit int
	}{{store.file, store.headerBytes, journalHeaderLimit}, {store.lock, store.lockBytes, 256}} {
		raw, err := journalReadRetained(item.file, item.limit)
		if err != nil || !bytes.Equal(raw, item.body) {
			return errors.Join(err, errors.New("journal immutable header or exclusive lock bytes changed"))
		}
	}
	return nil
}

func journalReadRetained(file *protectionObject, limit int) ([]byte, error) {
	if limit < 1 || limit > JournalRecordLimit {
		return nil, errors.New("journal read has an invalid fixed bound")
	}
	if err := file.verify(); err != nil {
		return nil, err
	}
	if _, err := syscall.Seek(file.handle, 0, 0); err != nil {
		return nil, err
	}
	buffer := make([]byte, limit+1)
	read := 0
	for read < len(buffer) {
		var count uint32
		err := syscall.ReadFile(file.handle, buffer[read:], &count, nil)
		if err != nil && !errors.Is(err, syscall.ERROR_HANDLE_EOF) {
			return nil, err
		}
		read += int(count)
		if count == 0 || errors.Is(err, syscall.ERROR_HANDLE_EOF) {
			break
		}
	}
	if read > limit {
		return nil, errors.New("journal retained file exceeds its fixed bound")
	}
	return buffer[:read], file.verify()
}

// FlushFileBuffers is required even for an empty initialized slot: Windows
// caches file metadata too. Only the inactive retained file is overwritten;
// the previous complete slot survives a short write, failed flush or crash.
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
func journalWriteRetained(file *protectionObject, body []byte) error {
	if len(body) > JournalRecordLimit {
		return errors.New("journal write exceeds its fixed bound")
	}
	if err := file.verify(); err != nil {
		return err
	}
	if _, err := syscall.Seek(file.handle, 0, 0); err != nil {
		return err
	}
	for written := 0; written < len(body); {
		var count uint32
		if err := syscall.WriteFile(file.handle, body[written:], &count, nil); err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		written += int(count)
	}
	if err := syscall.SetEndOfFile(file.handle); err != nil {
		return err
	}
	if err := syscall.FlushFileBuffers(file.handle); err != nil {
		return err
	}
	actual, err := journalReadRetained(file, JournalRecordLimit)
	if err != nil || !bytes.Equal(actual, body) {
		return errors.Join(err, errors.New("journal write did not independently read back its complete flushed bytes"))
	}
	return file.verify()
}

func (store *ProtectionJournal) readSelection() (JournalSelection, []byte, error) {
	var slots [2][]byte
	for index, file := range store.slots {
		body, err := journalReadRetained(file, JournalRecordLimit)
		if err != nil {
			return JournalSelection{}, nil, err
		}
		slots[index] = body
	}
	selection, err := SelectJournalRecord(store.header.JournalID, slots)
	if err != nil {
		return JournalSelection{}, nil, err
	}
	return selection, append([]byte(nil), slots[selection.Slot]...), nil
}

// Snapshot rereads both captured files. A failed/pending write is not silently
// acknowledged as a new current record, even if some bytes are already visible.
func (store *ProtectionJournal) Snapshot(ctx context.Context) (JournalSelection, error) {
	if store == nil {
		return JournalSelection{}, errors.New("journal snapshot has no retained native store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.verifyController(ctx); err != nil {
		return JournalSelection{}, err
	}
	if store.pending != nil {
		return JournalSelection{}, errors.New("journal durable append remains pending its exact flush and readback")
	}
	if store.recovery != nil {
		return JournalSelection{}, errors.New("journal controller recovery has not joined its native observation")
	}
	if err := store.verifyObjects(); err != nil {
		return JournalSelection{}, err
	}
	selection, raw, err := store.readSelection()
	if err != nil || !bytes.Equal(raw, store.currentBytes) || selection.SHA256 != store.current.SHA256 || selection.Slot != store.current.Slot || selection.Incomplete != store.current.Incomplete {
		return JournalSelection{}, errors.Join(err, errors.New("journal snapshot changed without an owned durable append"))
	}
	return selection, store.verifyController(ctx)
}

// Append writes comparison data under this exact native creator. Its caller
// must supply the independent native proof that makes this record appropriate
// (including the BFE write transaction's precommit barrier). This operation
// alone neither changes protection nor grants restart/removal authority.
// A failed write retains its exact inactive slot and bytes; only that same
// append may retry. Close preserves both files for later checked recovery.
func (store *ProtectionJournal) Append(ctx context.Context, previousSHA256 string, next JournalRecord) (JournalSelection, error) {
	if store == nil {
		return JournalSelection{}, errors.New("journal append has no retained native store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.verifyController(ctx); err != nil {
		return JournalSelection{}, err
	}
	if store.recovery != nil {
		return JournalSelection{}, errors.New("journal ordinary append cannot replace its captured recovery owner")
	}
	next = cloneJournalRecord(next)
	body, err := CanonicalJournalRecord(next)
	if err != nil || next.Controller != store.controller || previousSHA256 != store.current.SHA256 || store.current.Incomplete {
		return JournalSelection{}, errors.Join(err, errors.New("journal append lost its exact creator, previous digest or complete slots"))
	}
	if err := CheckJournalTransition(store.current.Record, next); err != nil {
		return JournalSelection{}, err
	}
	if err := requireJournalProfileBindings(store.current.Record); err != nil {
		return JournalSelection{}, err
	}
	if err := requireJournalProfileBindings(next); err != nil {
		return JournalSelection{}, err
	}
	return store.appendCanonicalLocked(ctx, previousSHA256, next, body)
}

// The caller already checked either the strict ordinary transition or the
// private native recovery capability. This helper never selects a controller,
// candidate or alternate write; it flushes only the captured immutable bytes.
func (store *ProtectionJournal) appendCanonicalLocked(ctx context.Context, previousSHA256 string, next JournalRecord, body []byte) (JournalSelection, error) {
	if err := store.verifyObjects(); err != nil {
		return JournalSelection{}, err
	}
	if store.pending == nil {
		selection, raw, err := store.readSelection()
		if err != nil || !bytes.Equal(raw, store.currentBytes) || selection.SHA256 != previousSHA256 || selection.Incomplete {
			return JournalSelection{}, errors.Join(err, errors.New("journal append changed its retained previous generation"))
		}
		digest, err := JournalRecordSHA256(body)
		if err != nil {
			return JournalSelection{}, err
		}
		store.pending = &journalPendingAppend{record: next, body: body, digest: digest, slot: 1 - store.current.Slot}
	} else if !bytes.Equal(store.pending.body, body) {
		return JournalSelection{}, errors.New("journal append cannot replace its pending native file write")
	}
	pending := store.pending
	// Every retry still proves that the preceding slot was left intact. It
	// never discovers or overwrites a different last-acknowledged generation.
	previous, err := journalReadRetained(store.slots[store.current.Slot], JournalRecordLimit)
	if err != nil || !bytes.Equal(previous, store.currentBytes) {
		return JournalSelection{}, errors.Join(err, errors.New("journal pending write lost its previous complete slot"))
	}
	if err := store.verifyController(ctx); err != nil {
		return JournalSelection{}, err
	}
	if err := journalWriteRetained(store.slots[pending.slot], pending.body); err != nil {
		return JournalSelection{}, err
	}
	if err := store.verifyObjects(); err != nil {
		return JournalSelection{}, err
	}
	selection, raw, err := store.readSelection()
	if err != nil || selection.Incomplete || selection.Slot != pending.slot || selection.SHA256 != pending.digest || !bytes.Equal(raw, pending.body) {
		return JournalSelection{}, errors.Join(err, errors.New("journal append did not prove its exact durable successor"))
	}
	store.current, store.currentBytes = selection, append([]byte(nil), raw...)
	store.pending = nil
	// Cancellation after a proved flush does not erase that durable intent.
	// Return its identity together with the error; a native barrier must still
	// refuse its ACK/commit when the captured operation has been cancelled.
	return JournalSelection{cloneJournalRecord(selection.Record), selection.SHA256, selection.Slot, selection.Incomplete}, store.verifyController(ctx)
}

// Close never deletes the stable lock, immutable header or either slot. It
// serializes with writes and retries every still-owned handle while keeping a
// prior close error sticky; another caller cannot mistake an incomplete join
// for a clean release of the recovery directory.
func (store *ProtectionJournal) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	store.closed = true
	recovery := store.recovery
	store.mu.Unlock()
	// Recovery's synchronous callback may need the journal mutex to observe
	// cancellation. Never close its files or wait for its gate under that lock.
	var recoveryErr error
	if recovery != nil {
		recoveryErr = recovery.Close(context.Background())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	failure := recoveryErr
	for _, file := range []*protectionObject{store.slots[0], store.slots[1], store.file, store.lock, store.root} {
		failure = errors.Join(failure, file.close())
	}
	for _, pins := range [][]*protectionObject{store.pins, store.dataPins} {
		for index := len(pins) - 1; index >= 0; index-- {
			failure = errors.Join(failure, pins[index].close())
		}
	}
	failure = errors.Join(failure, store.data.close())
	if store.desktop != nil {
		failure = errors.Join(failure, store.desktop.Close())
	}
	if store.self != nil {
		failure = errors.Join(failure, store.self.Close())
	}
	if store.closeErr == nil {
		store.closeErr = failure
	}
	return errors.Join(store.closeErr, failure)
}
