//go:build windows

package windowsprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

const (
	protectionDirectoryName = "RouterVPN-Owned-Protection-v2"
	protectionLockName      = "owner.lock"
	protectionRecordName    = "prepared-owner.json"
)

// PreparedOwner is only the retained identity before any Firewall mutation.
// It cannot adopt old rollback JSON, change a rule/profile, or authorize a WFP
// transfer. A later mutation journal must acquire this native capability, not
// reconstruct it from Record or SHA256. Close preserves the durable record;
// DiscardPrepared removes only this never-activated captured preparation.
type PreparedOwner struct {
	mu           sync.Mutex
	api          *protectionNativeAPI
	self         *windowscontroller.Process
	identity     windowscontroller.TokenIdentity
	record       OwnerRecord
	body         []byte
	digest       string
	pins         []*protectionObject
	root         *protectionObject
	lock         *protectionObject
	file         *protectionObject
	closed       bool
	discarding   bool
	discarded    bool
	deleteMarked bool
	closeErr     error
}

// CreatePreparedOwner derives the machine location and controller identity
// from native Windows authorities. No environment variable, caller-selected
// pathname, parsed record or supplied PID chooses this owner.
func CreatePreparedOwner(ctx context.Context, capture Capture, policy string) (*PreparedOwner, error) {
	if ctx == nil || ctx.Err() != nil || capture.Validate() != nil || policy != "on-connect" && policy != "always" {
		return nil, errors.New("protection preparation requires its live exact capture and strict policy")
	}
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	return createPreparedOwner(ctx, paths.ProgramData, capture, policy)
}

// The private machine-directory parameter is the native fixture boundary.
// Production calls it only with MachineDirectories' authoritative ProgramData.
func createPreparedOwner(ctx context.Context, machineDirectory string, capture Capture, policy string) (_ *PreparedOwner, failure error) {
	if ctx == nil || ctx.Err() != nil || capture.Validate() != nil || policy != "on-connect" && policy != "always" {
		return nil, errors.New("protection preparation requires its live exact capture and strict policy")
	}
	api, err := protectionNative()
	if err != nil {
		return nil, err
	}
	owner := &PreparedOwner{api: api}
	complete := false
	defer func() {
		if !complete {
			// Even a short/failed initial write remains the exact CREATE_NEW
			// object retained by this creator. Abort never opens an old record.
			failure = errors.Join(failure, owner.abortCreation())
		}
	}()
	owner.self, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return owner, err
	}
	owner.identity, err = owner.self.Identity()
	if err != nil || !owner.identity.Primary || !owner.identity.Elevated || !owner.identity.Administrator {
		return owner, errors.Join(err, errors.New("protection preparation requires the retained elevated controller token"))
	}
	started, err := owner.self.StartTimeUTCTicks()
	if err != nil {
		return owner, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return owner, err
	}
	owner.record = OwnerRecord{Schema: OwnerRecordSchema, Kind: OwnerRecordKind, OwnerID: hex.EncodeToString(nonce[:]), Capture: capture,
		Controller: Controller{PID: owner.self.PID(), StartTimeUTCTicks: started, SID: owner.identity.SID,
			AuthenticationID: owner.identity.AuthenticationID, SessionID: owner.identity.SessionID}, Policy: policy}
	owner.body, err = CanonicalOwnerRecord(owner.record)
	if err != nil {
		return owner, err
	}
	owner.digest, err = OwnerRecordSHA256(owner.body)
	if err != nil {
		return owner, err
	}
	var canonical string
	owner.pins, canonical, err = pinProtectionDirectory(api, machineDirectory)
	if err != nil {
		return owner, err
	}
	if err := owner.verifyController(ctx); err != nil {
		return owner, err
	}
	owner.root, err = createProtectionDirectory(api, filepath.Join(canonical, protectionDirectoryName))
	if err != nil {
		return owner, err
	}
	owner.lock, err = createProtectionFile(api, filepath.Join(owner.root.path, protectionLockName), true)
	if err != nil {
		return owner, fmt.Errorf("another or unknown protection owner already holds this preparation: %w", err)
	}
	if err := owner.verifyInventory(false); err != nil {
		return owner, err
	}
	if err := owner.verifyController(ctx); err != nil {
		return owner, err
	}
	owner.file, err = createProtectionFile(api, filepath.Join(owner.root.path, protectionRecordName), false)
	if err != nil {
		return owner, err
	}
	var written uint32
	if err := syscall.WriteFile(owner.file.handle, owner.body, &written, nil); err != nil || int(written) != len(owner.body) {
		return owner, errors.Join(err, errors.New("protection owner record was not completely written"))
	}
	if err := syscall.FlushFileBuffers(owner.file.handle); err != nil {
		return owner, err
	}
	if err := owner.verifyLocked(ctx, capture); err != nil {
		return owner, err
	}
	complete = true
	return owner, nil
}

// Record and SHA256 return comparison data only. They do not transfer handles
// or turn a decoded/copy-created structure into native protection authority.
func (owner *PreparedOwner) Record() OwnerRecord {
	if owner == nil {
		return OwnerRecord{}
	}
	return owner.record
}

func (owner *PreparedOwner) SHA256() string {
	if owner == nil {
		return ""
	}
	return owner.digest
}

func (owner *PreparedOwner) Verify(ctx context.Context, capture Capture) error {
	if owner == nil {
		return errors.New("protection preparation has no native owner")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.verifyLocked(ctx, capture)
}

func (owner *PreparedOwner) verifyController(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || owner.self == nil || owner.self.PID() != uint32(os.Getpid()) || owner.record.Controller.PID != owner.self.PID() {
		return errors.New("protection preparation lost its current controller lifetime")
	}
	if err := owner.self.Alive(); err != nil {
		return err
	}
	identity, err := owner.self.Identity()
	if err != nil || identity != owner.identity || !identity.Primary || !identity.Elevated || !identity.Administrator {
		return errors.Join(err, errors.New("protection preparation changed its retained controller token"))
	}
	started, err := owner.self.StartTimeUTCTicks()
	if err != nil || started != owner.record.Controller.StartTimeUTCTicks || identity.SID != owner.record.Controller.SID ||
		identity.AuthenticationID != owner.record.Controller.AuthenticationID || identity.SessionID != owner.record.Controller.SessionID {
		return errors.Join(err, errors.New("protection preparation changed its exact process creation identity"))
	}
	return ctx.Err()
}

func (owner *PreparedOwner) verifyObjects() error {
	for _, pin := range owner.pins {
		if err := pin.verify(); err != nil {
			return err
		}
	}
	if owner.root == nil || owner.lock == nil || owner.file == nil {
		return errors.New("protection preparation has incomplete native file ownership")
	}
	for _, file := range []*protectionObject{owner.root, owner.lock, owner.file} {
		if err := owner.verifyCurrentObject(file); err != nil {
			return err
		}
	}
	return nil
}

func (owner *PreparedOwner) verifyCurrentObject(file *protectionObject) error {
	if err := file.verify(); err != nil {
		return err
	}
	if err := verifyProtectionSecurity(owner.api, file.handle, file.directory); err != nil {
		return err
	}
	current, err := openProtectionObject(file.path, file.directory, protectionReadAttributes|protectionReadControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
	if current != nil {
		if err == nil && !sameProtectionObject(file.identity, current.identity) {
			err = errors.New("protection pathname no longer names its retained object")
		}
		err = errors.Join(err, current.close())
	}
	return err
}

func (owner *PreparedOwner) verifyInventory(recordExists bool) error {
	if owner.root == nil {
		return errors.New("protection preparation has no retained directory")
	}
	if err := owner.root.verify(); err != nil {
		return err
	}
	directory, err := os.Open(owner.root.path)
	if err != nil {
		return err
	}
	entries, readErr := directory.Readdirnames(3)
	closeErr := directory.Close()
	if closeErr != nil || readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	expected := map[string]bool{protectionLockName: true}
	if recordExists {
		expected[protectionRecordName] = true
	}
	if len(entries) != len(expected) {
		return errors.New("protection directory contains an existing or unknown recovery owner")
	}
	for _, name := range entries {
		if !expected[name] {
			return errors.New("protection directory contains an unrecognized owner or journal")
		}
		delete(expected, name)
	}
	return owner.root.verify()
}

func (owner *PreparedOwner) verifyLocked(ctx context.Context, capture Capture) error {
	if owner.closed || owner.discarding || owner.discarded {
		return errors.New("protection preparation is retired or belongs to another capture")
	}
	return owner.verifyCaptured(ctx, capture)
}

func (owner *PreparedOwner) verifyCaptured(ctx context.Context, capture Capture) error {
	if capture != owner.record.Capture {
		return errors.New("protection preparation belongs to another capture")
	}
	if err := owner.verifyController(ctx); err != nil {
		return err
	}
	if err := owner.verifyObjects(); err != nil {
		return err
	}
	if err := owner.verifyInventory(true); err != nil {
		return err
	}
	if _, err := syscall.Seek(owner.file.handle, 0, 0); err != nil {
		return err
	}
	buffer := make([]byte, OwnerRecordLimit+1)
	var read uint32
	if err := syscall.ReadFile(owner.file.handle, buffer, &read, nil); err != nil && !errors.Is(err, syscall.ERROR_HANDLE_EOF) {
		return err
	}
	if read > OwnerRecordLimit || !bytes.Equal(buffer[:read], owner.body) {
		return errors.New("protection preparation changed its immutable owner bytes")
	}
	actual, err := ParseOwnerRecord(buffer[:read])
	if err != nil || actual != owner.record {
		return errors.Join(err, errors.New("protection preparation changed its canonical owner record"))
	}
	if err := owner.file.verify(); err != nil {
		return err
	}
	return owner.verifyController(ctx)
}

// Close relinquishes handles and the delete-on-close lock only. The immutable
// record survives for a future explicit, independently proved recovery path.
// Repeated calls retry any still-retained native handles but keep the first
// failure sticky, so an uncertain retirement never becomes success.
func (owner *PreparedOwner) Close() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.closed = true
	return owner.closeLocked()
}

func (owner *PreparedOwner) closeLocked() error {
	var failure error
	for _, file := range []*protectionObject{owner.file, owner.lock, owner.root} {
		failure = errors.Join(failure, file.close())
	}
	for index := len(owner.pins) - 1; index >= 0; index-- {
		failure = errors.Join(failure, owner.pins[index].close())
	}
	if owner.self != nil {
		failure = errors.Join(failure, owner.self.Close())
	}
	if owner.closeErr == nil {
		owner.closeErr = failure
	}
	return owner.closeErr
}

// DiscardPrepared is unavailable after Close and proves the entire unchanged
// preparation before deleting it. FileDispositionInfo acts on the retained
// CREATE_NEW handle; no pathname-based removal can target a replacement.
func (owner *PreparedOwner) DiscardPrepared(ctx context.Context) error {
	if owner == nil {
		return errors.New("protection discard has no captured preparation")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.discarded {
		return owner.closeErr
	}
	if owner.closed {
		return errors.New("closed preparation cannot reacquire discard authority")
	}
	if !owner.discarding {
		if err := owner.verifyLocked(ctx, owner.record.Capture); err != nil {
			return err
		}
		owner.discarding = true
	} else if !owner.deleteMarked {
		// A denied disposition changed no native file state. The complete
		// owner, including current ACLs and immutable bytes, must still hold
		// before retrying the original handle's deletion authority.
		if err := owner.verifyCaptured(ctx, owner.record.Capture); err != nil {
			return err
		}
	} else {
		// A partial native delete retains its original handles. Retry joins
		// that same operation; it cannot reopen a pathname or adopt a record.
		if err := owner.verifyController(ctx); err != nil {
			return err
		}
		for _, file := range owner.pins {
			if err := file.verify(); err != nil {
				return err
			}
		}
		for _, file := range []*protectionObject{owner.root, owner.lock} {
			if err := owner.verifyCurrentObject(file); err != nil {
				return err
			}
		}
	}
	if err := owner.deleteCreatedRecord(); err != nil {
		return err
	}
	owner.discarded, owner.closed = true, true
	return owner.closeLocked()
}

func (owner *PreparedOwner) deleteCreatedRecord() error {
	if owner.file == nil {
		return nil
	}
	if !owner.deleteMarked {
		if err := owner.file.verify(); err != nil {
			return err
		}
		if err := verifyProtectionSecurity(owner.api, owner.file.handle, false); err != nil {
			return err
		}
		// FILE_DISPOSITION_INFO contains one BOOLEAN. DELETE was acquired at
		// CREATE_NEW, and every other data/delete opener is denied by sharing.
		// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
		remove := byte(1)
		ok, _, callErr := owner.api.setInformation.Call(uintptr(owner.file.handle), 4 /* FileDispositionInfo */, uintptr(unsafe.Pointer(&remove)), 1)
		runtime.KeepAlive(&remove)
		if ok == 0 {
			return fmt.Errorf("discard captured preparation by handle: %w", callErr)
		}
		owner.deleteMarked = true
	}
	if err := owner.file.close(); err != nil {
		return err
	}
	if _, err := os.Lstat(owner.file.path); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("discarded protection preparation has not proved absent"))
	}
	return nil
}

func (owner *PreparedOwner) abortCreation() error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.closed = true
	// Only a file returned by this attempt's CREATE_NEW reaches this method.
	// A prior record/lock collision is never opened or removed here.
	failure := owner.deleteCreatedRecord()
	return errors.Join(failure, owner.closeLocked())
}
