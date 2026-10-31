//go:build windows

package windowsprotection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

// OpenProtectionJournalForStartup never creates a machine journal merely to
// open an application. It either opens the complete existing owner, or retains
// the authenticated desktop/Data/machine handles for a checked initial-absence
// proof. Any error may still carry a partial owner that its caller must close.
// A missing peer inside an existing journal is never initial absence.
func OpenProtectionJournalForStartup(ctx context.Context, desktop *windowscontroller.Process, data *os.File) (*ProtectionJournal, error) {
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	return openProtectionJournalWithStartup(ctx, paths.ProgramData, desktop, data, mobiletor.ReadDesktopWindowsProtectionExpectation)
}

func journalNamespaceNotFound(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND)
}

// InitialAbsence is a fresh native observation, not a saved record or a
// lifetime permission to create a later tunnel. The retained owner must close
// successfully before the app acknowledges empty startup. A later connection
// must create/recheck its real journal before capturing any predecessor.
func (store *ProtectionJournal) InitialAbsence(ctx context.Context) (bool, error) {
	return store.initialAbsence(ctx, mobiletor.ReadDesktopWindowsProtectionExpectation)
}

// The read callback is only the same private native-fixture boundary used by
// journal creation. Production always uses the exact Windows BFE reader.
func (store *ProtectionJournal) initialAbsence(ctx context.Context,
	read func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error) (bool, error) {
	if store == nil {
		return false, errors.New("startup absence has no retained native owner")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.verifyController(ctx); err != nil {
		return false, err
	}
	if !store.initialAbsent {
		return false, nil // an existing journal must take normal snapshot/recovery
	}
	if store.initialized || store.root != nil || store.file != nil || store.lock != nil ||
		store.slots[0] != nil || store.slots[1] != nil || read == nil {
		return false, errors.New("startup absence cannot adopt existing or partial journal files")
	}
	if err := store.verifyInitialAbsenceCapture(ctx); err != nil {
		return false, err
	}
	if err := store.verifyInitialNamespaceAbsent(); err != nil {
		return false, err
	}
	if err := read(ctx, nil); err != nil {
		return false, err
	}
	// Native readback must not turn a journal that appeared during observation
	// into an absent store. Retain an unexpected opened root for checked Close.
	if err := store.verifyInitialNamespaceAbsent(); err != nil {
		return false, err
	}
	if err := store.verifyInitialAbsenceCapture(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (store *ProtectionJournal) verifyInitialAbsenceCapture(ctx context.Context) error {
	if err := store.verifyController(ctx); err != nil {
		return err
	}
	if store.data == nil || len(store.pins) == 0 || len(store.dataPins) == 0 {
		return errors.New("startup absence lost its original Data or machine ancestry")
	}
	desktop, identity, err := journalProcessCapture(store.desktop)
	if err != nil || desktop != store.desktopCapture || identity != store.desktopIdentity {
		return errors.Join(err, errors.New("startup absence changed its authenticated original desktop"))
	}
	for _, pins := range [][]*protectionObject{store.pins, store.dataPins} {
		for _, file := range pins {
			if err := file.verify(); err != nil {
				return err
			}
		}
	}
	if !sameProtectionObject(store.data.identity, store.dataPins[len(store.dataPins)-1].identity) {
		return errors.New("startup absence changed its captured private directory")
	}
	if err := store.verifyObject(store.data, false); err != nil {
		return err
	}
	return store.verifyController(ctx)
}

func (store *ProtectionJournal) verifyInitialNamespaceAbsent() error {
	if len(store.pins) == 0 || store.root != nil {
		return errors.New("startup absence has an existing or unowned journal namespace")
	}
	machine := store.pins[len(store.pins)-1]
	if err := machine.verify(); err != nil {
		return err
	}
	root, err := openProtectionObject(filepath.Join(machine.path, journalDirectoryName), true,
		syscall.FILE_LIST_DIRECTORY|protectionReadAttributes|protectionReadControl, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)
	if root != nil {
		store.root = root // even an invalid/partial opened object remains owned
	}
	if root != nil || !journalNamespaceNotFound(err) {
		return errors.Join(err, errors.New("startup absence found an existing or inaccessible journal namespace"))
	}
	return machine.verify()
}
