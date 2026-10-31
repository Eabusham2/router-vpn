package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/windowsprotection"
)

// These tests exercise the shipping application initializer and source-stage
// ordering. Only native journal/BFE ownership is modeled; the actual retained
// Windows namespace and identity checks have a separate mandatory native gate.
type desktopInitialJournalStore struct {
	base               *desktopNodeJournalFixtureStore
	absent, closed     bool
	proofs, closes     int
	proofErr, closeErr error
	onProof, onClose   func()
}

func (s *desktopInitialJournalStore) InitialAbsence(context.Context) (bool, error) {
	s.proofs++
	if s.closed {
		return false, errors.New("fixture absence owner is already joined")
	}
	if s.onProof != nil {
		s.onProof()
	}
	return s.absent, s.proofErr
}

func (s *desktopInitialJournalStore) Snapshot(ctx context.Context) (windowsprotection.JournalSelection, error) {
	if s.closed || s.absent || s.base == nil {
		return windowsprotection.JournalSelection{}, errors.New("fixture absence is not a durable journal snapshot")
	}
	selection, err := s.base.Snapshot(ctx)
	selection.Slot = int((selection.Record.Sequence - 1) % 2)
	return selection, err
}

func (s *desktopInitialJournalStore) Append(ctx context.Context, previous string, next windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error) {
	if s.closed || s.absent || s.base == nil {
		return windowsprotection.JournalSelection{}, errors.New("fixture absence cannot acknowledge a journal write")
	}
	return s.base.Append(ctx, previous, next)
}

func (s *desktopInitialJournalStore) Close() error {
	s.closes++
	if s.onClose != nil {
		s.onClose()
	}
	if s.closeErr != nil {
		return s.closeErr
	}
	s.closed = true
	return nil
}

type desktopInitialJournalFixture struct {
	a          *app
	slot       *desktopNodeProtectionSlot
	backend    desktopNodeProtectionBackend
	controller windowsprotection.Controller
	head       windowsprotection.JournalRecord
	absence    *desktopInitialJournalStore
	durable    *desktopInitialJournalStore
	open       func(context.Context) (desktopNodeProtectionJournal, error)
	create     func(context.Context) (desktopNodeProtectionJournal, error)
	currentErr error
	opens      int
	creates    int
	begins     int
}

func newDesktopInitialJournalFixture(t *testing.T) *desktopInitialJournalFixture {
	t.Helper()
	f := &desktopInitialJournalFixture{a: &app{}}
	f.a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "routers.json")
	f.controller = windowsprotection.Controller{PID: 101, StartTimeUTCTicks: 638000000000000000,
		SID: "S-1-5-21-100-200-300-1001", AuthenticationID: 123, SessionID: 2}
	f.head = windowsprotection.JournalRecord{Schema: 1, Kind: windowsprotection.JournalRecordKind,
		JournalID: strings.Repeat("a", 32), Sequence: 1, Controller: f.controller, Phase: "settled"}
	f.absence = &desktopInitialJournalStore{absent: true}
	f.durable = &desktopInitialJournalStore{base: &desktopNodeJournalFixtureStore{head: f.head}}
	f.open = func(context.Context) (desktopNodeProtectionJournal, error) {
		return f.absence, nil
	}
	f.create = func(context.Context) (desktopNodeProtectionJournal, error) {
		if !f.absence.closed {
			return nil, errors.New("fixture creator preceded joining the absence owner")
		}
		return f.durable, nil
	}
	kernel := &desktopNodeProtectionFixture{}
	f.backend = kernel.backend()
	f.backend.bootstrap = func(ctx context.Context, profiles string) (desktopNodeRecoveryBackend, error) {
		if ctx.Err() != nil || profiles != f.a.cfg.ProfilesFile {
			return desktopNodeRecoveryBackend{}, errors.New("fixture bootstrap changed its original Data owner")
		}
		return desktopNodeRecoveryBackend{controller: f.controller,
			current: func() error { return f.currentErr },
			open: func(ctx context.Context) (desktopNodeProtectionJournal, error) {
				f.opens++
				return f.open(ctx)
			},
			create: func(ctx context.Context) (desktopNodeProtectionJournal, error) {
				f.creates++
				return f.create(ctx)
			},
			begin: func(context.Context, desktopNodeProtectionJournal) (desktopNodeJournalRecovery, error) {
				f.begins++
				return nil, errors.New("fixture has no permission to adopt a foreign controller")
			}}, nil
	}
	f.slot = &desktopNodeProtectionSlot{backend: f.backend}
	f.a.nodeProtection = f.slot
	return f
}

func (f *desktopInitialJournalFixture) initialize(ctx context.Context) error {
	return f.a.initializeDesktopNodeRecoveryWith(ctx, f.backend)
}

func (f *desktopInitialJournalFixture) launch(t *testing.T) *desktopNodeLaunch {
	t.Helper()
	profile, original := desktopOwnedNodeTestSource(t, "initial-node", "198.51.100.8", "wg")
	f.a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	root := t.TempDir()
	launch, err := newDesktopOwnedNodeLaunch(profile, original, "wg", root, profile.Endpoint,
		desktopOwnedNodeTestNetwork(t), strings.Repeat("1", 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "native-private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	return launch
}

func TestDesktopNodeInitialStartupDoesNotCreateJournal(t *testing.T) {
	f := newDesktopInitialJournalFixture(t)
	if err := f.initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.creates != 0 || f.begins != 0 || f.opens != 1 || f.absence.proofs != 1 || f.absence.closes != 1 ||
		!f.absence.closed || f.a.nodeProtection != nil || f.slot.journal != nil || !f.slot.provedEmpty() || f.a.state.Connected {
		t.Fatal("blank startup created or retained a machine journal without an actual protected source")
	}
	if entries, err := os.ReadDir(filepath.Dir(f.a.cfg.ProfilesFile)); err != nil || len(entries) != 0 {
		t.Fatal("blank startup wrote private profile or recovery state", err)
	}
	if _, err := f.slot.begin(context.Background(), &desktopNodeLaunch{}, desktopNodeProtectionPolicy(t, "2", "always", 0)); err == nil || f.slot.active != nil {
		t.Fatal("read-only startup absence authorized a source without a durable journal")
	}
}

func TestDesktopNodeInitialSourceCreatesBeforeCapturedAttempt(t *testing.T) {
	f := newDesktopInitialJournalFixture(t)
	if err := f.a.ensureDesktopNodeRecovery(context.Background(), f.slot); err != nil || !f.slot.provedEmpty() {
		t.Fatal("fixture could not prove read-only initial absence", err)
	}
	first := f.absence
	f.absence = &desktopInitialJournalStore{absent: true}
	launch := f.launch(t)
	if err := stageDesktopOwnedNodeInputs(f.a, launch); err != nil {
		t.Fatal("protected source captured an attempt before materializing its rechecked durable journal", err)
	}
	if f.creates != 1 || f.opens != 2 || !first.closed || !f.absence.closed || f.durable.closed || f.slot.journal != f.durable ||
		launch.ownedNode.attempt == nil || f.slot.active != launch.ownedNode.attempt || launch.ownedNode.attempt.transfer.Predecessor != nil {
		t.Fatal("protected source captured an attempt before materializing its rechecked durable journal")
	}
	if f.slot.recovery.head == nil || !reflect.DeepEqual(f.slot.recovery.head.Record, f.head) || f.begins != 0 {
		t.Fatal("new source substituted recovery or lost its exact current-controller empty checkpoint")
	}
}

func TestDesktopNodeInitialSourceRejectsUnmaterializedJournal(t *testing.T) {
	for _, fault := range []string{"foreign-header", "missing-peer", "create-failure", "absence-close", "incomplete-create"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopInitialJournalFixture(t)
			if err := f.a.ensureDesktopNodeRecovery(context.Background(), f.slot); err != nil {
				t.Fatal(err)
			}
			f.absence = &desktopInitialJournalStore{absent: true}
			launch := f.launch(t)
			switch fault {
			case "foreign-header", "missing-peer":
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) {
					return f.durable, errors.New("fixture changed namespace: " + fault)
				}
			case "create-failure":
				f.create = func(context.Context) (desktopNodeProtectionJournal, error) {
					return f.durable, errors.New("fixture journal creation is incomplete")
				}
			case "absence-close":
				f.absence.closeErr = errors.New("fixture absence owner is still joining")
			case "incomplete-create":
				f.durable.base.incomplete = true
			}
			if err := stageDesktopOwnedNodeInputs(f.a, launch); err == nil || launch.ownedNode.attempt != nil || f.slot.active != nil || f.slot.known {
				t.Fatal("protected source staged an attempt from unmaterialized or foreign durable state")
			}
			if _, err := os.Stat(filepath.Join(launch.directory, "node-protection-transfer.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unmaterialized source published native predecessor authority", err)
			}
		})
	}
}

func TestDesktopNodeInitialStartupRejectsMissingAndForeignState(t *testing.T) {
	for _, fault := range []string{"root-errno-only", "missing-header", "nil-store", "unknown-proof", "false-without-snapshot", "foreign-controller", "incomplete-record"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopInitialJournalFixture(t)
			switch fault {
			case "root-errno-only":
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) { return nil, os.ErrNotExist }
			case "missing-header":
				f.absence.absent = false
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) { return f.absence, os.ErrNotExist }
			case "nil-store":
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) { return nil, nil }
			case "unknown-proof":
				f.absence.proofErr = errors.New("fixture native namespace or BFE is unresolved")
			case "false-without-snapshot":
				f.absence.absent = false
			case "foreign-controller":
				f.durable.base.head.Controller.PID++
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) { return f.durable, nil }
			case "incomplete-record":
				f.durable.base.incomplete = true
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) { return f.durable, nil }
			}
			if err := f.initialize(context.Background()); err == nil || f.creates != 0 || f.slot.known || f.slot.active != nil || f.a.nodeProtection != f.slot {
				t.Fatal("unknown or foreign journal became initial absence or was replaced by creation")
			}
			if f.durable.base.writes != 0 || f.durable.base.head.Controller.PID != f.controller.PID && fault != "foreign-controller" {
				t.Fatal("failed initial startup rewrote existing journal state")
			}
		})
	}
}

func TestDesktopNodeInitialAbsenceRequiresCurrentJoinedOwner(t *testing.T) {
	for _, fault := range []string{"cancel-during-proof", "cancel-after-close", "changed-selection", "changed-controller", "close-failure"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopInitialJournalFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "cancel-during-proof":
				f.absence.onProof = cancel
			case "cancel-after-close":
				f.absence.onClose = cancel
			case "changed-selection":
				f.absence.onProof = func() { f.a.profiles.SelectedID = "replacement" }
			case "changed-controller":
				f.absence.onProof = func() { f.currentErr = errors.New("fixture controller ended") }
			case "close-failure":
				f.absence.closeErr = errors.New("fixture retained native owner has not joined")
			}
			if err := f.a.ensureDesktopNodeJournalForStart(ctx, f.slot); err == nil || f.creates != 0 || f.slot.known || f.slot.active != nil || f.slot.recovery.ready {
				t.Fatal("cancelled, replaced or unjoined absence admitted durable source creation")
			}
			if fault == "close-failure" && (f.slot.journal != f.absence || !f.slot.recovery.absenceClosing || f.absence.closed) {
				t.Fatal("failed absence join discarded its exact native owner")
			}
		})
	}
}

func TestDesktopNodeInitialCloseRetryReopensExactNamespace(t *testing.T) {
	for _, replacement := range []string{"still-absent", "foreign-header", "missing-peer"} {
		t.Run(replacement, func(t *testing.T) {
			f := newDesktopInitialJournalFixture(t)
			first := f.absence
			first.closeErr = errors.New("fixture retryable native owner join")
			if err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot); err == nil {
				t.Fatal("unjoined initial absence reached source creation")
			}
			// Native ProtectionJournal.Close has a sticky first error. This
			// modeled retryable owner covers application ordering only; the app
			// never overrides a native error to manufacture this success.
			first.closeErr = nil
			f.absence = &desktopInitialJournalStore{absent: true}
			if replacement != "still-absent" {
				f.open = func(context.Context) (desktopNodeProtectionJournal, error) {
					return f.durable, errors.New("fixture reopened " + replacement)
				}
			}
			err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot)
			if !first.closed || first.closes != 2 || first.proofs != 1 || f.opens != 2 {
				t.Fatal("absence retry reused old proof instead of joining then reopening its native namespace")
			}
			if replacement == "still-absent" {
				if err != nil || f.creates != 1 || f.slot.journal != f.durable || !f.slot.known || !f.absence.closed {
					t.Fatal("fresh checked absence could not finish durable source preparation", err)
				}
			} else if err == nil || f.creates != 0 || f.slot.known || f.slot.journal != f.durable {
				t.Fatal("old absence authorized creation over a new foreign or incomplete namespace")
			}
		})
	}
}

func TestDesktopNodeInitialCreateRetryRetainsPartialOwner(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete", true: "complete-but-unacknowledged"}[published], func(t *testing.T) {
			f := newDesktopInitialJournalFixture(t)
			partial := f.durable
			f.create = func(context.Context) (desktopNodeProtectionJournal, error) {
				return partial, errors.New("fixture create did not acknowledge its final native write")
			}
			if err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot); err == nil || f.slot.journal != partial || f.slot.known || f.creates != 1 {
				t.Fatal("failed journal creation lost its retained partial owner or admitted the source")
			}
			partial.closeErr = errors.New("fixture partial create still owns native handles")
			if err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot); err == nil || f.opens != 1 || f.creates != 1 || f.slot.journal != partial {
				t.Fatal("partial creation was replaced before its original native owner joined")
			}
			partial.closeErr = nil
			reopened := &desktopInitialJournalStore{base: &desktopNodeJournalFixtureStore{head: f.head}}
			f.open = func(context.Context) (desktopNodeProtectionJournal, error) {
				if !partial.closed {
					return nil, errors.New("fixture reopen preceded partial-owner join")
				}
				if !published {
					return reopened, os.ErrNotExist // missing a peer, not the root
				}
				return reopened, nil
			}
			err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot)
			if f.opens != 2 || f.creates != 1 || partial.closes != 2 || f.slot.journal != reopened || reopened.base.writes != 0 {
				t.Fatal("create retry repeated creation, rewrote bytes, or lost its reopened exact owner")
			}
			if published {
				if err != nil || !f.slot.known || f.slot.recovery.head == nil || !reflect.DeepEqual(f.slot.recovery.head.Record, f.head) {
					t.Fatal("complete same-controller create could not be read back after exact owner join", err)
				}
			} else if err == nil || f.slot.known || f.slot.recovery.ready {
				t.Fatal("incomplete creation was treated as absent or repaired with invented state")
			}
		})
	}
}

func TestDesktopNodeInitialCreateCancellationRetainsWrittenJournal(t *testing.T) {
	f := newDesktopInitialJournalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.create = func(context.Context) (desktopNodeProtectionJournal, error) {
		cancel() // the actual journal may already exist when its caller is cancelled
		return f.durable, nil
	}
	if err := f.a.ensureDesktopNodeJournalForStart(ctx, f.slot); err == nil || f.slot.known || f.slot.journal != f.durable ||
		f.slot.recovery.ready || f.slot.active != nil || f.creates != 1 {
		t.Fatal("late creation cancellation admitted a source or discarded the written journal")
	}
	if err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot); err != nil || !f.slot.known ||
		f.slot.journal != f.durable || f.creates != 1 || f.opens != 1 || f.slot.recovery.head == nil ||
		!reflect.DeepEqual(f.slot.recovery.head.Record, f.head) {
		t.Fatal("cancelled creation did not retry through its exact retained durable readback", err)
	}
}

func TestDesktopNodeInitialCancelledStartCannotAuthorizeReadOnlyCreate(t *testing.T) {
	f := newDesktopInitialJournalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := f.absence
	first.onClose = cancel
	if err := f.a.ensureDesktopNodeJournalForStart(ctx, f.slot); err == nil || f.creates != 0 || f.slot.known || !first.closed {
		t.Fatal("cancelled source start did not retain its unmaterialized outcome")
	}
	f.absence = &desktopInitialJournalStore{absent: true}
	readOnly := f.absence
	if err := f.initialize(context.Background()); err != nil || f.creates != 0 || !readOnly.closed ||
		!f.slot.provedEmpty() || f.a.nodeProtection != nil {
		t.Fatal("cancelled source start lent creation authority to later read-only startup", err)
	}
	// The previous empty slot was joined and dropped. Only this newly explicit
	// source request may acquire another owner and create its durable record.
	f.slot = &desktopNodeProtectionSlot{backend: f.backend}
	f.a.nodeProtection = f.slot
	f.absence = &desktopInitialJournalStore{absent: true}
	if err := f.a.ensureDesktopNodeJournalForStart(context.Background(), f.slot); err != nil || f.creates != 1 ||
		f.opens != 3 || !f.absence.closed || f.slot.journal != f.durable || !f.slot.known {
		t.Fatal("new explicit source did not acquire its own durable creation authority", err)
	}
}
