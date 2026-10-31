//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/mobiletor"
)

func journalNativeStartup(t *testing.T, fixture *journalNativeFixture) (*ProtectionJournal, error) {
	t.Helper()
	store, err := openProtectionJournalWithStartup(context.Background(), fixture.machine, fixture.desktop, fixture.data, fixture.initialRead)
	if store != nil {
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Error("startup observation did not join its retained native handles", err)
			}
		})
	}
	return store, err
}

// Process/token, Data ancestry, root lookup and cleanup use real Windows
// handles. Only BFE absence is modeled here; the composed application Session
// separately executes the shipping read against the actual native provider.
func TestWindowsProtectionJournalStartupAbsentWithoutCreation(t *testing.T) {
	fixture := journalNativeInputs(t)
	store, err := journalNativeStartup(t, fixture)
	if err != nil || store == nil || fixture.reads != 1 {
		t.Fatal("native startup did not prove initial absence", err, fixture.reads)
	}
	if _, err := os.Lstat(filepath.Join(fixture.machine, journalDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty native startup created or adopted a machine journal", err)
	}
	if _, err := store.Snapshot(context.Background()); err == nil {
		t.Fatal("an initial-absence observation fabricated a durable journal head")
	}
	absent, err := store.initialAbsence(context.Background(), fixture.initialRead)
	if err != nil || !absent || fixture.reads != 2 {
		t.Fatal("initial absence reused a historical native protection read", err, fixture.reads)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if absent, err := store.initialAbsence(context.Background(), fixture.initialRead); err == nil || absent {
		t.Fatal("closed startup owner acknowledged native absence")
	}
}

func TestWindowsProtectionJournalStartupExistingAndIncomplete(t *testing.T) {
	for _, change := range []string{"complete", "files.json", "journal.lock", "slot-0.json", "slot-1.json", "other-data", "unknown-root"} {
		t.Run(change, func(t *testing.T) {
			fixture := journalNativeCreate(t)
			if err := fixture.store.Close(); err != nil {
				t.Fatal(err)
			}
			if change == "other-data" {
				path := filepath.Join(t.TempDir(), "another-private-root")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = file.Close() })
				observation := *fixture
				observation.data = file
				fixture = &observation
			} else if change == "unknown-root" {
				if err := os.WriteFile(filepath.Join(fixture.machine, journalDirectoryName, "foreign.json"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if change != "complete" {
				if err := os.Remove(filepath.Join(fixture.machine, journalDirectoryName, change)); err != nil {
					t.Fatal(err)
				}
			}
			fixture.reads = 0
			opened, err := journalNativeStartup(t, fixture)
			if opened == nil || fixture.reads != 0 || (err == nil) != (change == "complete") {
				t.Fatal("existing or incomplete native journal became initial absence", err, fixture.reads)
			}
			if absent, _ := opened.initialAbsence(context.Background(), fixture.initialRead); absent || fixture.reads != 0 {
				t.Fatal("missing peer or changed Data acquired an initial-absence capability")
			}
			if change == "complete" {
				if _, err := opened.Snapshot(context.Background()); err != nil {
					t.Fatal("complete existing journal lost normal recovery", err)
				}
			}
		})
	}
}

func TestWindowsProtectionJournalStartupRejectsChangedObservation(t *testing.T) {
	for _, change := range []string{"native-protection", "cancelled", "namespace-appeared", "desktop", "data", "machine-ancestor", "missing-reader"} {
		t.Run(change, func(t *testing.T) {
			fixture := journalNativeInputs(t)
			store, err := journalNativeStartup(t, fixture)
			if err != nil || store == nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			read := func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error {
				switch change {
				case "native-protection":
					return errors.New("exact native provider is not absent")
				case "cancelled":
					cancel()
				case "namespace-appeared":
					return os.Mkdir(filepath.Join(fixture.machine, journalDirectoryName), 0700)
				case "desktop":
					store.desktopCapture.AuthenticationID++
				case "data":
					return store.data.close()
				case "machine-ancestor":
					return store.pins[len(store.pins)-1].close()
				}
				return nil
			}
			if change == "missing-reader" {
				read = nil
			}
			if absent, err := store.initialAbsence(ctx, read); err == nil || absent {
				t.Fatal("startup accepted changed native protection, namespace or retained identity")
			}
		})
	}
}
