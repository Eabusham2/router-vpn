//go:build (linux && !android) || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Test observation files are descendants of an already-created private directory,
// never entries in the install/workspace directories whose ACL is being read.
const macOSControllerFixtureEvents = "fixture-events"

func macOSControllerFixtureEventPath(root, name string) string {
	return filepath.Join(root, macOSControllerFixtureEvents, name)
}

func macOSRuntimeFixtureCleanedPath(root, workspace string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Clean(workspace) != workspace || filepath.Dir(workspace) != filepath.Join(root, "run", "native-node") {
		return "", errors.New("fixture cleanup event lost original validated workspace")
	}
	name := filepath.Base(workspace)
	if !strings.HasPrefix(name, "session-") || len(name) == len("session-") {
		return "", errors.New("fixture cleanup event lost original session basename")
	}
	return macOSControllerFixtureEventPath(root, name+".child-cleaned"), nil
}

// Read exactly the native ownership fields bracketed by OwnedPathACL. Reflection
// only handles the test build's Darwin Ctimespec versus Linux Ctim field name;
// no production ACL or process validation seam is changed.
type macOSFixtureDirectoryRevision struct {
	mode            os.FileMode
	uid, gid, links uint64
	changed         [2]int64
}

func macOSFixtureDirectoryMetadata(path string) (os.FileInfo, macOSFixtureDirectoryRevision, error) {
	var revision macOSFixtureDirectoryRevision
	info, err := os.Lstat(path)
	if err != nil {
		return nil, revision, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, revision, errors.New("fixture metadata has no original directory")
	}
	native := reflect.ValueOf(info.Sys())
	if native.Kind() != reflect.Pointer || native.IsNil() {
		return nil, revision, errors.New("fixture directory has no native stat")
	}
	native = native.Elem()
	changed := native.FieldByName("Ctimespec")
	if !changed.IsValid() {
		changed = native.FieldByName("Ctim")
	}
	uid, gid, links := native.FieldByName("Uid"), native.FieldByName("Gid"), native.FieldByName("Nlink")
	if !changed.IsValid() || !uid.IsValid() || !gid.IsValid() || !links.IsValid() {
		return nil, revision, errors.New("fixture directory has no native ownership metadata")
	}
	revision = macOSFixtureDirectoryRevision{info.Mode(), uid.Uint(), gid.Uint(), links.Uint(), [2]int64{changed.FieldByName("Sec").Int(), changed.FieldByName("Nsec").Int()}}
	return info, revision, nil
}

func TestMacOSOwnedControllerNativeFixtureEventsPreserveCapturedDirectoryMetadata(t *testing.T) {
	root := t.TempDir()
	events := filepath.Join(root, macOSControllerFixtureEvents)
	first, second := filepath.Join(root, "run", "native-node", "session-111"), filepath.Join(root, "run", "native-node", "session-222")
	for _, directory := range []string{events, first, second} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(events)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("events directory is not private", err)
	}
	originalRoot, rootBefore, err := macOSFixtureDirectoryMetadata(root)
	if err != nil {
		t.Fatal(err)
	}
	originalWorkspace, workspaceBefore, err := macOSFixtureDirectoryMetadata(first)
	if err != nil {
		t.Fatal(err)
	}
	originalEvents, eventsBefore, err := macOSFixtureDirectoryMetadata(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fixture-canceled", "fixture-release", "fixture-parent-joined", "fixture-runtime-joined"} {
		if err := os.WriteFile(macOSControllerFixtureEventPath(root, name), []byte("actual fixture event\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cleaned, err := macOSRuntimeFixtureCleanedPath(root, first)
	if err != nil {
		t.Fatal(err)
	}
	other, err := macOSRuntimeFixtureCleanedPath(root, second)
	if err != nil || other == cleaned {
		t.Fatal("cleanup marker borrowed another original workspace", err)
	}
	if err := os.WriteFile(cleaned, []byte("original native cleanup\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("one runtime cleanup claimed another original workspace", err)
	}
	for _, item := range []struct {
		path     string
		info     os.FileInfo
		revision macOSFixtureDirectoryRevision
	}{{root, originalRoot, rootBefore}, {first, originalWorkspace, workspaceBefore}} {
		current, revision, err := macOSFixtureDirectoryMetadata(item.path)
		if err != nil || !os.SameFile(item.info, current) || revision != item.revision {
			t.Fatal("fixture observations changed captured directory ACL metadata", item.path, err)
		}
	}
	current, eventsAfter, err := macOSFixtureDirectoryMetadata(events)
	if err != nil || !os.SameFile(originalEvents, current) || eventsAfter == eventsBefore {
		t.Fatal("actual event writes did not exercise native directory metadata", err)
	}
	for _, invalid := range []string{root, filepath.Join(root, "run", "native-node", "other"), filepath.Join(root, "run", "native-node", "session-"), filepath.Join(root, "run", "foreign", "session-111"), first + "/../session-111"} {
		if _, err := macOSRuntimeFixtureCleanedPath(root, invalid); err == nil {
			t.Fatal("cleanup event accepted another workspace", invalid)
		}
	}
}
