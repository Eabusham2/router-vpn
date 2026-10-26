package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// These IPC peers represent the separately built native process. Its output
// publisher uses Root.Rename, whose Windows replacement semantics preserve
// an already opened controller snapshot. The controller's ordinary private
// store uses path-based Rename and is not a substitute for that native writer.
// Keep real file ownership and failures in the fixture, without retrying or
// suppressing a failed publication.
type desktopNativeFixturePublisher struct {
	directory string
	info      os.FileInfo
	root      *os.Root
	owned     map[string]os.FileInfo
}

func newDesktopNativeFixturePublisher(directory string) (*desktopNativeFixturePublisher, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("isolated native publisher needs a private directory")
	}
	parent, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	root, err := parent.OpenRoot(filepath.Base(directory))
	if err != nil {
		return nil, err
	}
	publisher := &desktopNativeFixturePublisher{directory: directory, info: info, root: root, owned: make(map[string]os.FileInfo)}
	if err := publisher.currentDirectory(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return publisher, nil
}

func (publisher *desktopNativeFixturePublisher) currentDirectory() error {
	current, err := os.Lstat(publisher.directory)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(publisher.info, current) {
		return errors.New("isolated native publisher directory was replaced")
	}
	opened, err := publisher.root.Stat(".")
	if err != nil || !os.SameFile(publisher.info, opened) {
		return errors.New("isolated native publisher lost its captured directory")
	}
	return nil
}

func (publisher *desktopNativeFixturePublisher) current(name string) bool {
	info, err := publisher.root.Lstat(name)
	owned := publisher.owned[name]
	return owned == nil && errors.Is(err, os.ErrNotExist) || owned != nil && err == nil && info.Mode().IsRegular() && os.SameFile(owned, info)
}

func (publisher *desktopNativeFixturePublisher) publish(name string, raw []byte) error {
	if !desktopRuntimeFilename(name) || len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("isolated native publisher needs a bounded basename record")
	}
	if err := publisher.currentDirectory(); err != nil {
		return err
	}
	if !publisher.current(name) {
		return errors.New("isolated native publisher output belongs to another owner")
	}
	temporary := "." + name + ".pending"
	file, err := publisher.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	defer func() {
		if actual, e := publisher.root.Lstat(temporary); e == nil && info != nil && os.SameFile(info, actual) {
			_ = publisher.root.Remove(temporary)
		}
	}()
	if err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := publisher.currentDirectory(); err != nil {
		return err
	}
	if !publisher.current(name) {
		return errors.New("isolated native publisher output changed before replacement")
	}
	if err := desktopNativeFixtureRename(publisher.root, temporary, name); err != nil {
		return err
	}
	actual, err := publisher.root.Lstat(name)
	if err != nil || !os.SameFile(info, actual) {
		return errors.New("isolated native publisher replacement lost its file identity")
	}
	publisher.owned[name] = actual
	return nil
}

func TestDesktopRuntimeWorkspacePublisherReplacesWhileSnapshotIsOpen(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	publisher, err := newDesktopNativeFixturePublisher(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.root.Close()
	for generation := 0; generation < 8; generation++ {
		name := "proof.json"
		old := []byte(fmt.Sprintf(`{"generation":%d}`, generation))
		if err := publisher.publish(name, old); err != nil {
			t.Fatal("initial captured publication", err)
		}
		snapshot, err := publisher.root.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		// The file stays open throughout replacement, just as the real reader
		// retains its snapshot handle while validating an atomic heartbeat.
		fresh := []byte(fmt.Sprintf(`{"generation":%d,"new":true}`, generation))
		if runtime.GOOS == "windows" && generation == 0 {
			// Reproduce the observed kernel boundary, independently of timing:
			// MoveFileEx-backed path Rename cannot replace this open snapshot.
			legacy := filepath.Join(directory, ".proof.json.legacy")
			if err := os.WriteFile(legacy, fresh, 0600); err != nil {
				_ = snapshot.Close()
				t.Fatal(err)
			}
			legacyErr := os.Rename(legacy, filepath.Join(directory, name))
			if !errors.Is(legacyErr, syscall.Errno(5)) && !errors.Is(legacyErr, syscall.Errno(32)) {
				_ = snapshot.Close()
				t.Fatalf("legacy Windows publisher did not reproduce access/sharing denial with the retained snapshot: %v", legacyErr)
			}
			if err := os.Remove(legacy); err != nil {
				_ = snapshot.Close()
				t.Fatal(err)
			}
		}
		publishErr := publisher.publish(name, fresh)
		retained, readErr := io.ReadAll(snapshot)
		closeErr := snapshot.Close()
		if publishErr != nil || readErr != nil || closeErr != nil || string(retained) != string(old) {
			t.Fatalf("captured native replacement failed or changed the held snapshot: publish=%v read=%v close=%v old=%q", publishErr, readErr, closeErr, retained)
		}
		current, err := readDesktopRuntimeSnapshot(publisher.root, name, 64<<10)
		if err != nil || string(current) != string(fresh) {
			t.Fatal("new snapshot did not contain the complete replacement", string(current), err)
		}
	}
}

func TestDesktopRuntimeWorkspacePublisherRejectsForeignOutputsAndPaths(t *testing.T) {
	for _, kind := range []string{"existing", "replacement", "directory", "pending", "parent", "empty", "oversized", "renamed"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "runtime")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			publisher, err := newDesktopNativeFixturePublisher(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.root.Close()
			name, raw := "proof.json", []byte(`{"owned":true}`)
			foreign := []byte("foreign-owner")
			switch kind {
			case "existing":
				err = os.WriteFile(filepath.Join(directory, name), foreign, 0600)
			case "replacement":
				if err = publisher.publish(name, raw); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(filepath.Join(directory, name), filepath.Join(directory, "old.json")); err == nil {
					err = os.WriteFile(filepath.Join(directory, name), foreign, 0600)
				}
			case "directory":
				err = os.Mkdir(filepath.Join(directory, name), 0700)
			case "pending":
				err = os.WriteFile(filepath.Join(directory, "."+name+".pending"), foreign, 0600)
			case "parent":
				name = "../proof.json"
			case "empty":
				raw = nil
			case "oversized":
				raw = make([]byte, (64<<10)+1)
			case "renamed":
				if err = os.Rename(directory, directory+"-retired"); err == nil {
					err = os.Mkdir(directory, 0700)
				}
			}
			if err != nil {
				t.Fatal("fixture setup", err)
			}
			if err := publisher.publish(name, raw); err == nil {
				t.Fatal("isolated native publisher accepted foreign output or path", kind)
			}
			if kind == "existing" || kind == "replacement" || kind == "pending" {
				if kind == "pending" {
					name = "." + name + ".pending"
				}
				actual, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil || string(actual) != string(foreign) {
					t.Fatal("foreign publisher output changed", string(actual), err)
				}
			}
		})
	}
}
