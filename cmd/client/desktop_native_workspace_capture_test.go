package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func desktopWorkspaceCaptureFixture(t *testing.T) *desktopNodeLaunch {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "captured")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	return launch
}

func TestDesktopRuntimeWorkspaceRemovalKeepsCapturedHandleOpen(t *testing.T) {
	launch := desktopWorkspaceCaptureFixture(t)
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		t.Fatal("captured workspace lost its live ownership guard", err)
	}
	parent, err := os.OpenRoot(filepath.Dir(launch.directory))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	// Keep the actual captured child handle open across removal. On Windows
	// this fails with the old os.OpenRoot(directory) capture because its handle
	// does not share deletion. No early close or sharing-error skip is allowed.
	held, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(held, launch.directoryInfo) {
		t.Fatal("workspace handle was closed or changed before removal", err)
	}
	if err := parent.Remove(filepath.Base(launch.directory)); err != nil {
		t.Fatal("owned empty workspace cannot be removed while its identity handle remains open", err)
	}
	if err := launch.directoryRoot.Close(); err != nil {
		t.Fatal("retained workspace handle did not close after removal", err)
	}
	if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned workspace remained after removal and handle close", err)
	}
}

func TestDesktopRuntimeWorkspaceProductionCleanupClosesCapturedHandle(t *testing.T) {
	launch := desktopWorkspaceCaptureFixture(t)
	for _, name := range []string{"source.json", "stop.json", "stopped.json"} {
		if err := writeDesktopRuntimeFile(launch, name, []byte(`{"schema":1}`), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		t.Fatal("cleanup started without a live captured workspace", err)
	}
	if err := cleanupDesktopNodeLaunch(launch); err != nil {
		t.Fatal("production cleanup did not retire its owned files and directory", err)
	}
	if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("production cleanup left its private workspace", err)
	}
	if _, err := launch.directoryRoot.Stat("."); err == nil {
		t.Fatal("production cleanup retained an open directory handle")
	}
}

func TestDesktopRuntimeWorkspaceUnknownFileRetainsFilesAndHandle(t *testing.T) {
	launch := desktopWorkspaceCaptureFixture(t)
	owned := []byte(`{"schema":1,"owner":"captured"}`)
	foreign := []byte("retain the unrelated file")
	if err := writeDesktopRuntimeFile(launch, "source.json", owned, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(launch.directory, "unrelated.txt"), foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDesktopNodeLaunch(launch); err == nil {
		t.Fatal("cleanup accepted a workspace containing an unowned file")
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		t.Fatal("rejected cleanup discarded the captured directory handle", err)
	}
	for name, want := range map[string][]byte{"source.json": owned, "unrelated.txt": foreign} {
		actual, err := os.ReadFile(filepath.Join(launch.directory, name))
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatal("rejected cleanup removed or changed workspace contents", name, err)
		}
	}
	// The same retained owner may retry only after the explicitly removed
	// unrelated file is gone; rejection did not silently transfer ownership.
	if err := launch.directoryRoot.Remove("unrelated.txt"); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDesktopNodeLaunch(launch); err != nil {
		t.Fatal("retained captured owner could not complete cleanup", err)
	}
	if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful cleanup retry retained the workspace", err)
	}
}

func TestDesktopRuntimeWorkspaceCaptureRetainsIdentityAcrossParentClose(t *testing.T) {
	launch := desktopWorkspaceCaptureFixture(t)
	// captureDesktopRuntimeDirectory has returned and closed its temporary
	// parent. The independently retained child must still read and write its
	// exact workspace; it must not depend on the temporary parent's lifetime.
	content := []byte(`{"schema":1,"owner":"child"}`)
	if err := writeDesktopRuntimeFile(launch, "stop.json", content, false); err != nil {
		t.Fatal("closing the capture parent invalidated its child", err)
	}
	actual, err := readDesktopRuntimeFile(launch, "stop.json", 1024)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("captured child lost its own file identity", err)
	}
	if err := cleanupDesktopNodeLaunch(launch); err != nil {
		t.Fatal(err)
	}
}
