package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Publish the test child's PID only after its private marker is complete and
// closed. The native parent keeps its exact PID comparison; a file created by
// os.WriteFile at the public name could otherwise be observed before its write.
func desktopNodeProcessNativePublishEntry(directory string, pid int, publish func(string, string) error) error {
	if pid <= 0 || publish == nil {
		return errors.New("native entry publication requires its process and publisher")
	}
	pending, err := os.CreateTemp(directory, ".node-process-entered-*")
	if err != nil {
		return err
	}
	defer os.Remove(pending.Name())
	body := strconv.Itoa(pid)
	written, writeErr := io.WriteString(pending, body)
	if writeErr == nil && written != len(body) {
		writeErr = io.ErrShortWrite
	}
	if err := errors.Join(writeErr, pending.Close()); err != nil {
		return err
	}
	return publish(pending.Name(), filepath.Join(directory, "node-process-entered"))
}

func TestDesktopNodeProcessEntryPublication(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "node-process-entered")
	pid := os.Getpid()
	calls := 0
	err := desktopNodeProcessNativePublishEntry(directory, pid, func(pending, target string) error {
		calls++
		if target != path || pending == target {
			t.Fatal("native entry marker became visible before complete publication")
		}
		if _, err := os.ReadFile(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("native entry marker became visible before complete publication", err)
		}
		body, err := os.ReadFile(pending)
		if err != nil || string(body) != strconv.Itoa(pid) {
			t.Fatal("native entry publication lost its original complete PID", string(body), err)
		}
		return os.Rename(pending, target)
	})
	if err != nil || calls != 1 {
		t.Fatal("native entry publication did not use its one original publisher", calls, err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != strconv.Itoa(pid) {
		t.Fatal("published native entry came from another process", string(body), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "node-process-entered" {
		t.Fatal("native entry publication retained its private marker", entries, err)
	}
}

func TestDesktopNodeProcessEntryPublicationFailureKeepsMarkerAbsent(t *testing.T) {
	directory := t.TempDir()
	refused := errors.New("original publisher refused")
	err := desktopNodeProcessNativePublishEntry(directory, os.Getpid(), func(_, _ string) error { return refused })
	if !errors.Is(err, refused) {
		t.Fatal("native entry publication lost its original refusal", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed native entry publication left a public or private marker", entries, err)
	}
}

func TestDesktopNodeProcessEntryPublicationRejectsInvalidInput(t *testing.T) {
	directory := t.TempDir()
	for _, pid := range []int{0, -1} {
		if err := desktopNodeProcessNativePublishEntry(directory, pid, os.Rename); err == nil {
			t.Fatal("native entry publication accepted an invalid PID", pid)
		}
	}
	if err := desktopNodeProcessNativePublishEntry(directory, os.Getpid(), nil); err == nil {
		t.Fatal("native entry publication accepted a missing publisher")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused native entry publication touched its namespace", entries, err)
	}
}
