package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Keep a directory handle as well as its pathname. A superseding session or a
// renamed directory must never redirect a proof read, stop request or cleanup.
func captureDesktopRuntimeDirectory(launch *desktopNodeLaunch, directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("native runtime workspace is not a private directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return errors.New("native runtime workspace changed while being captured")
	}
	launch.directory, launch.directoryInfo, launch.directoryRoot = directory, info, root
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		_ = root.Close()
		return err
	}
	return nil
}

func desktopExternalDirectoryCurrent(launch *desktopNodeLaunch) error {
	if launch == nil || launch.directoryInfo == nil || launch.directoryRoot == nil {
		return errors.New("native runtime has no captured private workspace identity")
	}
	current, err := os.Lstat(launch.directory)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, launch.directoryInfo) {
		return errors.New("native runtime workspace was replaced; refusing another owner's files")
	}
	opened, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(opened, launch.directoryInfo) {
		return errors.New("native runtime workspace handle is no longer owned")
	}
	return nil
}

func desktopRuntimeFilename(name string) bool {
	return name != "" && filepath.Base(name) == name && name != "." && name != ".."
}

// Heartbeats are atomically replaced by the native owner. Read one complete
// opened record; a newer record may replace its name while this read finishes.
// The opened file must still be the private regular file inspected before open.
func readDesktopRuntimeFile(launch *desktopNodeLaunch, name string, limit int64) ([]byte, error) {
	if launch == nil {
		return nil, errors.New("native runtime record has no captured owner")
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if !desktopRuntimeFilename(name) || limit <= 0 {
		return nil, errors.New("invalid native runtime record")
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		body, err := readDesktopRuntimeSnapshot(launch.directoryRoot, name, limit)
		if errors.Is(err, errDesktopRuntimeSnapshotChanged) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err = desktopExternalDirectoryCurrent(launch); err != nil {
			return nil, err
		}
		return body, nil
	}
	return nil, errDesktopRuntimeSnapshotChanged
}

var errDesktopRuntimeSnapshotChanged = errors.New("native runtime record changed while opening")

func readDesktopRuntimeSnapshot(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("native runtime record is not a bounded private file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errDesktopRuntimeSnapshotChanged
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(body) == 0 || int64(len(body)) > limit || int64(len(body)) != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("native runtime record changed while reading")
	}
	return body, nil
}

// Initial inputs and stop requests are immutable. O_EXCL prevents truncating a
// replacement owner's file; retries may only accept the exact existing bytes.
// The CLI ignores a not-yet-complete stop JSON record until this write finishes.
func writeDesktopRuntimeFile(launch *desktopNodeLaunch, name string, data []byte, retry bool) error {
	if launch == nil || !desktopRuntimeFilename(name) || len(data) == 0 || len(data) > 8<<20 {
		return errors.New("invalid native runtime input")
	}
	launch.workspaceMu.Lock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		launch.workspaceMu.Unlock()
		return err
	}
	file, err := launch.directoryRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		launch.workspaceMu.Unlock()
		if retry && errors.Is(err, os.ErrExist) {
			body, readErr := readDesktopRuntimeFile(launch, name, int64(len(data)))
			if readErr == nil && bytes.Equal(data, body) {
				return nil
			}
			return errors.New("native runtime request already has another owner or contents")
		}
		return err
	}
	info, err := file.Stat()
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	current, statErr := launch.directoryRoot.Lstat(name)
	if err == nil && (closeErr != nil || statErr != nil || info == nil || !os.SameFile(info, current) || current.Size() != int64(len(data))) {
		err = errors.New("native runtime input changed during publication")
	}
	if err == nil {
		err = desktopExternalDirectoryCurrent(launch)
	}
	launch.workspaceMu.Unlock()
	if err != nil {
		return err
	}
	body, err := readDesktopRuntimeFile(launch, name, int64(len(data)))
	if err != nil || !bytes.Equal(data, body) {
		return errors.New("native runtime input did not retain its captured contents")
	}
	return nil
}

func desktopRuntimeOwnedFile(name string) bool {
	switch name {
	case "sing-box.json", "source.json", "capture.json", "proof.json", "progress.json", "stop.json", "stopped.json", "native-multihop.process.json",
		".proof.json.pending", ".progress.json.pending", ".stopped.json.pending", "mtu-request.json", "mtu-commit.json", "mtu-cancel.json", "mtu-status.json", ".mtu-status.json.pending",
		"path-request.json", "path-cancel.json", "path-status.json", ".path-status.json.pending",
		"node-mtu-request.json", "node-mtu-status.json", ".node-mtu-status.json.pending":
		return true
	}
	return false
}

// Used after the exact process has drained (or before it ever started). File
// removals are relative to the captured handle. No recursive pathname deletion
// is permitted, and unknown files are retained for explicit recovery.
func cleanupDesktopNodeLaunch(launch *desktopNodeLaunch) error {
	if launch == nil || launch.directory == "" {
		return nil
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	directory, err := launch.directoryRoot.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, e := launch.directoryRoot.Lstat(entry.Name())
		if e != nil || !desktopRuntimeOwnedFile(entry.Name()) || !info.Mode().IsRegular() {
			return errors.New("native workspace contains unowned files; captured workspace retained")
		}
	}
	for _, entry := range entries {
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			return err
		}
		if err := launch.directoryRoot.Remove(entry.Name()); err != nil {
			return err
		}
	}
	// The parent is opened before checking the child again; removal cannot be
	// redirected through a renamed parent or a substituted parent symlink.
	parent, err := os.OpenRoot(filepath.Dir(launch.directory))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(launch.directory)
	info, err := parent.Lstat(name)
	if err != nil || !os.SameFile(info, launch.directoryInfo) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native workspace changed before final retirement")
	}
	if err = desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	if err = parent.Remove(name); err != nil { // Only an empty directory; never replacement contents.
		return err
	}
	return launch.directoryRoot.Close()
}
