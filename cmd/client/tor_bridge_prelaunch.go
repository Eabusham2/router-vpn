package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Before exec.Start the controller owns only prepared input files and an
// empty Tor data directory. The native launcher owns teardown after Start.
type torBridgePrelaunch struct {
	mu        sync.Mutex
	workspace *desktopNodeLaunch
	files     map[string]os.FileInfo
	command   *exec.Cmd
	app       *app
	dns       activeDNSRuntimeIdentity
	retired   bool
}

var errTorPrelaunchRejected = errors.New("captured Tor prelaunch operation was rejected")

func captureTorBridgePrelaunch(a *app, profileID, directory string) (*torBridgePrelaunch, error) {
	workspace := &desktopNodeLaunch{}
	if err := captureDesktopRuntimeDirectory(workspace, directory); err != nil {
		return nil, err
	}
	owner := &torBridgePrelaunch{workspace: workspace, files: make(map[string]os.FileInfo), app: a,
		dns: activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: "external-tor-bridge", Config: filepath.Join(directory, "sing-box.json")}}
	for _, name := range []string{"torrc", "sing-box.json", "tor-data"} {
		info, err := workspace.directoryRoot.Lstat(name)
		if err != nil || name == "tor-data" && !info.IsDir() || name != "tor-data" && !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			owner.close()
			return nil, errors.New("Tor prelaunch inputs are missing or have an unowned type")
		}
		owner.files[name] = info
	}
	if err := owner.validate(); err != nil {
		owner.close()
		return nil, err
	}
	return owner, nil
}

func (owner *torBridgePrelaunch) close() {
	if owner != nil && owner.workspace != nil && owner.workspace.directoryRoot != nil {
		_ = owner.workspace.directoryRoot.Close()
	}
}

// The caller owns its connection transaction. Prelaunch failures retire only
// this unstarted workspace; a successful Start transfers it to native teardown.
func (owner *torBridgePrelaunch) start(check func() error) error {
	if owner == nil {
		return errors.New("Tor launch has no captured prepared workspace")
	}
	defer owner.close()
	if owner.command == nil || check == nil {
		return errors.Join(errors.New("Tor launch has no captured command or operation guard"), owner.cleanup())
	}
	if err := check(); err != nil {
		return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
	}
	if err := owner.validate(); err != nil {
		return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
	}
	if err := owner.command.Start(); err != nil {
		return errors.Join(err, owner.cleanup())
	}
	return nil
}

func (owner *torBridgePrelaunch) validate() error {
	if err := desktopExternalDirectoryCurrent(owner.workspace); err != nil {
		return err
	}
	directory, err := owner.workspace.directoryRoot.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil || len(entries) != len(owner.files) {
		return errors.New("Tor prelaunch workspace contains unowned files")
	}
	for _, entry := range entries {
		expected, known := owner.files[entry.Name()]
		current, err := owner.workspace.directoryRoot.Lstat(entry.Name())
		if !known || err != nil || !os.SameFile(expected, current) || current.Mode()&os.ModeSymlink != 0 {
			return errors.New("Tor prelaunch input was replaced; private workspace retained")
		}
	}
	data, err := owner.workspace.directoryRoot.Open("tor-data")
	if err != nil {
		return err
	}
	entries, err = data.ReadDir(1)
	_ = data.Close()
	if len(entries) != 0 || err != nil && !errors.Is(err, io.EOF) {
		return errors.New("Tor prelaunch data directory is no longer empty; native owner retained")
	}
	return desktopExternalDirectoryCurrent(owner.workspace)
}

func (owner *torBridgePrelaunch) cleanup() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.retired {
		return nil
	}
	if owner.command != nil && owner.command.Process != nil {
		return errors.New("Tor process has started; prelaunch cleanup cannot retire its runtime")
	}
	if err := owner.validate(); err != nil {
		return err
	}
	// Remove only the empty captured directory and the exact captured torrc.
	// Existing native cleanup then removes sing-box.json and the empty parent
	// through the captured handle; it never recursively deletes a pathname.
	for _, name := range []string{"tor-data", "torrc"} {
		if err := desktopExternalDirectoryCurrent(owner.workspace); err != nil {
			return err
		}
		current, err := owner.workspace.directoryRoot.Lstat(name)
		if err != nil || !os.SameFile(owner.files[name], current) || current.Mode()&os.ModeSymlink != 0 {
			return errors.New("Tor prelaunch input changed before retirement")
		}
		if err := owner.workspace.directoryRoot.Remove(name); err != nil {
			return err
		}
	}
	if err := cleanupDesktopNodeLaunch(owner.workspace); err != nil {
		return err
	}
	activeDNSRuntimeIdentities.CompareAndDelete(owner.app, owner.dns)
	owner.retired = true
	return nil
}
