package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
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

func captureTorBridgePrelaunch(a *app, profileID, directory string, captured ...*desktopNodeLaunch) (*torBridgePrelaunch, error) {
	workspace := &desktopNodeLaunch{}
	names := []string{"torrc", "sing-box.json", "tor-data"}
	if len(captured) > 1 {
		return nil, errors.New("Tor prelaunch has competing workspace owners")
	}
	if len(captured) == 1 {
		workspace = captured[0]
		if workspace == nil || workspace.tor == nil || workspace.directoryRoot == nil || workspace.profileID != profileID || workspace.directory != directory {
			return nil, errors.New("Tor prelaunch capture has another node or workspace")
		}
		names = append(append([]string{}, desktopTorInputNames...), "tor-data")
	} else if err := captureDesktopRuntimeDirectory(workspace, directory); err != nil {
		return nil, err
	}
	owner := &torBridgePrelaunch{workspace: workspace, files: make(map[string]os.FileInfo), app: a,
		dns: activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: "external-tor-bridge", Config: filepath.Join(directory, "sing-box.json")}}
	for _, name := range names {
		info, err := workspace.directoryRoot.Lstat(name)
		if err != nil || name == "tor-data" && !info.IsDir() || name != "tor-data" && !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if len(captured) == 0 {
				owner.close()
			}
			return nil, errors.New("Tor prelaunch inputs are missing or have an unowned type")
		}
		owner.files[name] = info
	}
	if err := owner.validate(); err != nil {
		// A supplied capture still belongs to its caller on failure. Keep the
		// retained handle usable for that caller's exact-input cleanup.
		if len(captured) == 0 {
			owner.close()
		}
		return nil, err
	}
	return owner, nil
}

func (owner *torBridgePrelaunch) close() {
	if owner != nil && owner.workspace != nil && owner.workspace.tor != nil && owner.command != nil && owner.command.Process != nil {
		// A started native command retains this same handle until its checked
		// close transaction. Prelaunch must not discard the runtime's identity.
		return
	}
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
	if owner.workspace.tor != nil {
		launch := owner.workspace
		if owner.app == nil || launch.tor.network == "" || launch.tor.network != launch.tor.currentNetworkIdentity() {
			return errors.Join(errTorPrelaunchRejected, errors.New("Tor physical network changed before launch"), owner.cleanup())
		}
		owner.app.mu.Lock()
		profile, found := owner.app.profileByIDLocked(launch.profileID)
		current := found && owner.app.cmd == nil && desktopTorSourceIdentityToken(profile) == launch.tor.profileToken && launch.tor.entryCurrentLocked(owner.app) == nil
		owner.app.mu.Unlock()
		if !current {
			return errors.Join(errTorPrelaunchRejected, errors.New("Tor node or process changed before launch"), owner.cleanup())
		}
		if err := launch.tor.entryCurrent(owner.app); err != nil {
			return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
		}
		launch.command, launch.tor.started = owner.command, time.Now()
		if _, exists := desktopNodeOwners.LoadOrStore(owner.app, launch); exists {
			return errors.Join(errTorPrelaunchRejected, errors.New("another native owner still requires cleanup"), owner.cleanup())
		}
		// Admission itself may race cancellation. The final operation check
		// runs after the native owner is registered and before any child starts.
		if err := check(); err != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, launch)
			return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
		}
		if err := launch.tor.entryCurrent(owner.app); err != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, launch)
			return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
		}
		// Preparation is read-only with respect to the current connection. Its
		// DNS registration transfers only after the prior owner has stopped and
		// this exact native session has passed final admission checks.
		if err := registerActiveDNSRuntimeConfig(owner.app, owner.dns.ProfileID, owner.dns.RuntimeID, owner.dns.Config); err != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, launch)
			return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
		}
	}
	if err := owner.command.Start(); err != nil {
		if owner.workspace.tor != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, owner.workspace)
		}
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
		if owner.workspace.tor != nil && entry.Name() != "tor-data" {
			input, known := owner.workspace.tor.inputs[entry.Name()]
			raw, err := readDesktopRuntimeFile(owner.workspace, entry.Name(), desktopTorInputLimit(entry.Name()))
			if !known || err != nil || desktopTorDigest(raw) != input.digest {
				return errors.New("Tor prelaunch input contents changed after capture")
			}
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
	if owner.workspace.tor != nil {
		if err := cleanupDesktopTorLaunch(owner.workspace); err != nil {
			return err
		}
		activeDNSRuntimeIdentities.CompareAndDelete(owner.app, owner.dns)
		owner.retired = true
		return nil
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
