package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
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
	return captureTorBridgePrelaunchContext(context.Background(), a, profileID, directory, captured...)
}

func captureTorBridgePrelaunchContext(ctx context.Context, a *app, profileID, directory string, captured ...*desktopNodeLaunch) (*torBridgePrelaunch, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("Tor prelaunch capture has no live original caller")
	}
	workspace := &desktopNodeLaunch{}
	names := []string{"torrc", "sing-box.json", "tor-data"}
	if len(captured) > 1 {
		return nil, errors.New("Tor prelaunch has competing workspace owners")
	}
	if len(captured) == 1 {
		workspace = captured[0]
		if workspace == nil || workspace.tor == nil || workspace.directoryRoot == nil || workspace.profileID != profileID || workspace.directory != directory || !desktopTorRuntimeID(workspace.mode) {
			return nil, errors.New("Tor prelaunch capture has another node or workspace")
		}
		names = append(append([]string{}, desktopTorInputNames...), "tor-data")
	} else if err := captureDesktopRuntimeDirectory(workspace, directory); err != nil {
		return nil, err
	}
	runtimeID := "external-tor-bridge"
	if workspace.tor != nil {
		runtimeID = workspace.mode
	}
	owner := &torBridgePrelaunch{workspace: workspace, files: make(map[string]os.FileInfo), app: a,
		dns: activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: filepath.Join(directory, "sing-box.json")}}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			if len(captured) == 0 {
				owner.close()
			}
			return nil, err
		}
		info, err := workspace.directoryRoot.Lstat(name)
		if err != nil || name == "tor-data" && !info.IsDir() || name != "tor-data" && !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if len(captured) == 0 {
				owner.close()
			}
			return nil, errors.New("Tor prelaunch inputs are missing or have an unowned type")
		}
		owner.files[name] = info
	}
	if err := owner.validateContext(ctx); err != nil {
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
	operation := context.Background()
	if owner != nil && owner.app != nil {
		operation = owner.app.connectionOperationContextOrBackground()
	}
	return owner.startContext(operation, check)
}
func (owner *torBridgePrelaunch) startContext(operation context.Context, check func() error) error {
	if owner == nil {
		return errors.New("Tor launch has no captured prepared workspace")
	}
	defer owner.close()
	if owner.command == nil || check == nil {
		return errors.Join(errors.New("Tor launch has no captured command or operation guard"), owner.cleanup())
	}
	if operation == nil {
		return errors.Join(errTorPrelaunchRejected, errors.New("Tor launch has no live original caller"), owner.cleanup())
	}
	if err := operation.Err(); err != nil {
		return errors.Join(errTorPrelaunchRejected, errConnectionOperationCancelled, err, owner.cleanup())
	}
	if err := check(); err != nil {
		return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
	}
	if err := owner.validateContext(operation); err != nil {
		return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
	}
	if owner.workspace.tor != nil {
		launch := owner.workspace
		network, networkErr := launch.tor.currentNetworkIdentityContext(operation)
		if owner.app == nil || networkErr != nil || launch.tor.network == "" || launch.tor.network != network {
			return errors.Join(errTorPrelaunchRejected, errors.New("Tor physical network changed before launch"), owner.cleanup())
		}
		if err := desktopnetwork.LockContext(operation, &owner.app.mu); err != nil {
			return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
		}
		profile, found := owner.app.profileByIDLocked(launch.profileID)
		current := found && owner.app.cmd == nil && desktopTorSourceIdentityToken(profile) == launch.tor.profileToken && launch.tor.entryCurrentLocked(owner.app) == nil
		owner.app.mu.Unlock()
		if !current {
			return errors.Join(errTorPrelaunchRejected, errors.New("Tor node or process changed before launch"), owner.cleanup())
		}
		if err := launch.tor.entryCurrentContext(operation, owner.app); err != nil {
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
		if err := launch.tor.entryCurrentContext(operation, owner.app); err != nil {
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
	if owner.workspace.tor != nil {
		startup, err := captureDesktopNativeStartup(operation, owner.workspace)
		if err == nil {
			owner.command.Env, err = desktopNativeStartupEnvironment(startup, owner.workspace, owner.command.Env)
		}
		if err != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, owner.workspace)
			return errors.Join(err, owner.cleanup())
		}
	}
	finalErr := operation.Err()
	if finalErr == nil {
		finalErr = check()
	}
	if err := errors.Join(finalErr, operation.Err()); err != nil {
		if owner.workspace.tor != nil {
			desktopNodeOwners.CompareAndDelete(owner.app, owner.workspace)
		}
		return errors.Join(errTorPrelaunchRejected, err, owner.cleanup())
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
	return owner.validateContext(context.Background())
}

func (owner *torBridgePrelaunch) validateContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Tor prelaunch validation has no live original caller")
	}
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
		if err := ctx.Err(); err != nil {
			return err
		}
		expected, known := owner.files[entry.Name()]
		current, err := owner.workspace.directoryRoot.Lstat(entry.Name())
		if !known || err != nil || !os.SameFile(expected, current) || current.Mode()&os.ModeSymlink != 0 {
			return errors.New("Tor prelaunch input was replaced; private workspace retained")
		}
		if owner.workspace.tor != nil && entry.Name() != "tor-data" {
			input, known := owner.workspace.tor.inputs[entry.Name()]
			raw, err := readDesktopRuntimeFileContext(ctx, owner.workspace, entry.Name(), desktopTorInputLimit(entry.Name()))
			if !known || err != nil || desktopTorDigest(raw) != input.digest {
				return errors.Join(err, errors.New("Tor prelaunch input contents changed after capture"))
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
	return errors.Join(desktopExternalDirectoryCurrent(owner.workspace), ctx.Err())
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
