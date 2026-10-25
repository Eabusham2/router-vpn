package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"router-vpn/internal/mobiletor"
)

// The controller retains the native Tor owner until its exact native process,
// standalone Tor child, PT workers and TUN have drained. A process exit alone
// cannot release private inputs or the client's protection policy.
type desktopTorRuntime struct {
	mu               sync.Mutex
	expected         mobiletor.DesktopBridgeMetadata
	digests          mobiletor.DesktopBridgeInputDigests
	profileToken     string
	network          string
	networkIdentity  func() string
	started          time.Time
	adopted          *desktopTorProof
	stopAcknowledged bool
	inputs           map[string]desktopTorInput
	dataInfo         os.FileInfo
}

type desktopTorInput struct {
	info   os.FileInfo
	digest string
}

type desktopTorProof struct {
	Schema         int                             `json:"schema"`
	SessionID      string                          `json:"session_id"`
	SourceSHA256   string                          `json:"source_sha256"`
	ConfigSHA256   string                          `json:"config_sha256"`
	Policy         mobiletor.DesktopBridgeMetadata `json:"policy"`
	Proof          mobiletor.Proof                 `json:"proof"`
	InterfaceName  string                          `json:"interface_name"`
	InterfaceIndex int                             `json:"interface_index"`
	EffectiveMTU   int                             `json:"effective_mtu"`
	Healthy        bool                            `json:"healthy"`
	HeartbeatAt    int64                           `json:"heartbeat_at"`
}

type desktopTorProgress struct {
	Schema       int    `json:"schema"`
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Stage        string `json:"stage"`
}

func (owner *desktopTorRuntime) currentNetworkIdentity() string {
	if owner != nil && owner.networkIdentity != nil {
		return owner.networkIdentity()
	}
	return physicalNetworkIdentity()
}

func desktopTorDigest(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func validateDesktopTorProof(raw []byte, owner *desktopTorRuntime, now time.Time) (desktopTorProof, error) {
	var proof desktopTorProof
	bad := errors.New("native Tor proof is stale or differs from its captured policy, process or path")
	if owner == nil || len(raw) == 0 || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &proof) != nil {
		return proof, bad
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	expected := owner.expected
	if proof.Schema != 1 || !proof.Healthy || proof.Policy != expected || proof.SessionID != expected.SessionID || proof.SourceSHA256 != expected.SourceSHA256 || proof.ConfigSHA256 != expected.ConfigSHA256 || proof.Proof.SessionID != expected.SessionID || !proof.Proof.IsTor || !proof.Proof.DNSProven || owner.started.IsZero() || proof.Proof.CheckedAt.Before(owner.started.Add(-time.Second)) || proof.Proof.CheckedAt.After(now.Add(time.Second)) || proof.HeartbeatAt < now.Add(-3*time.Second).UnixMilli() || proof.HeartbeatAt > now.Add(time.Second).UnixMilli() || proof.HeartbeatAt < proof.Proof.CheckedAt.UnixMilli() {
		return proof, bad
	}
	if ip, err := publicTorExit(proof.Proof.IP); err != nil || ip != proof.Proof.IP {
		return proof, bad
	}
	if proof.InterfaceIndex <= 0 || proof.InterfaceName == "" || len(proof.InterfaceName) > 64 || proof.EffectiveMTU < 1280 || proof.EffectiveMTU > 9000 || proof.EffectiveMTU != expected.ConfiguredMTU || expected.InterfaceName != "" && proof.InterfaceName != expected.InterfaceName {
		return proof, bad
	}
	for _, r := range proof.InterfaceName {
		if r <= 0x20 || r == 0x7f {
			return proof, bad
		}
	}
	if adopted := owner.adopted; adopted != nil && (proof.Proof.SessionID != adopted.Proof.SessionID || proof.Proof.IP != adopted.Proof.IP || !proof.Proof.CheckedAt.Equal(adopted.Proof.CheckedAt) || proof.InterfaceName != adopted.InterfaceName || proof.InterfaceIndex != adopted.InterfaceIndex || proof.EffectiveMTU != adopted.EffectiveMTU) {
		return proof, bad
	}
	return proof, nil
}

func (a *app) desktopTorCurrent(launch *desktopNodeLaunch) error {
	if launch == nil || launch.tor == nil || launch.command == nil || launch.command.Process == nil {
		return errors.New("Tor has no captured native process")
	}
	if raw, found := desktopNodeOwners.Load(a); !found || raw != launch {
		return errors.New("Tor native owner was replaced")
	}
	owner := launch.tor
	if owner.network == "" || owner.network != owner.currentNetworkIdentity() {
		return errors.New("Tor proof belongs to a retired physical network")
	}
	a.mu.Lock()
	current, found := a.profileByIDLocked(launch.profileID)
	valid := a.cmd == launch.command && found && owner.profileToken != "" && asyncMeasurementProfileToken(current) == owner.profileToken
	a.mu.Unlock()
	if !valid {
		return errors.New("Tor native session or captured private node changed")
	}
	if desktopNodeProcessExited(launch) {
		return errors.New("Tor native process exited before its proof could be retained")
	}
	return desktopExternalDirectoryCurrent(launch)
}

func (a *app) readDesktopTorProof(launch *desktopNodeLaunch) (desktopTorProof, error) {
	if err := a.desktopTorCurrent(launch); err != nil {
		return desktopTorProof{}, err
	}
	raw, err := readDesktopRuntimeFile(launch, "proof.json", 64<<10)
	if err != nil {
		return desktopTorProof{}, err
	}
	proof, err := validateDesktopTorProof(raw, launch.tor, time.Now())
	if err == nil {
		err = a.desktopTorCurrent(launch)
	}
	return proof, err
}

func (a *app) readDesktopTorProgress(launch *desktopNodeLaunch) error {
	if err := a.desktopTorCurrent(launch); err != nil {
		return err
	}
	raw, err := readDesktopRuntimeFile(launch, "progress.json", 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var progress desktopTorProgress
	expected := launch.tor.expected
	if decodeRelayControlJSON(raw, &progress) != nil || progress.Schema != 1 || progress.SessionID != expected.SessionID || progress.SourceSHA256 != expected.SourceSHA256 || progress.ConfigSHA256 != expected.ConfigSHA256 {
		return errors.New("Tor progress belongs to another native capture")
	}
	switch progress.Stage {
	case "starting", "authenticating", "starting-tun", "starting-transports", "bootstrapping", "proving", "connected", "stopping", "cleanup-pending", "closed":
	default:
		return errors.New("Tor progress has an unowned lifecycle stage")
	}
	if err := a.desktopTorCurrent(launch); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cmd != launch.command {
		return errors.New("Tor progress completed for a replacement connection")
	}
	if !a.state.Connected {
		a.state.Phase = "tor-bridge:" + progress.Stage
	}
	return nil
}

func (a *app) waitDesktopTorProof(ctx context.Context, launch *desktopNodeLaunch) (desktopTorProof, error) {
	if ctx == nil {
		return desktopTorProof{}, errors.New("Tor proof has no captured operation context")
	}
	deadline, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := deadline.Err(); err != nil {
			return desktopTorProof{}, err
		}
		if err := a.readDesktopTorProgress(launch); err != nil {
			return desktopTorProof{}, err
		}
		proof, err := a.readDesktopTorProof(launch)
		if err == nil {
			if err := deadline.Err(); err != nil {
				return desktopTorProof{}, err
			}
			if err := a.desktopTorCurrent(launch); err != nil {
				return desktopTorProof{}, err
			}
			launch.tor.mu.Lock()
			captured := proof
			launch.tor.adopted = &captured
			launch.tor.mu.Unlock()
			return proof, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return desktopTorProof{}, err
		}
		select {
		case <-deadline.Done():
			return desktopTorProof{}, deadline.Err()
		case <-ticker.C:
		case <-desktopNodeProcessDone(launch):
			return desktopTorProof{}, errors.New("Tor native startup exited before its captured path was proved")
		}
	}
}

func desktopTorStopped(launch *desktopNodeLaunch) (bool, error) {
	raw, err := readDesktopRuntimeFile(launch, "stopped.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record desktopExternalStop
	expected := launch.tor.expected
	if decodeRelayControlJSON(raw, &record) != nil || record.Schema != 1 || !record.Closed || record.SessionID != expected.SessionID || record.SourceSHA256 != expected.SourceSHA256 {
		return false, errors.New("Tor drain acknowledgement belongs to another native session")
	}
	launch.tor.mu.Lock()
	launch.tor.stopAcknowledged = true
	launch.tor.mu.Unlock()
	return true, nil
}

func desktopTorStopOwner(a *app, launch *desktopNodeLaunch, command *exec.Cmd) error {
	if launch == nil || launch.tor == nil || launch.command == nil || command != nil && command != launch.command {
		return errors.New("Tor teardown has no captured process owner")
	}
	if raw, found := desktopNodeOwners.Load(a); !found || raw != launch {
		return errors.New("Tor teardown owner changed before drain")
	}
	a.mu.Lock()
	matches := a.cmd == nil || a.cmd == launch.command
	a.mu.Unlock()
	if !matches {
		return errors.New("Tor teardown cannot change a replacement connection")
	}
	return nil
}

func prepareDesktopTorStop(a *app, command *exec.Cmd) error {
	raw, found := desktopNodeOwners.Load(a)
	if !found {
		return nil
	}
	launch, ok := raw.(*desktopNodeLaunch)
	if !ok || launch == nil || launch.tor == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return requestDesktopTorStop(ctx, a, launch, command)
}

func requestDesktopTorStop(ctx context.Context, a *app, launch *desktopNodeLaunch, command *exec.Cmd) error {
	if ctx == nil {
		return errors.New("Tor teardown requires a bounded context")
	}
	if err := desktopTorStopOwner(a, launch, command); err != nil {
		return err
	}
	owner := launch.tor
	owner.mu.Lock()
	acknowledged := owner.stopAcknowledged
	owner.mu.Unlock()
	if acknowledged && desktopNodeProcessExited(launch) {
		if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := desktopTorStopped(launch); err != nil {
		return err
	}
	request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: owner.expected.SessionID, SourceSHA256: owner.expected.SourceSHA256})
	if err := writeDesktopRuntimeFile(launch, "stop.json", request, true); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := desktopTorStopOwner(a, launch, command); err != nil {
			return err
		}
		closed, err := desktopTorStopped(launch)
		if err != nil {
			return err
		}
		exited := desktopNodeProcessExited(launch)
		if closed && exited {
			return desktopTorStopOwner(a, launch, command)
		}
		if exited {
			return errors.New("Tor native process exited without checked drain; protection and private ownership retained")
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("Tor native drain is still pending; protection and private ownership retained"), ctx.Err())
		case <-ticker.C:
		case <-desktopNodeProcessDone(launch):
		}
	}
}

func stopDesktopTorRuntime(a *app, launch *desktopNodeLaunch, command *exec.Cmd) error {
	if err := desktopTorStopOwner(a, launch, command); err != nil {
		return err
	}
	launch.tor.mu.Lock()
	acknowledged := launch.tor.stopAcknowledged
	launch.tor.mu.Unlock()
	if !acknowledged || !desktopNodeProcessExited(launch) {
		return errors.New("Tor cleanup requires its checked native drain and joined process")
	}
	if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return cleanupDesktopTorLaunch(launch)
}

func desktopTorMailbox(name string) bool {
	switch name {
	case "proof.json", "progress.json", "stop.json", "stopped.json", ".proof.json.pending", ".progress.json.pending", ".stopped.json.pending":
		return true
	}
	return false
}

// Only the exact captured immutable inputs, empty captured Tor data directory
// and bounded native mailboxes may be removed after drain. The native child
// owns removal of its control cookie/port and data files before acknowledging.
func cleanupDesktopTorLaunch(launch *desktopNodeLaunch) error {
	if launch == nil || launch.tor == nil {
		return errors.New("Tor cleanup has no captured workspace")
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	root := launch.directoryRoot
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(64)
	_ = directory.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 32 {
		return errors.New("Tor cleanup has an unbounded workspace")
	}
	observed := map[string]os.FileInfo{}
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Tor cleanup encountered a replaced input")
		}
		if name == "tor-data" {
			if launch.tor.dataInfo == nil || !info.IsDir() || !os.SameFile(info, launch.tor.dataInfo) {
				return errors.New("Tor data directory has another owner")
			}
			data, err := root.Open("tor-data")
			if err != nil {
				return err
			}
			actual, statErr := data.Stat()
			contents, readErr := data.ReadDir(1)
			_ = data.Close()
			if statErr != nil || !os.SameFile(info, actual) || len(contents) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
				return errors.New("Tor data directory has not drained")
			}
		} else {
			if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
				return errors.New("Tor workspace contains an unowned file type")
			}
			if input, ok := launch.tor.inputs[name]; ok {
				if input.info == nil || !os.SameFile(info, input.info) {
					return errors.New("Tor immutable input was replaced")
				}
				raw, err := readDesktopRuntimeSnapshot(root, name, 4<<20)
				if err != nil || desktopTorDigest(raw) != input.digest {
					return errors.New("Tor immutable input contents changed")
				}
			} else if !desktopTorMailbox(name) || info.Size() > 64<<10 {
				return errors.New("Tor workspace contains unowned files; cleanup remains pending")
			}
		}
		observed[name] = info
	}
	for _, entry := range entries {
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			return err
		}
		current, err := root.Lstat(entry.Name())
		if err != nil || !os.SameFile(observed[entry.Name()], current) || current.Mode()&os.ModeSymlink != 0 {
			return errors.New("Tor workspace changed during retirement")
		}
		if err := root.Remove(entry.Name()); err != nil {
			return err
		}
	}
	parent, err := os.OpenRoot(filepath.Dir(launch.directory))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(launch.directory)
	current, err := parent.Lstat(name)
	if err != nil || !os.SameFile(current, launch.directoryInfo) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
		return errors.New("Tor workspace changed before final retirement")
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	if err := parent.Remove(name); err != nil {
		return err
	}
	return root.Close()
}

func (a *app) monitorDesktopTorRuntime(launch *desktopNodeLaunch) {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if !a.ownsConnectionRuntime(launch.command) {
				return
			}
			if _, err := a.readDesktopTorProof(launch); err == nil {
				continue
			}
			if !a.operationMu.TryLock() {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				a.operationMu.Unlock()
				return
			}
			if _, err := a.readDesktopTorProof(launch); err == nil {
				a.operationMu.Unlock()
				continue
			}
			err := a.stopModeWithIntent(true)
			message := "Tor native proof or physical network retired; protection is held"
			if err != nil {
				message += "; " + err.Error()
			}
			a.mu.Lock()
			a.state.Connected, a.state.Phase, a.state.LastError = false, "failed", message
			a.mu.Unlock()
			sessionTrackerFor(a).markRequestFailure(message)
			a.operationMu.Unlock()
			return
		}
	}()
}
