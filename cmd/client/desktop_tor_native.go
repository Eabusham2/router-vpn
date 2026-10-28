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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/mobiletor"
)

// The controller retains the native Tor owner until its exact native process,
// standalone Tor child, PT workers and TUN have drained. A process exit alone
// cannot release private inputs or the client's protection policy.
type desktopTorRuntime struct {
	mu                    sync.Mutex
	proofMu               sync.Mutex
	dnsMu                 sync.Mutex
	dnsGeneration         uint64
	dnsFailed             bool
	pathMu                sync.Mutex
	pathGeneration        uint64
	pathFailed            bool
	mtu                   *desktopMTUSession
	mtuAuthority          desktopTorMTUAuthority
	mtuReadback           *mobiletor.DesktopBridgeMTUReadback
	mtuPriorReadback      *mobiletor.DesktopBridgeMTUReadback
	mtuTransition         *mobiletor.DesktopBridgeMTUTransition
	mtuRetiredTransition  uint64
	lastProofHeartbeat    int64
	paddingReceipt        *mobiletor.PaddingReceipt
	paddingProof          *mobiletor.DesktopBridgePaddingProof
	expected              mobiletor.DesktopBridgeMetadata
	digests               mobiletor.DesktopBridgeInputDigests
	profileToken          string
	committedChoice       atomic.Pointer[desktopTorCommittedChoice]
	predecessor           *desktopTorPredecessorCapture
	network               string
	networkIdentity       func() string
	started               time.Time
	adopted               *desktopTorProof
	stopAcknowledged      bool
	prelaunchAcknowledged bool
	admissionObserved     bool
	inputs                map[string]desktopTorInput
	dataInfo              os.FileInfo
}

type desktopTorInput struct {
	info   os.FileInfo
	digest string
}

type desktopTorProof struct {
	Schema         int                                  `json:"schema"`
	SessionID      string                               `json:"session_id"`
	SourceSHA256   string                               `json:"source_sha256"`
	ConfigSHA256   string                               `json:"config_sha256"`
	Policy         mobiletor.DesktopBridgeMetadata      `json:"policy"`
	Proof          mobiletor.Proof                      `json:"proof"`
	InterfaceName  string                               `json:"interface_name"`
	InterfaceIndex int                                  `json:"interface_index"`
	EffectiveMTU   int                                  `json:"effective_mtu"`
	Healthy        bool                                 `json:"healthy"`
	HeartbeatAt    int64                                `json:"heartbeat_at"`
	MTUReadback    *mobiletor.DesktopBridgeMTUReadback  `json:"mtu_readback,omitempty"`
	EntryProof     *mobiletor.DesktopBridgeEntryProof   `json:"entry_proof,omitempty"`
	Padding        *mobiletor.PaddingReceipt            `json:"padding,omitempty"`
	PaddingProof   *mobiletor.DesktopBridgePaddingProof `json:"padding_proof,omitempty"`
}

type desktopTorProgress struct {
	Schema       int    `json:"schema"`
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Stage        string `json:"stage"`
}

// This wrapper witness proves only that native admission was never attempted.
// It cannot replace a native stopped receipt once progress or any worker exists.
type desktopTorPrelaunchFailure struct {
	Schema          int    `json:"schema"`
	SessionID       string `json:"session_id"`
	SourceSHA256    string `json:"source_sha256"`
	ConfigSHA256    string `json:"config_sha256"`
	NoNativeProcess bool   `json:"no_native_process"`
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
	return validateDesktopTorProofAt(raw, owner, now, now)
}

// A bounded MTU transition may retain its historical interface admission, but
// padding always requires a currently observed native lease and fresh proofs.
// The two clocks can differ only in that transition's explicit reader path.
func validateDesktopTorProofAt(raw []byte, owner *desktopTorRuntime, now, paddingNow time.Time) (desktopTorProof, error) {
	var proof desktopTorProof
	bad := errors.New("native Tor proof is stale or differs from its captured policy, process or path")
	if owner == nil || len(raw) == 0 || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &proof) != nil {
		return proof, bad
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	expected := owner.expected
	if proof.Schema != 1 || !proof.Healthy || proof.Policy != expected || proof.SessionID != expected.SessionID || proof.SourceSHA256 != expected.SourceSHA256 || proof.ConfigSHA256 != expected.ConfigSHA256 || proof.Proof.SessionID != expected.SessionID || !proof.Proof.IsTor || !proof.Proof.DNSProven || owner.started.IsZero() || proof.Proof.CheckedAt.Before(owner.started.Add(-time.Second)) || proof.Proof.CheckedAt.After(now.Add(time.Second)) || proof.HeartbeatAt < now.Add(-mobiletor.DesktopBridgeHeartbeatMaxAge).UnixMilli() || proof.HeartbeatAt > now.Add(time.Second).UnixMilli() || proof.HeartbeatAt < proof.Proof.CheckedAt.UnixMilli() {
		return proof, bad
	}
	if ip, err := publicTorExit(proof.Proof.IP); err != nil || ip != proof.Proof.IP {
		return proof, bad
	}
	if !expected.ValidEntryProof(proof.EntryProof, owner.started, now) {
		return proof, bad
	}
	if expected.ValidatePaddingProof(proof.Padding, proof.PaddingProof, owner.started, paddingNow) != nil ||
		mobiletor.ValidateDesktopPaddingProgress(owner.paddingReceipt, proof.Padding, owner.paddingProof, proof.PaddingProof) != nil {
		return proof, bad
	}
	if proof.InterfaceIndex <= 0 || proof.InterfaceName == "" || len(proof.InterfaceName) > 64 || proof.EffectiveMTU < 1280 || proof.EffectiveMTU > 9000 || expected.InterfaceName != "" && proof.InterfaceName != expected.InterfaceName {
		return proof, bad
	}
	for _, r := range proof.InterfaceName {
		if r <= 0x20 || r == 0x7f {
			return proof, bad
		}
	}
	if adopted := owner.adopted; adopted != nil && (proof.Proof.SessionID != adopted.Proof.SessionID || proof.Proof.IP != adopted.Proof.IP || !proof.Proof.CheckedAt.Equal(adopted.Proof.CheckedAt)) {
		return proof, bad
	}
	if adopted := owner.adopted; adopted != nil && expected.EntryID != "" && (adopted.EntryProof == nil || proof.EntryProof.EntryID != adopted.EntryProof.EntryID || proof.EntryProof.EntrySHA256 != adopted.EntryProof.EntrySHA256 || !proof.EntryProof.CheckedAt.Equal(adopted.EntryProof.CheckedAt)) {
		return proof, bad
	}
	if !desktopTorProofReadbackLocked(owner, proof) {
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
	valid := a.cmd == launch.command && found && owner.sourceIdentityToken() != "" && desktopTorSourceIdentityToken(current) == owner.sourceIdentityToken() && owner.entryCurrentLocked(a) == nil
	a.mu.Unlock()
	if !valid {
		return errors.New("Tor native session or captured private node changed")
	}
	if err := owner.entryCurrent(a); err != nil {
		return err
	}
	if desktopNodeProcessExited(launch) {
		return errors.New("Tor native process exited before its proof could be retained")
	}
	return desktopExternalDirectoryCurrent(launch)
}

func (a *app) readDesktopTorProof(launch *desktopNodeLaunch) (desktopTorProof, error) {
	if launch == nil || launch.tor == nil {
		return desktopTorProof{}, errors.New("Tor proof has no captured owner")
	}
	// Serialize file read and receipt adoption so an older concurrent reader
	// cannot regress the retained native interface revision.
	launch.tor.proofMu.Lock()
	defer launch.tor.proofMu.Unlock()
	if err := a.desktopTorCurrent(launch); err != nil {
		return desktopTorProof{}, err
	}
	raw, err := readDesktopRuntimeFile(launch, "proof.json", 64<<10)
	if err != nil {
		return desktopTorProof{}, err
	}
	launch.tor.mu.Lock()
	launch.tor.admissionObserved = true
	launch.tor.mu.Unlock()
	proof, err := validateDesktopTorProof(raw, launch.tor, time.Now())
	if err == nil {
		err = a.desktopTorCurrent(launch)
	}
	if err == nil {
		err = noteDesktopTorStrictHeartbeat(launch.tor, proof)
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
	launch.tor.mu.Lock()
	launch.tor.admissionObserved = true
	launch.tor.mu.Unlock()
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
		a.state.Phase = strings.TrimPrefix(launch.mode, "external-") + ":" + progress.Stage
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

func desktopTorNoNativeWork(launch *desktopNodeLaunch) (bool, error) {
	if launch == nil || launch.tor == nil || !desktopNodeProcessExited(launch) {
		return false, nil
	}
	raw, err := readDesktopRuntimeFile(launch, "prelaunch-failed.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	bad := errors.New("Tor prelaunch witness does not prove an unused captured native workspace")
	var witness desktopTorPrelaunchFailure
	owner := launch.tor
	expected := owner.expected
	if decodeRelayControlJSON(raw, &witness) != nil || witness.Schema != 1 || !witness.NoNativeProcess || witness.SessionID != expected.SessionID || witness.SourceSHA256 != expected.SourceSHA256 || witness.ConfigSHA256 != expected.ConfigSHA256 {
		return false, bad
	}
	owner.mu.Lock()
	proved := owner.adopted != nil || owner.admissionObserved
	owner.mu.Unlock()
	if proved || len(owner.inputs) != len(desktopTorInputNames) || owner.dataInfo == nil {
		return false, bad
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return false, err
	}
	root := launch.directoryRoot
	directory, err := root.Open(".")
	if err != nil {
		return false, err
	}
	entries, readErr := directory.ReadDir(16)
	_ = directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) < 7 || len(entries) > 8 {
		return false, bad
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		seen[name] = true
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false, bad
		}
		if input, ok := owner.inputs[name]; ok {
			contents, err := readDesktopRuntimeSnapshot(root, name, desktopTorInputLimit(name))
			if err != nil || input.info == nil || !os.SameFile(info, input.info) || desktopTorDigest(contents) != input.digest {
				return false, bad
			}
			continue
		}
		switch name {
		case "tor-data":
			if !info.IsDir() || !os.SameFile(info, owner.dataInfo) {
				return false, bad
			}
			data, err := root.Open(name)
			if err != nil {
				return false, bad
			}
			actual, statErr := data.Stat()
			contents, readErr := data.ReadDir(1)
			_ = data.Close()
			if statErr != nil || !os.SameFile(actual, info) || len(contents) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
				return false, bad
			}
		case "prelaunch-failed.json":
			contents, err := readDesktopRuntimeSnapshot(root, name, 4096)
			if err != nil || desktopTorDigest(contents) != desktopTorDigest(raw) {
				return false, bad
			}
		case "stop.json":
			contents, err := readDesktopRuntimeSnapshot(root, name, 4096)
			var stop desktopExternalStop
			if err != nil || decodeRelayControlJSON(contents, &stop) != nil || stop.Schema != 1 || stop.Closed || stop.SessionID != expected.SessionID || stop.SourceSHA256 != expected.SourceSHA256 {
				return false, bad
			}
		default:
			// Even a partial progress write establishes an attempted native
			// admission. No-work cleanup cannot infer that its workers drained.
			return false, bad
		}
	}
	for _, name := range append(append([]string(nil), desktopTorInputNames...), "tor-data", "prelaunch-failed.json") {
		if !seen[name] {
			return false, bad
		}
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil || !desktopNodeProcessExited(launch) {
		return false, bad
	}
	owner.mu.Lock()
	owner.prelaunchAcknowledged = true
	owner.mu.Unlock()
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

func observeDesktopTorDrain(readExited func() bool, readStopped func() (bool, error)) (closed, exited bool, err error) {
	// The child publishes its terminal receipt before it exits. Sample the
	// process first: otherwise a missing receipt followed by a newly completed
	// process could combine observations from opposite sides of that publish.
	// A receipt observed while this sample is still running remains pending.
	exited = readExited()
	closed, err = readStopped()
	return
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
	acknowledged := owner.stopAcknowledged || owner.prelaunchAcknowledged
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
		closed, exited, err := observeDesktopTorDrain(
			func() bool { return desktopNodeProcessExited(launch) },
			func() (bool, error) { return desktopTorStopped(launch) },
		)
		if err != nil {
			return err
		}
		if closed && exited {
			return desktopTorStopOwner(a, launch, command)
		}
		if exited {
			if unused, err := desktopTorNoNativeWork(launch); err != nil {
				return err
			} else if unused {
				return desktopTorStopOwner(a, launch, command)
			}
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
	acknowledged := launch.tor.stopAcknowledged || launch.tor.prelaunchAcknowledged
	unused := launch.tor.prelaunchAcknowledged && !launch.tor.stopAcknowledged
	launch.tor.mu.Unlock()
	if !acknowledged || !desktopNodeProcessExited(launch) {
		return errors.New("Tor cleanup requires checked native drain or a verified prelaunch failure and joined process")
	}
	if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if unused {
		if valid, err := desktopTorNoNativeWork(launch); err != nil {
			return err
		} else if !valid {
			return errors.New("Tor prelaunch witness changed before private cleanup")
		}
	}
	return cleanupDesktopTorLaunch(launch)
}

func desktopTorMailbox(name string) bool {
	switch name {
	case "proof.json", "progress.json", "stop.json", "stopped.json", "prelaunch-failed.json", ".proof.json.pending", ".progress.json.pending", ".stopped.json.pending",
		"dns-status.json", "dns-request.json", "dns-cancel.json", ".dns-status.json.pending",
		"mtu-status.json", "mtu-request.json", "mtu-commit.json", "mtu-cancel.json", ".mtu-status.json.pending",
		"path-status.json", "path-request.json", "path-cancel.json", ".path-status.json.pending",
		"mtu-transition.json", ".mtu-transition.json.pending":
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
				if info.Size() != 0 || input.digest != desktopTorDigest(nil) {
					raw, err := readDesktopRuntimeSnapshot(root, name, desktopTorInputLimit(name))
					if err != nil || desktopTorDigest(raw) != input.digest {
						return errors.New("Tor immutable input contents changed")
					}
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
			if a.desktopTorMonitorCurrent(launch) {
				continue
			}
			if !a.operationMu.TryLock() {
				continue
			}
			if !a.ownsConnectionRuntime(launch.command) {
				a.operationMu.Unlock()
				return
			}
			if a.desktopTorMonitorCurrent(launch) {
				a.operationMu.Unlock()
				continue
			}
			// Automatic proof/network retirement cannot preserve a completed
			// DNS draft as though the user explicitly disconnected this path.
			invalidateDesktopDNSResults(a)
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
