package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

var desktopTorInputNames = []string{"torrc", "tor-defaults", "tor-profile.json", "tor-capture.json", "sing-box.json"}

// The zero value is the complete shipping adapter. Isolated controller tests
// may supply process/binary boundaries while exercising the same capture,
// staging, native preflight order, owned prelaunch, proof and cleanup logic.
type desktopTorConnectRuntime struct {
	capability func() standardExitCapability
	runtime    func(string, common.RouterProfile, common.RouterProfile, *desktopTorPredecessorCapture) (torBridgeRuntime, error)
	preflight  desktopExternalPreflightCommand
	command    func(*app, torBridgeRuntime, []string) (*exec.Cmd, error)
}

func captureDesktopTorExecutable(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 384<<20 {
		return "", errors.New("Tor executable is not a bounded captured regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", errors.New("Tor executable changed while opening")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, (384<<20)+1))
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("Tor executable changed during byte identity capture")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func prepareTorBridgeRuntime(root string, policy, profile common.RouterProfile) (torBridgeRuntime, error) {
	return prepareTorBridgeRuntimeWithPredecessor(root, policy, profile, nil)
}

func prepareTorBridgeRuntimeWithPredecessor(root string, policy, profile common.RouterProfile, predecessor *desktopTorPredecessorCapture) (torBridgeRuntime, error) {
	tor, err := desktopTorExecutable(root)
	if err != nil {
		return torBridgeRuntime{}, err
	}
	native, err := verifyBundledNative(desktopAmneziaPackageRoot())
	if err != nil {
		return torBridgeRuntime{}, err
	}
	return stageDesktopTorInputsWithPredecessor(root, policy, profile, tor, native, predecessor)
}

// Separate binary verification from immutable staging so isolated tests can
// exercise exact input ownership without installing a TUN or private server.
// Shipping preparation above always verifies the complete packaged engine.
func stageDesktopTorInputs(root string, policy, profile common.RouterProfile, tor, native string) (result torBridgeRuntime, failure error) {
	return stageDesktopTorInputsWithPredecessor(root, policy, profile, tor, native, nil)
}

func stageDesktopTorInputsWithPredecessor(root string, policy, profile common.RouterProfile, tor, native string, predecessor *desktopTorPredecessorCapture) (result torBridgeRuntime, failure error) {
	capturedToken := desktopTorSourceIdentityToken(profile)
	profile, cfg, transports, endpoint, err := torBridgeProfile(cloneRouterProfile(profile))
	if err != nil {
		return result, err
	}
	if policy.ID != profile.ID || policy.External == nil || policy.External.Protocol != "tor-bridge" {
		return result, errors.New("Tor policy belongs to another captured node")
	}
	expectedBridge, _ := json.Marshal(profile.External.TorBridge)
	policyBridge, _ := json.Marshal(policy.External.TorBridge)
	if !bytes.Equal(expectedBridge, policyBridge) {
		return result, errors.New("Tor policy changed its captured transport credentials")
	}
	if !filepath.IsAbs(native) || filepath.Clean(native) != native {
		return result, errors.New("Tor requires its exact native executable path")
	}
	torHash, err := captureDesktopTorExecutable(tor)
	if err != nil {
		return result, err
	}
	policyCopy := cloneRouterProfile(policy)
	if predecessor != nil {
		if policyCopy.MultihopEntryMode == "" {
			policyCopy.MultihopEntryMode = predecessor.mode
		}
	}
	profileRaw, err := desktopTorRuntimePolicyJSON(policyCopy)
	if err != nil {
		return result, err
	}
	if predecessor != nil {
		// RouterProfile stores the exit protocol once. Add the compiler's
		// explicit graph identity only to the runtime copy, preserving the
		// captured effective policy and explicit disabled LAN access.
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(profileRaw, &fields); err != nil {
			return result, err
		}
		fields["multihop_exit_mode"], err = json.Marshal(policyCopy.External.Protocol)
		if err != nil {
			return result, err
		}
		if predecessor.native == nil {
			return result, errors.New("Tor physical policy has no captured Router graph")
		}
		egress, err := mobilemultihop.NodePhysicalEgress(predecessor.mode, predecessor.native.Profile(), predecessor.native.Config())
		if err != nil {
			return result, err
		}
		// This runtime-only projection is covered by the same private profile
		// digest as the selected policy. Both launch wrappers compare it with
		// their physical firewall inputs before installing any exception.
		fields["desktop_physical_egress"], err = json.Marshal(egress)
		if err == nil {
			profileRaw, err = json.Marshal(fields)
		}
		if err != nil {
			return result, err
		}
	}
	var random [48]byte
	if _, err = io.ReadFull(rand.Reader, random[:]); err != nil {
		return result, err
	}
	defer clear(random[:])
	session, isolation := hex.EncodeToString(random[:16]), hex.EncodeToString(random[16:])
	// Validate policy before creating a workspace; cached MTU and unsupported
	// compositions can never be silently substituted during staging.
	if predecessor == nil {
		_, err = mobiletor.NewDesktopBridgePolicy(string(profileRaw), session, isolation, runtime.GOOS)
	} else if predecessor.native == nil || predecessor.entry.ID != predecessor.native.ID() || predecessor.assetsSHA256 != predecessor.native.AssetsSHA256() {
		err = errors.New("Tor staging has an incomplete Router entry capture")
	} else {
		_, err = mobiletor.NewDesktopBridgePolicyWithPredecessor(string(profileRaw), session, isolation, runtime.GOOS, predecessor.native)
	}
	if err != nil {
		return result, err
	}
	directory, err := newPrivateRuntimeDir(root, "tor-bridge")
	if err != nil {
		return result, err
	}
	physicalEndpoint := endpoint
	if predecessor != nil {
		physicalEndpoint = predecessor.endpoint
	}
	launch := &desktopNodeLaunch{root: root, profileID: profile.ID, policyProfileID: profile.ID, mode: "external-tor-bridge", endpoint: physicalEndpoint, tor: &desktopTorRuntime{profileToken: capturedToken, predecessor: predecessor, inputs: map[string]desktopTorInput{}}}
	if err = captureDesktopRuntimeDirectory(launch, directory); err != nil {
		return result, err
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, cleanupDesktopTorLaunch(launch))
			_ = launch.directoryRoot.Close()
		}
	}()
	var inputs *mobiletor.DesktopBridgeInputs
	if predecessor == nil {
		inputs, err = mobiletor.NewDesktopBridgeCapture(string(profileRaw), session, isolation, runtime.GOOS, tor, directory)
	} else {
		inputs, err = mobiletor.NewDesktopBridgeCaptureWithPredecessor(string(profileRaw), session, isolation, runtime.GOOS, tor, directory, predecessor.native)
	}
	if err != nil {
		return result, err
	}
	launch.tor.expected, launch.tor.digests = inputs.Policy().Metadata(), inputs.Digests()
	launch.configSHA256 = inputs.Digests().ConfigSHA256
	if err = launch.directoryRoot.Mkdir("tor-data", 0700); err != nil {
		return result, err
	}
	launch.tor.dataInfo, err = launch.directoryRoot.Lstat("tor-data")
	if err != nil {
		return result, err
	}
	contents := map[string]string{"torrc": inputs.Torrc(), "tor-defaults": inputs.Defaults(), "tor-profile.json": inputs.Policy().Profile(), "tor-capture.json": inputs.JSON(), "sing-box.json": inputs.Policy().Config()}
	for _, name := range desktopTorInputNames {
		if err = writeDesktopTorInput(launch, name, []byte(contents[name])); err != nil {
			return result, err
		}
	}
	result = torBridgeRuntime{RuntimeDir: directory, TorBinary: tor, NativeBinary: native, TorSHA256: torHash, Transport: cfg.Transport, PluginTransports: append([]string(nil), transports...), BridgeEndpoint: endpoint, SocksPort: cfg.SocksPort, Launch: launch}
	return result, nil
}

func desktopTorRuntimePolicyJSON(policy common.RouterProfile) ([]byte, error) {
	// Runtime Home resolution and explicit graph choices have already been
	// validated together. Durable normalization would erase derived private
	// addresses or reinterpret those choices without the captured entry.
	type runtimeWire common.RouterProfile
	raw, err := json.Marshal(runtimeWire(policy))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["home_lan_access"], _ = json.Marshal(policy.HomeLANAccess)
	return json.Marshal(fields)
}

// Capture the inode before writing, including a partial failed write. Cleanup
// may retire only the exact bytes this writer supplied to that owned inode.
func writeDesktopTorInput(launch *desktopNodeLaunch, name string, raw []byte) (failure error) {
	if launch == nil || launch.tor == nil || !desktopRuntimeFilename(name) || len(raw) == 0 || int64(len(raw)) > desktopTorInputLimit(name) {
		return errors.New("invalid captured Tor input")
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	file, err := launch.directoryRoot.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	n, err := file.Write(raw)
	launch.tor.inputs[name] = desktopTorInput{info: info, digest: desktopTorDigest(raw[:n])}
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	current, err := launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(info, current) || current.Size() != int64(len(raw)) {
		return errors.New("Tor input changed during publication")
	}
	read, err := readDesktopRuntimeSnapshot(launch.directoryRoot, name, int64(len(raw)))
	if err != nil || !bytes.Equal(read, raw) {
		return errors.New("Tor input did not retain its exact captured contents")
	}
	return desktopExternalDirectoryCurrent(launch)
}

func desktopTorEnvironment(base []string, root, profile, endpoint string, inputs mobiletor.DesktopBridgeInputDigests, session, torHash string) []string {
	environment := desktopNativeEnvironment(base, root, profile, endpoint)
	clean := environment[:0]
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(key), "HOMEVPN_TOR_") {
			continue
		}
		clean = append(clean, entry)
	}
	return append(clean, "HOMEVPN_TOR_SESSION="+session, "HOMEVPN_TOR_SOURCE_SHA256="+inputs.SourceSHA256, "HOMEVPN_TOR_PROFILE_SHA256="+inputs.ProfileSHA256, "HOMEVPN_TOR_CAPTURE_SHA256="+inputs.CaptureSHA256, "HOMEVPN_TOR_TORRC_SHA256="+inputs.TorrcSHA256, "HOMEVPN_TOR_DEFAULTS_SHA256="+inputs.DefaultsSHA256, "HOMEVPN_TOR_CONFIG_SHA256="+inputs.ConfigSHA256, "HOMEVPN_TOR_BINARY_SHA256="+torHash)
}

func prepareTorBridgeCommand(a *app, policy, profile common.RouterProfile) (command *exec.Cmd, staged *torBridgePrelaunch, failure error) {
	return prepareTorBridgeCommandWithRuntime(a, policy, profile, nil, desktopTorConnectRuntime{})
}

func desktopTorLaunchEnvironment(base []string, root string, prepared torBridgeRuntime) ([]string, error) {
	launch := prepared.Launch
	if launch == nil || launch.tor == nil || launch.tor.expected.NodeID != launch.profileID {
		return nil, errors.New("Tor launch environment has no captured node")
	}
	owner := launch.tor
	profileID, endpoint := launch.profileID, prepared.BridgeEndpoint
	if owner.predecessor != nil {
		profileID, endpoint = owner.predecessor.entry.ID, owner.predecessor.endpoint
	}
	environment := desktopTorEnvironment(base, root, profileID, endpoint, owner.digests, owner.expected.SessionID, prepared.TorSHA256)
	environment = envWithValue(environment, "HOMEVPN_POLICY_PROFILE_ID", launch.profileID)
	if owner.predecessor == nil {
		if owner.expected.EntryID != "" {
			return nil, errors.New("Tor launch lost its captured Router entry")
		}
		return environment, nil
	}
	entry := owner.predecessor
	if entry.native == nil || owner.expected.EntryID != profileID || owner.expected.EntryMode != entry.mode || owner.expected.EntryAssetsSHA256 != entry.assetsSHA256 {
		return nil, errors.New("Tor launch environment differs from its captured Router entry")
	}
	egress, err := mobilemultihop.NodePhysicalEgress(entry.mode, entry.native.Profile(), entry.native.Config())
	if err != nil {
		return nil, err
	}
	hosts, seen, found := []string{endpoint}, map[string]bool{endpoint: true}, false
	for _, tuple := range egress {
		if tuple.Host == endpoint {
			found = true
		}
		if !seen[tuple.Host] {
			hosts = append(hosts, tuple.Host)
			seen[tuple.Host] = true
		}
	}
	if !found {
		return nil, errors.New("Tor physical endpoint does not belong to its captured Router graph")
	}
	hostJSON, err := json.Marshal(hosts)
	if err != nil {
		return nil, err
	}
	egressJSON, err := json.Marshal(egress)
	if err != nil {
		return nil, err
	}
	return append(environment, "HOMEVPN_EXTERNAL_SESSION="+owner.expected.SessionID, "HOMEVPN_NATIVE_ENDPOINTS_JSON="+string(hostJSON), "HOMEVPN_NATIVE_EGRESS_JSON="+string(egressJSON)), nil
}

func prepareTorBridgeCommandWithRuntime(a *app, policy, profile common.RouterProfile, predecessor *desktopTorPredecessorCapture, driver desktopTorConnectRuntime) (command *exec.Cmd, staged *torBridgePrelaunch, failure error) {
	if driver.runtime == nil {
		driver.runtime = prepareTorBridgeRuntimeWithPredecessor
	}
	if driver.preflight == nil {
		driver.preflight = runDesktopExternalPreflightCommand
	}
	if driver.command == nil {
		driver.command = desktopTorRuntimeCommand
	}
	root, err := filepath.Abs(clientRoot(a))
	if err != nil {
		return nil, nil, err
	}
	network := physicalNetworkIdentity()
	if network == "" {
		return nil, nil, errors.New("Tor preparation could not capture its physical network")
	}
	prepared, err := driver.runtime(root, policy, profile, predecessor)
	if err != nil {
		return nil, nil, err
	}
	launch := prepared.Launch
	if launch == nil || launch.tor == nil || launch.directoryRoot == nil || launch.directory != prepared.RuntimeDir || launch.profileID != profile.ID || launch.tor.predecessor != predecessor {
		return nil, nil, errors.New("Tor preparation did not retain the exact captured runtime owner")
	}
	launch.tor.network = network
	owner, err := captureTorBridgePrelaunch(a, profile.ID, prepared.RuntimeDir, launch)
	if err != nil {
		cleanupErr := cleanupDesktopTorLaunch(launch)
		closeErr := launch.directoryRoot.Close()
		return nil, nil, errors.Join(err, cleanupErr, closeErr)
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, owner.cleanup())
			owner.close()
		}
	}()
	environment, err := desktopTorLaunchEnvironment(os.Environ(), root, prepared)
	if err != nil {
		return nil, nil, err
	}
	if err = preflightDesktopTorLaunch(a.connectionOperationContextOrBackground(), prepared.NativeBinary, launch, environment, driver.preflight); err != nil {
		return nil, nil, err
	}
	cmd, err := driver.command(a, prepared, environment)
	if err != nil {
		return nil, nil, err
	}
	owner.command, launch.command = cmd, cmd
	return cmd, owner, nil
}

func desktopTorRuntimeCommand(a *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		helper := filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-tor-bridge-windows.ps1")
		if info, err := os.Lstat(helper); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("native Windows Tor helper is missing or unsafe")
		}
		powershell, err := safeExecutable("powershell.exe")
		if err != nil {
			return nil, err
		}
		cmd = exec.Command(powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", prepared.RuntimeDir, "-BridgeEndpoint", prepared.BridgeEndpoint, "-SocksPort", strconv.Itoa(prepared.SocksPort), "-TorBinary", prepared.TorBinary, "-NativeBinary", prepared.NativeBinary, "-TunnelAlias", "router-vpn-tor")
	} else {
		helper := filepath.Join(a.cfg.ScriptsDir, "native-tor-bridge.sh")
		if info, err := os.Lstat(helper); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("native Tor helper is missing or unsafe")
		}
		cmd = exec.Command("bash", helper, "up", prepared.RuntimeDir, prepared.BridgeEndpoint, strconv.Itoa(prepared.SocksPort), prepared.TorBinary, prepared.NativeBinary)
	}
	cmd.Dir = prepared.Launch.root
	cmd.Env = environment
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func preflightDesktopTorLaunch(ctx context.Context, binary string, launch *desktopNodeLaunch, environment []string, run desktopExternalPreflightCommand) error {
	if ctx == nil || launch == nil || launch.tor == nil || run == nil {
		return errors.New("Tor preflight has no captured runtime")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run(ctx, binary, []string{"routervpn-tor", "--help"}, environment, launch.directory); err != nil {
		return err
	}
	if err := run(ctx, binary, []string{"check", "-D", launch.directory, "-c", filepath.Join(launch.directory, "sing-box.json")}, environment, launch.directory); err != nil {
		return err
	}
	for name, input := range launch.tor.inputs {
		current, err := launch.directoryRoot.Lstat(name)
		if err != nil || !os.SameFile(input.info, current) {
			return errors.New("Tor preflight replaced a captured input")
		}
		raw, err := readDesktopRuntimeFile(launch, name, desktopTorInputLimit(name))
		if err != nil || desktopTorDigest(raw) != input.digest {
			return errors.New("Tor preflight changed a captured input")
		}
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	return ctx.Err()
}
