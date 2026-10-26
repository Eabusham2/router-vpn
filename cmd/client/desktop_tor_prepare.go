package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

var desktopTorInputNames = []string{"torrc", "tor-defaults", "tor-profile.json", "tor-capture.json", "sing-box.json"}

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
	tor, err := desktopTorExecutable(root)
	if err != nil {
		return torBridgeRuntime{}, err
	}
	native, err := verifyBundledNative(desktopAmneziaPackageRoot())
	if err != nil {
		return torBridgeRuntime{}, err
	}
	return stageDesktopTorInputs(root, policy, profile, tor, native)
}

// Separate binary verification from immutable staging so isolated tests can
// exercise exact input ownership without installing a TUN or private server.
// Shipping preparation above always verifies the complete packaged engine.
func stageDesktopTorInputs(root string, policy, profile common.RouterProfile, tor, native string) (result torBridgeRuntime, failure error) {
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
	profileRaw, err := json.Marshal(cloneRouterProfile(policy))
	if err != nil {
		return result, err
	}
	var random [48]byte
	if _, err = io.ReadFull(rand.Reader, random[:]); err != nil {
		return result, err
	}
	defer clear(random[:])
	session, isolation := hex.EncodeToString(random[:16]), hex.EncodeToString(random[16:])
	// Validate policy before creating a workspace; cached MTU and unsupported
	// compositions can never be silently substituted during staging.
	if _, err = mobiletor.NewDesktopBridgePolicy(string(profileRaw), session, isolation, runtime.GOOS); err != nil {
		return result, err
	}
	directory, err := newPrivateRuntimeDir(root, "tor-bridge")
	if err != nil {
		return result, err
	}
	launch := &desktopNodeLaunch{root: root, profileID: profile.ID, policyProfileID: profile.ID, mode: "external-tor-bridge", endpoint: endpoint, tor: &desktopTorRuntime{profileToken: capturedToken, inputs: map[string]desktopTorInput{}}}
	if err = captureDesktopRuntimeDirectory(launch, directory); err != nil {
		return result, err
	}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, cleanupDesktopTorLaunch(launch))
			_ = launch.directoryRoot.Close()
		}
	}()
	inputs, err := mobiletor.NewDesktopBridgeCapture(string(profileRaw), session, isolation, runtime.GOOS, tor, directory)
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

// Capture the inode before writing, including a partial failed write. Cleanup
// may retire only the exact bytes this writer supplied to that owned inode.
func writeDesktopTorInput(launch *desktopNodeLaunch, name string, raw []byte) (failure error) {
	if launch == nil || launch.tor == nil || !desktopRuntimeFilename(name) || len(raw) == 0 || len(raw) > 4<<20 {
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
	root, err := filepath.Abs(clientRoot(a))
	if err != nil {
		return nil, nil, err
	}
	network := physicalNetworkIdentity()
	if network == "" {
		return nil, nil, errors.New("Tor preparation could not capture its physical network")
	}
	prepared, err := prepareTorBridgeRuntime(root, policy, profile)
	if err != nil {
		return nil, nil, err
	}
	launch := prepared.Launch
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
	environment := desktopTorEnvironment(os.Environ(), root, profile.ID, prepared.BridgeEndpoint, launch.tor.digests, launch.tor.expected.SessionID, prepared.TorSHA256)
	if err = preflightDesktopTorLaunch(a.connectionOperationContextOrBackground(), prepared.NativeBinary, launch, environment, runDesktopExternalPreflightCommand); err != nil {
		return nil, nil, err
	}
	if err = registerActiveDNSRuntimeConfig(a, profile.ID, "external-tor-bridge", filepath.Join(prepared.RuntimeDir, "sing-box.json")); err != nil {
		return nil, nil, fmt.Errorf("register captured Tor DNS policy: %w", err)
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		helper := filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-tor-bridge-windows.ps1")
		if info, err := os.Lstat(helper); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("native Windows Tor helper is missing or unsafe")
		}
		powershell, err := safeExecutable("powershell.exe")
		if err != nil {
			return nil, nil, err
		}
		cmd = exec.Command(powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", prepared.RuntimeDir, "-BridgeEndpoint", prepared.BridgeEndpoint, "-SocksPort", strconv.Itoa(prepared.SocksPort), "-TorBinary", prepared.TorBinary, "-NativeBinary", prepared.NativeBinary, "-TunnelAlias", "router-vpn-tor")
	} else {
		helper := filepath.Join(a.cfg.ScriptsDir, "native-tor-bridge.sh")
		if info, err := os.Lstat(helper); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("native Tor helper is missing or unsafe")
		}
		cmd = exec.Command("bash", helper, "up", prepared.RuntimeDir, prepared.BridgeEndpoint, strconv.Itoa(prepared.SocksPort), prepared.TorBinary, prepared.NativeBinary)
	}
	cmd.Dir = root
	cmd.Env = environment
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	owner.command, launch.command = cmd, cmd
	return cmd, owner, nil
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
		raw, err := readDesktopRuntimeFile(launch, name, 4<<20)
		if err != nil || desktopTorDigest(raw) != input.digest {
			return errors.New("Tor preflight changed a captured input")
		}
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	return ctx.Err()
}
