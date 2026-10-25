package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

type desktopNodeLaunch struct {
	command                    *exec.Cmd
	stop                       []string
	directory, profileID, mode string
	root, endpoint             string
	config, metadata           []byte
	configSHA256               string
	mtuSession                 string
	policyProfileID            string
	external                   *desktopExternalRuntime
	directoryInfo              os.FileInfo
	directoryRoot              *os.Root
	workspaceMu                sync.Mutex
	nodeWaitOnce               sync.Once
	nodeWaitDone               chan struct{}
	nodeStopAcknowledged       bool
}

var desktopNodeOwners sync.Map // map[*app]*desktopNodeLaunch; retained until checked cleanup

func desktopNodeNativeSelected(mode string) bool {
	if !mobilemultihop.NodeProfileMode(mode) {
		return false
	}
	_, err := os.Lstat(filepath.Join(desktopAmneziaPackageRoot(), "runtime", "native", "NATIVE-RUNTIME.json"))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func readDesktopNodeAssets(root, id, mode string) (map[string][]byte, error) {
	dir, err := nativeGeneratedDir(root, id, mode)
	if err != nil {
		return nil, err
	}
	// Reading a generated node must never create a missing profile or follow an
	// imported link into another node's private files.
	for current := dir; current != filepath.Clean(root); current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("captured native profile directory is missing or linked")
		}
		if filepath.Dir(current) == current {
			return nil, errors.New("captured profile escaped its application root")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 || len(entries) > 32 {
		return nil, errors.New("captured native profile asset count is invalid")
	}
	files := map[string][]byte{}
	total := 0
	for _, entry := range entries {
		name := entry.Name()
		if !nativeMultihopID.MatchString(name) || strings.HasPrefix(name, ".") || strings.Contains(name, "..") || entry.IsDir() {
			return nil, errors.New("captured native profile has an unsafe asset")
		}
		body, e := readPrivateRegular(filepath.Join(dir, name), 4<<20)
		if e != nil || len(body) == 0 {
			return nil, errors.New("captured native profile asset is missing or unsafe")
		}
		total += len(body)
		if total > 12<<20 {
			return nil, errors.New("captured native profile is oversized")
		}
		files[name] = body
	}
	return files, nil
}

func encodeDesktopNodeAssets(files map[string][]byte) string {
	encoded := map[string]string{}
	for name, body := range files {
		encoded[name] = base64.StdEncoding.EncodeToString(body)
	}
	raw, _ := json.Marshal(encoded)
	return string(raw)
}

func desktopNodeDNSBootstrap(p common.RouterProfile) (string, error) {
	selection, err := expectedDNSSelection(p)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(selection.Host); err == nil {
		return "", nil
	}
	// Bootstrap only the selected resolver's hostname, through the same proven
	// node's saved Home AdGuard address. Never resolve it via ambient DNS.
	address := p.AdGuardIPv4
	if address == "" {
		address = p.AdGuardIPv6
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.IsPrivate() || ip.Zone() != "" || ip.Is4In6() {
		return "", errors.New("custom DNS hostname requires this node's saved Home AdGuard bootstrap")
	}
	query := map[string]any{"server": "external-dns-bootstrap"}
	if p.IPv6Mode == "off" {
		query["strategy"] = "ipv4_only"
	}
	raw, _ := json.Marshal(map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": address, "server_port": 53, "detour": "proxy"}, "query": query})
	return string(raw), nil
}

// freezeDesktopNodeAssets changes only this captured outer node's transport
// address in launch copies. DNS names, certificate identities, private services,
// keys, paths and saved source bytes remain unchanged.
func freezeDesktopNodeAssets(files map[string][]byte, host, address string) (map[string][]byte, error) {
	copy := map[string][]byte{}
	for name, body := range files {
		copy[name] = append([]byte(nil), body...)
		switch name {
		case "wg.conf", "wg-socks.conf", "awg.conf", "awg-socks.conf":
			lines := strings.Split(string(body), "\n")
			for i, line := range lines {
				key, value, ok := strings.Cut(line, "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
					continue
				}
				value = strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
				captured, port, e := net.SplitHostPort(value)
				if e != nil {
					return nil, errors.New("native peer endpoint is malformed")
				}
				if mobilemultihop.SameNativeNodeHost(captured, host) {
					lines[i] = key + "= " + net.JoinHostPort(address, port)
				}
			}
			copy[name] = []byte(strings.Join(lines, "\n"))
		case "sing-box.json", "xray.json", "outer-xray.json", "middle-sing-box.json":
			var graph map[string]any
			if decodeRelayControlJSON(body, &graph) != nil {
				return nil, errors.New("native transport JSON is ambiguous")
			}
			outs, _ := graph["outbounds"].([]any)
			for _, raw := range outs {
				out, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if server, ok := out["server"].(string); ok && strings.EqualFold(server, host) {
					out["server"] = address
					if tls, ok := out["tls"].(map[string]any); ok && tls["enabled"] == true && (tls["server_name"] == nil || tls["server_name"] == "") {
						tls["server_name"] = host
					}
				}
				settings, _ := out["settings"].(map[string]any)
				peers, _ := settings["vnext"].([]any)
				for _, raw := range peers {
					if peer, ok := raw.(map[string]any); ok {
						if value, ok := peer["address"].(string); ok && strings.EqualFold(value, host) {
							peer["address"] = address
						}
					}
				}
			}
			value, e := json.Marshal(graph)
			if e != nil {
				return nil, e
			}
			copy[name] = value
		}
	}
	return copy, nil
}

func compileDesktopNode(ctx context.Context, p common.RouterProfile, mode string, files, start map[string][]byte, lookup applexray.Lookup) (*mobilemultihop.NodeProfile, string, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, "", errors.New("native node preparation was cancelled")
	}
	if p.NodeKind == "" {
		p.NodeKind = "router-vpn"
	}
	if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" {
		if _, err := mobilemultihop.NativeBaseSourceForEndpoint(mode, files, p.Endpoint); err != nil {
			return nil, "", err
		}
	}
	bootstrap, err := desktopNodeDNSBootstrap(p)
	if err != nil {
		return nil, "", err
	}
	compile := func(address string) (*mobilemultihop.NodeProfile, error) {
		owned := p
		owned.Endpoint = address
		f, s := files, start
		if address != p.Endpoint {
			var e error
			f, e = freezeDesktopNodeAssets(files, p.Endpoint, address)
			if e != nil {
				return nil, e
			}
			s, e = freezeDesktopNodeAssets(start, p.Endpoint, address)
			if e != nil {
				return nil, e
			}
		}
		startJSON := ""
		if len(s) != 0 {
			startJSON = encodeDesktopNodeAssets(s)
		}
		raw, e := json.Marshal(owned)
		if e != nil {
			return nil, e
		}
		return mobilemultihop.NewNodeProfile(mode, encodeDesktopNodeAssets(f), string(raw), startJSON, bootstrap)
	}
	if ip, err := netip.ParseAddr(p.Endpoint); err == nil {
		if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Zone() != "" || ip.Is4In6() {
			return nil, "", errors.New("native outer node is not an allowed unicast endpoint")
		}
		compiled, err := compile(p.Endpoint)
		return compiled, p.Endpoint, err
	}
	if !applexray.ValidNodeHostname(p.Endpoint) || lookup == nil {
		return nil, "", errors.New("native node hostname requires its captured bootstrap resolver")
	}
	// Validate the entire source before any lookup. This reserved, unroutable
	// compilation address is never executed or staged and is discarded here.
	if _, err := compile("192.0.2.254"); err != nil {
		return nil, "", err
	}
	answers, err := lookup(ctx, p.Endpoint)
	if err != nil || ctx.Err() != nil || len(answers) == 0 || len(answers) > 32 {
		return nil, "", errors.New("captured native node lookup failed or expired")
	}
	var chosen netip.Addr
	for _, ip := range answers {
		if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Zone() != "" || ip.Is4In6() {
			continue
		}
		if !chosen.IsValid() || ip.Is4() {
			chosen = ip
			if ip.Is4() {
				break
			}
		}
	}
	if !chosen.IsValid() {
		return nil, "", errors.New("captured node has no usable unicast address")
	}
	compiled, err := compile(chosen.String())
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	return compiled, chosen.String(), err
}

func desktopNativeEnvironment(environment []string, root, profile, endpoint string) []string {
	result := desktopStandardEngineEnvironment(environment, false)
	clean := result[:0]
	for _, entry := range result {
		name, _, _ := strings.Cut(entry, "=")
		name = strings.ToUpper(name)
		if name == "HOMEVPN_STANDARD_ENGINE" || name == "HOMEVPN_ROOT" || name == "HOMEVPN_PROFILE_ID" || name == "HOMEVPN_POLICY_PROFILE_ID" || name == "HOMEVPN_ENDPOINT" || name == "HOMEVPN_NATIVE_ENDPOINTS_JSON" || name == "HOMEVPN_NATIVE_EGRESS_JSON" || name == "HOMEVPN_NODE_SESSION" || name == "HOMEVPN_NODE_CONFIG_SHA256" {
			continue
		}
		clean = append(clean, entry)
	}
	executable, _ := os.Executable()
	packageRoot := desktopAmneziaPackageRoot()
	clean = append(clean, "HOMEVPN_STANDARD_ENGINE=native", "HOMEVPN_NATIVE_CONTROLLER="+executable, "HOMEVPN_NATIVE_PACKAGE="+packageRoot, "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+profile, "HOMEVPN_POLICY_PROFILE_ID="+profile, "HOMEVPN_ENDPOINT="+endpoint)
	return nativeLibraryEnvironment(clean, filepath.Join(packageRoot, "runtime", "native"))
}

func prepareDesktopNodeLaunch(a *app, p common.RouterProfile, mode string) (*desktopNodeLaunch, error) {
	if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(clientRoot(a))
	if err != nil {
		return nil, err
	}
	files, err := readDesktopNodeAssets(root, p.ID, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	var start map[string][]byte
	if p.StartLayer != "" && p.StartLayer != "off" && !mobilemultihop.MAXMode(mode) && mode != "shadowsocks" {
		start, err = readDesktopNodeAssets(root, p.ID, "shadowsocks")
		if err != nil {
			return nil, err
		}
		defer func() {
			for _, body := range start {
				clear(body)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(a.connectionOperationContextOrBackground(), 10*time.Second)
	defer cancel()
	compiled, endpoint, err := compileDesktopNode(ctx, p, mode, files, start, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
	if err != nil {
		return nil, err
	}
	if err := a.checkConnectionOperation(); err != nil {
		return nil, err
	}
	var graph map[string]any
	if json.Unmarshal([]byte(compiled.Config()), &graph) != nil {
		return nil, errors.New("native compiler returned an invalid graph")
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if runtime.GOOS == "darwin" {
		delete(tun, "interface_name")
	} else {
		tun["interface_name"] = "router-vpn"
	}
	data, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	var metadata map[string]any
	if json.Unmarshal([]byte(compiled.Metadata()), &metadata) != nil {
		return nil, errors.New("native capture metadata is invalid")
	}
	sum := sha256.Sum256(data)
	metadata["config_sha256"] = hex.EncodeToString(sum[:])
	receipt, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	return &desktopNodeLaunch{root: root, endpoint: endpoint, profileID: p.ID, mode: mode, config: data, metadata: receipt}, nil
}

// Stage only after the prior runtime is completely drained. A prior mode's
// cleanup must never delete the new graph before its captured process starts.
func stageDesktopNodeLaunch(a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.command != nil || launch.directory != "" || len(launch.config) == 0 {
		return errors.New("native launch has already been staged or is incomplete")
	}
	if err := a.checkConnectionOperation(); err != nil {
		return err
	}
	if launch.external != nil && (launch.external.network == "" || launch.external.network != launch.external.currentNetworkIdentity()) {
		return errors.New("external connection network changed before native staging")
	}
	var receipt struct {
		ConfigSHA256 string `json:"config_sha256"`
	}
	sum := sha256.Sum256(launch.config)
	configSHA256 := hex.EncodeToString(sum[:])
	if json.Unmarshal(launch.metadata, &receipt) != nil || receipt.ConfigSHA256 != configSHA256 {
		return errors.New("native launch graph differs from its captured configuration digest")
	}
	launch.configSHA256 = configSHA256
	if launch.external == nil {
		identifier, err := randomHex(16)
		if err != nil {
			return err
		}
		launch.mtuSession = identifier
	}
	root, endpoint := launch.root, launch.endpoint
	directory, err := newPrivateRuntimeDir(root, "native-node")
	if err != nil {
		return err
	}
	if err = captureDesktopRuntimeDirectory(launch, directory); err != nil {
		return err
	}
	owned := false
	defer func() {
		if !owned {
			_ = cleanupDesktopNodeLaunch(launch)
		}
	}()
	if err = writeDesktopRuntimeFile(launch, "sing-box.json", launch.config, false); err != nil {
		return err
	}
	capture := launch.metadata
	if launch.external != nil {
		capture = launch.external.capture
		if err = writeDesktopRuntimeFile(launch, "source.json", launch.external.source, false); err != nil {
			return err
		}
	}
	if err = writeDesktopRuntimeFile(launch, "capture.json", capture, false); err != nil {
		return err
	}
	var args []string
	if runtime.GOOS == "windows" {
		helper := filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-multihop-windows.ps1")
		args = []string{"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", directory, "-Endpoint", endpoint, "-TunnelAlias", "router-vpn"}
	} else {
		helper := "native-standard-exit-linux.sh"
		if runtime.GOOS == "darwin" {
			helper = "native-multihop-darwin.sh"
		}
		args = []string{"bash", filepath.Join(a.cfg.ScriptsDir, helper), "up", directory, endpoint, "router-vpn"}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = root
	cmd.Env = desktopNativeEnvironment(os.Environ(), root, launch.profileID, endpoint)
	if launch.external == nil {
		cmd.Env = nativeNodeMTUEnvironment(cmd.Env, launch.mtuSession, configSHA256)
	}
	if launch.external != nil {
		clean := cmd.Env[:0]
		for _, value := range cmd.Env {
			name, _, _ := strings.Cut(value, "=")
			if !strings.EqualFold(name, "HOMEVPN_POLICY_PROFILE_ID") && !strings.EqualFold(name, "HOMEVPN_EXTERNAL_SESSION") {
				clean = append(clean, value)
			}
		}
		cmd.Env = append(clean, "HOMEVPN_POLICY_PROFILE_ID="+launch.policyProfileID, "HOMEVPN_EXTERNAL_SESSION="+launch.external.session)
		if len(launch.external.physicalEndpoints) > 1 {
			encoded, err := json.Marshal(launch.external.physicalEndpoints)
			if err != nil {
				return err
			}
			cmd.Env = append(cmd.Env, "HOMEVPN_NATIVE_ENDPOINTS_JSON="+string(encoded))
		}
		if len(launch.external.physicalEgress) != 0 {
			encoded, err := json.Marshal(launch.external.physicalEgress)
			if err != nil {
				return err
			}
			cmd.Env = append(cmd.Env, "HOMEVPN_NATIVE_EGRESS_JSON="+string(encoded))
		}
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	stop := append([]string(nil), args...)
	if runtime.GOOS == "windows" {
		stop[7] = "down"
	} else {
		stop[2] = "down"
	}
	if launch.external != nil && launch.external.network != launch.external.currentNetworkIdentity() {
		return errors.New("external connection network changed during native staging")
	}
	owned = true
	launch.command, launch.stop, launch.directory = cmd, stop, directory
	clear(launch.config)
	clear(launch.metadata)
	launch.config = nil
	launch.metadata = nil
	return nil
}

func stopDesktopNodeRuntime(a *app, cmd *exec.Cmd) (bool, error) {
	raw, exists := desktopNodeOwners.Load(a)
	if !exists {
		return false, nil
	}
	owner, ok := raw.(*desktopNodeLaunch)
	if !ok || owner == nil || owner.command == nil || len(owner.stop) == 0 || cmd != nil && owner.command != cmd {
		return true, errors.New("native desktop cleanup lost its captured owner")
	}
	if _, err := os.Lstat(owner.directory); err == nil {
		if owner.external != nil || owner.mtuSession != "" {
			if err := desktopExternalDirectoryCurrent(owner); err != nil {
				return true, err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		stop := exec.CommandContext(ctx, owner.stop[0], owner.stop[1:]...)
		stop.Dir = owner.command.Dir
		stop.Env = append(append([]string(nil), owner.command.Env...), "HOMEVPN_KILLSWITCH_HOLD=1")
		if output, err := stop.CombinedOutput(); err != nil {
			return true, fmt.Errorf("native owned teardown failed: %w: %s", err, boundedMTUDetail(output))
		}
		if owner.external != nil {
			owner.external.mu.Lock()
			acknowledged := owner.external.stopAcknowledged
			owner.external.mu.Unlock()
			if !acknowledged || !desktopExternalProcessExited(owner) {
				return true, errors.New("native external cleanup has no closed process and lease acknowledgement")
			}
			if err := cleanupDesktopNodeLaunch(owner); err != nil {
				return true, err
			}
		} else if owner.mtuSession != "" {
			owner.workspaceMu.Lock()
			acknowledged := owner.nodeStopAcknowledged
			owner.workspaceMu.Unlock()
			if owner.command.Process != nil && (!acknowledged || !desktopNodeProcessExited(owner)) {
				return true, errors.New("native Router node cleanup lacks a checked close acknowledgement")
			}
			if err := cleanupDesktopNodeLaunch(owner); err != nil {
				return true, err
			}
		}
		if _, err := os.Lstat(owner.directory); !errors.Is(err, os.ErrNotExist) {
			return true, errors.New("native cleanup did not retire its captured private workspace")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return true, err
	}
	if current, ok := desktopNodeOwners.Load(a); !ok || current != owner {
		return true, errors.New("native desktop owner changed during cleanup")
	}
	return true, nil
}

// Keep the retired runtime identity until the surrounding stop transaction has
// also released its relay and protection. A failed firewall release must retry
// this captured native owner, never run the unrelated raw-mode stop command.
func finishDesktopNodeRuntime(a *app) error {
	raw, exists := desktopNodeOwners.Load(a)
	if !exists {
		return nil
	}
	owner, ok := raw.(*desktopNodeLaunch)
	if !ok || owner == nil {
		return errors.New("native desktop retirement lost its captured owner")
	}
	if _, err := os.Lstat(owner.directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("native desktop retirement still owns a private workspace")
	}
	if !desktopNodeOwners.CompareAndDelete(a, owner) {
		return errors.New("native desktop owner changed before stop committed")
	}
	if owner.external != nil {
		clear(owner.external.source)
		clear(owner.external.capture)
	}
	if owner.directoryRoot != nil {
		_ = owner.directoryRoot.Close()
	}
	clearActiveDNSRuntimeConfig(a)
	return nil
}
