package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

type torBridgeRuntime struct {
	RuntimeDir       string
	TorBinary        string
	PTBinary         string
	SingBoxBinary    string
	Transport        string
	PluginTransports []string
	BridgeEndpoint   string
	SocksPort        int
}

func safeExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil || strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s is unavailable", name)
	}
	if strings.ContainsAny(path, "\r\n\x00") {
		return "", fmt.Errorf("%s resolved to an unsafe executable path", name)
	}
	return path, nil
}

func torBridgeTransportBinary(transports []string) (string, error) {
	if len(transports) == 0 {
		return "", errors.New("Tor profile has no pluggable transports")
	}
	if path, err := safeExecutable("lyrebird"); err == nil {
		return path, nil
	}
	for _, transport := range transports {
		if transport != "obfs4" && transport != "meek_lite" {
			return "", fmt.Errorf("Tor %s requires lyrebird; legacy obfs4proxy cannot provide this transport", transport)
		}
	}
	if path, err := safeExecutable("obfs4proxy"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("Tor %s requires lyrebird (preferred) or obfs4proxy", strings.Join(transports, ","))
}

func torBridgeRuntimeCapabilityForRoot(root string) standardExitCapability {
	cap := standardExitCapability{Protocol: "tor-bridge", Implemented: true}
	switch runtime.GOOS {
	case "windows":
		if runtime.GOARCH != "amd64" {
			cap.Reason = "native Tor bridge runtime is unavailable on Windows ARM64 because the pinned Tor Project Expert Bundle has no Windows ARM64 build"
			return cap
		}
		for _, binary := range []string{"tor.exe", "lyrebird.exe", "sing-box.exe"} {
			if _, err := windowsTorRuntimeExecutable(root, binary); err != nil {
				cap.Reason = err.Error()
				return cap
			}
		}
		cap.Supported = true
		return cap
	case "linux", "darwin":
		for _, binary := range []string{"tor", "sing-box"} {
			if _, err := safeExecutable(binary); err != nil {
				cap.Reason = binary + " is required for the real Tor bridge runtime"
				return cap
			}
		}
		if _, err := safeExecutable("lyrebird"); err != nil {
			if _, legacyErr := safeExecutable("obfs4proxy"); legacyErr != nil {
				cap.Reason = "lyrebird is required for modern Tor circumvention transports (obfs4proxy remains an obfs4/meek_lite compatibility fallback)"
				return cap
			}
		}
		cap.Supported = true
		return cap
	default:
		cap.Reason = "Tor pluggable-transport full-device runtime is currently implemented on Windows x64, Linux and macOS only; this platform remains unavailable instead of faking Tor"
		return cap
	}
}

func torBridgeRuntimeCapability() standardExitCapability {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	return torBridgeRuntimeCapabilityForRoot(root)
}

func torRuntimeBridgeTransports(cfg common.ExternalTorBridgeConfig) ([]string, string, error) {
	if len(cfg.Bridges) < 1 || len(cfg.Bridges) > 8 {
		return nil, "", errors.New("Tor runtime requires between one and eight normalized bridge lines")
	}
	transports := make([]string, 0, len(cfg.Bridges))
	seen := map[string]bool{}
	firstHost := ""
	for i, line := range cfg.Bridges {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, "", fmt.Errorf("Tor bridge %d is not normalized", i+1)
		}
		transport := fields[0]
		switch transport {
		case "obfs4", "meek_lite", "snowflake", "webtunnel":
		default:
			return nil, "", fmt.Errorf("Tor bridge %d has unsupported runtime transport %q", i+1, transport)
		}
		host, port, err := net.SplitHostPort(fields[1])
		if err != nil {
			return nil, "", fmt.Errorf("Tor bridge %d endpoint is invalid", i+1)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return nil, "", fmt.Errorf("Tor bridge %d endpoint must remain a safe literal IP", i+1)
		}
		if transport == "obfs4" && ip.IsPrivate() {
			return nil, "", fmt.Errorf("Tor obfs4 bridge %d endpoint must remain a public literal IP", i+1)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, "", fmt.Errorf("Tor bridge %d endpoint port is invalid", i+1)
		}
		if firstHost == "" {
			firstHost = ip.String()
		}
		if !seen[transport] {
			seen[transport] = true
			transports = append(transports, transport)
		}
	}
	return transports, firstHost, nil
}

func torBridgeProfile(profile common.RouterProfile) (common.RouterProfile, common.ExternalTorBridgeConfig, []string, string, error) {
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", err
	}
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "tor-bridge" || profile.External.TorBridge == nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", errors.New("profile is not a Tor bridge node")
	}
	cfg := *profile.External.TorBridge
	cfg.Bridges = append([]string(nil), profile.External.TorBridge.Bridges...)
	transports, firstHost, err := torRuntimeBridgeTransports(cfg)
	if err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", err
	}
	if cfg.Transport != "custom" {
		if len(transports) != 1 || cfg.Transport != transports[0] {
			return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", errors.New("normalized Tor transport identity is inconsistent")
		}
	}
	return profile, cfg, transports, firstHost, nil
}

func torrcQuote(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("Tor runtime path is empty or unsafe")
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`, nil
}

func prepareTorBridgeRuntime(root string, policy, profile common.RouterProfile) (torBridgeRuntime, error) {
	cap := torBridgeRuntimeCapabilityForRoot(root)
	if !cap.Supported {
		return torBridgeRuntime{}, errors.New(cap.Reason)
	}
	profile, cfg, transports, bridgeHost, err := torBridgeProfile(profile)
	if err != nil {
		return torBridgeRuntime{}, err
	}
	killPolicy := strings.ToLower(strings.TrimSpace(policy.KillSwitchPolicy))
	if killPolicy == "" {
		if policy.KillSwitch {
			killPolicy = "on-connect"
		} else {
			killPolicy = "off"
		}
	}
	strictLiteralObfs4 := cfg.Transport == "obfs4" && len(cfg.Bridges) == 1 && len(transports) == 1 && transports[0] == "obfs4"
	if !strictLiteralObfs4 && killPolicy != "off" {
		return torBridgeRuntime{}, fmt.Errorf("Tor %s bridge set uses multiple or dynamic/CDN/WebRTC bootstrap egress that Router VPN cannot safely pre-whitelist yet; set this profile kill switch Off or use one obfs4 bridge so strict pre-tunnel leak protection remains truthful", cfg.Transport)
	}
	bridgeFields := strings.Fields(cfg.Bridges[0])
	_, bridgePort, err := net.SplitHostPort(bridgeFields[1])
	if err != nil {
		return torBridgeRuntime{}, err
	}
	bridgeEndpoint := net.JoinHostPort(bridgeHost, bridgePort)

	var torBinary, ptBinary, singBoxBinary string
	if runtime.GOOS == "windows" {
		torBinary, err = windowsTorRuntimeExecutable(root, "tor.exe")
		if err == nil {
			ptBinary, err = windowsTorRuntimeExecutable(root, "lyrebird.exe")
		}
		if err == nil {
			singBoxBinary, err = windowsTorRuntimeExecutable(root, "sing-box.exe")
		}
	} else {
		torBinary, err = safeExecutable("tor")
		if err == nil {
			ptBinary, err = torBridgeTransportBinary(transports)
		}
		if err == nil {
			singBoxBinary, err = safeExecutable("sing-box")
		}
	}
	if err != nil {
		return torBridgeRuntime{}, err
	}

	runtimeDir, err := newPrivateRuntimeDir(root, "tor-bridge")
	if err != nil {
		return torBridgeRuntime{}, err
	}
	cleanup := func(cause error) (torBridgeRuntime, error) {
		_ = os.RemoveAll(runtimeDir)
		return torBridgeRuntime{}, cause
	}
	dataDir := filepath.Join(runtimeDir, "tor-data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		return cleanup(err)
	}
	logPath := filepath.Join(runtimeDir, "tor.log")
	quotedData, err := torrcQuote(dataDir)
	if err != nil {
		return cleanup(err)
	}
	quotedPT, err := torrcQuote(ptBinary)
	if err != nil {
		return cleanup(err)
	}
	quotedLog, err := torrcQuote(logPath)
	if err != nil {
		return cleanup(err)
	}
	torrcLines := []string{
		"ClientOnly 1",
		"AvoidDiskWrites 1",
		"SafeLogging 1",
		fmt.Sprintf("SocksPort 127.0.0.1:%d", cfg.SocksPort),
		"DataDirectory " + quotedData,
		"UseBridges 1",
		"ClientTransportPlugin " + strings.Join(transports, ",") + " exec " + quotedPT,
	}
	for _, bridge := range cfg.Bridges {
		torrcLines = append(torrcLines, "Bridge "+bridge)
	}
	torrcLines = append(torrcLines, "Log notice file "+quotedLog)
	torrc := strings.Join(torrcLines, "\n") + "\n"
	if err := writePrivateRuntimeFile(filepath.Join(runtimeDir, "torrc"), []byte(torrc)); err != nil {
		return cleanup(err)
	}

	dnsServer, err := selectedTorBridgeDNS(policy)
	if err != nil {
		return cleanup(err)
	}
	outbound := map[string]any{
		"type": "socks", "tag": "custom-exit", "server": "127.0.0.1", "server_port": cfg.SocksPort, "version": "5",
	}
	singConfig := standardExitConfig(policy, dnsServer, nil, []any{outbound})
	raw, err := json.MarshalIndent(singConfig, "", "  ")
	if err != nil {
		return cleanup(err)
	}
	if len(raw) > 4<<20 {
		return cleanup(errors.New("Tor bridge sing-box config exceeds safety limit"))
	}
	if err := writePrivateRuntimeFile(filepath.Join(runtimeDir, "sing-box.json"), append(raw, '\n')); err != nil {
		return cleanup(err)
	}
	return torBridgeRuntime{
		RuntimeDir: runtimeDir, TorBinary: torBinary, PTBinary: ptBinary, SingBoxBinary: singBoxBinary,
		Transport: cfg.Transport, PluginTransports: append([]string(nil), transports...), BridgeEndpoint: bridgeHost, SocksPort: cfg.SocksPort,
	}, nil
}

func torBridgeCommand(a *app, policy, profile common.RouterProfile) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	prepared, err := prepareTorBridgeRuntime(root, policy, profile)
	if err != nil {
		return nil, err
	}
	if err := registerActiveDNSRuntimeConfig(a, profile.ID, "external-tor-bridge", filepath.Join(prepared.RuntimeDir, "sing-box.json")); err != nil {
		_ = os.RemoveAll(prepared.RuntimeDir)
		return nil, fmt.Errorf("register Tor DNS runtime identity: %w", err)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		helper := filepath.Join(root, "client", "native-tor-bridge-windows.ps1")
		if _, statErr := os.Stat(helper); statErr != nil {
			helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-tor-bridge-windows.ps1")
		}
		if st, statErr := os.Lstat(helper); statErr != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			_ = os.RemoveAll(prepared.RuntimeDir)
			return nil, errors.New("native Windows Tor bridge helper is missing or unsafe")
		}
		powershell, lookupErr := safeExecutable("powershell.exe")
		if lookupErr != nil {
			_ = os.RemoveAll(prepared.RuntimeDir)
			return nil, lookupErr
		}
		cmd = exec.Command(powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper,
			"-Action", "up",
			"-RuntimeDir", prepared.RuntimeDir,
			"-BridgeEndpoint", prepared.BridgeEndpoint,
			"-SocksPort", strconv.Itoa(prepared.SocksPort),
			"-TorBinary", prepared.TorBinary,
			"-PTBinary", prepared.PTBinary,
			"-SingBoxBinary", prepared.SingBoxBinary,
			"-TunnelAlias", "router-vpn-tor")
	} else {
		helper := filepath.Join(root, "modes", "native-tor-bridge.sh")
		if _, statErr := os.Stat(helper); statErr != nil {
			helper = filepath.Join(a.cfg.ScriptsDir, "native-tor-bridge.sh")
		}
		if st, statErr := os.Lstat(helper); statErr != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			_ = os.RemoveAll(prepared.RuntimeDir)
			return nil, errors.New("native Tor bridge helper is missing or unsafe")
		}
		cmd = exec.Command("bash", helper, "up", prepared.RuntimeDir, prepared.BridgeEndpoint, strconv.Itoa(prepared.SocksPort), prepared.TorBinary, prepared.SingBoxBinary)
	}
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"HOMEVPN_ROOT="+root,
		"HOMEVPN_PROFILE_ID="+profile.ID,
		"HOMEVPN_POLICY_PROFILE_ID="+profile.ID,
		"HOMEVPN_ENDPOINT="+prepared.BridgeEndpoint,
		"HOMEVPN_TOR_TRANSPORT="+prepared.Transport,
		"HOMEVPN_TOR_PLUGIN_TRANSPORTS="+strings.Join(prepared.PluginTransports, ","),
		"HOMEVPN_TOR_PT_BINARY="+prepared.PTBinary,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
