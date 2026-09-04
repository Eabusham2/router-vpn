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
	RuntimeDir     string
	TorBinary      string
	PTBinary       string
	SingBoxBinary  string
	Transport      string
	BridgeEndpoint string
	SocksPort      int
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

func torBridgeTransportBinary(transport string) (string, error) {
	if path, err := safeExecutable("lyrebird"); err == nil {
		return path, nil
	}
	if transport == "obfs4" || transport == "meek_lite" {
		if path, err := safeExecutable("obfs4proxy"); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("Tor %s requires lyrebird (preferred) or obfs4proxy", transport)
	}
	return "", fmt.Errorf("Tor %s requires lyrebird; legacy obfs4proxy cannot provide this transport", transport)
}

func torBridgeRuntimeCapability() standardExitCapability {
	cap := standardExitCapability{Protocol: "tor-bridge", Implemented: true}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		cap.Reason = "Tor pluggable-transport full-device runtime is currently implemented on Linux/macOS only; this platform remains unavailable instead of faking Tor"
		return cap
	}
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
}

func torBridgeProfile(profile common.RouterProfile) (common.RouterProfile, common.ExternalTorBridgeConfig, string, error) {
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", err
	}
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "tor-bridge" || profile.External.TorBridge == nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("profile is not a Tor bridge node")
	}
	cfg := *profile.External.TorBridge
	cfg.Bridges = append([]string(nil), profile.External.TorBridge.Bridges...)
	if len(cfg.Bridges) != 1 {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("current strict Tor runtime requires exactly one bridge line per profile; create separate profiles for additional bridges")
	}
	transport, err := common.TorBridgeTransport(&cfg)
	if err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", err
	}
	if cfg.Transport != transport {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("normalized Tor transport identity is inconsistent")
	}
	fields := strings.Fields(cfg.Bridges[0])
	if len(fields) < 3 || fields[0] != transport {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("normalized Tor bridge line is invalid")
	}
	host, port, err := net.SplitHostPort(fields[1])
	if err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("normalized Tor bridge endpoint is invalid")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("Tor bridge endpoint must remain a safe literal IP")
	}
	if transport == "obfs4" && ip.IsPrivate() {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("Tor obfs4 physical endpoint must remain a public literal IP")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("Tor bridge endpoint port is invalid")
	}
	return profile, cfg, ip.String(), nil
}

func torrcQuote(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("Tor runtime path is empty or unsafe")
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`, nil
}

func prepareTorBridgeRuntime(root string, policy, profile common.RouterProfile) (torBridgeRuntime, error) {
	cap := torBridgeRuntimeCapability()
	if !cap.Supported {
		return torBridgeRuntime{}, errors.New(cap.Reason)
	}
	profile, cfg, bridgeHost, err := torBridgeProfile(profile)
	if err != nil {
		return torBridgeRuntime{}, err
	}
	transport := cfg.Transport
	killPolicy := strings.ToLower(strings.TrimSpace(policy.KillSwitchPolicy))
	if killPolicy == "" {
		if policy.KillSwitch {
			killPolicy = "on-connect"
		} else {
			killPolicy = "off"
		}
	}
	if transport != "obfs4" && killPolicy != "off" {
		return torBridgeRuntime{}, fmt.Errorf("Tor %s uses dynamic/CDN/WebRTC bootstrap egress that Router VPN cannot safely pre-whitelist yet; set this profile kill switch Off or use obfs4 so strict pre-tunnel leak protection remains truthful", transport)
	}
	bridgeFields := strings.Fields(cfg.Bridges[0])
	_, bridgePort, err := net.SplitHostPort(bridgeFields[1])
	if err != nil {
		return torBridgeRuntime{}, err
	}
	bridgeEndpoint := net.JoinHostPort(bridgeHost, bridgePort)

	torBinary, err := safeExecutable("tor")
	if err != nil {
		return torBridgeRuntime{}, err
	}
	ptBinary, err := torBridgeTransportBinary(transport)
	if err != nil {
		return torBridgeRuntime{}, err
	}
	singBoxBinary, err := safeExecutable("sing-box")
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
	torrc := strings.Join([]string{
		"ClientOnly 1",
		"AvoidDiskWrites 1",
		"SafeLogging 1",
		fmt.Sprintf("SocksPort 127.0.0.1:%d", cfg.SocksPort),
		"DataDirectory " + quotedData,
		"UseBridges 1",
		"ClientTransportPlugin " + transport + " exec " + quotedPT,
		"Bridge " + cfg.Bridges[0],
		"Log notice file " + quotedLog,
	}, "\n") + "\n"
	if err := writePrivateRuntimeFile(filepath.Join(runtimeDir, "torrc"), []byte(torrc)); err != nil {
		return cleanup(err)
	}

	dnsServer, err := selectedStandardExitDNS(policy, true)
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
		Transport: transport, BridgeEndpoint: bridgeHost, SocksPort: cfg.SocksPort,
	}, nil
}

func torBridgeCommand(a *app, policy, profile common.RouterProfile) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	prepared, err := prepareTorBridgeRuntime(root, policy, profile)
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(root, "modes", "native-tor-bridge.sh")
	if _, err = os.Stat(helper); err != nil {
		helper = filepath.Join(a.cfg.ScriptsDir, "native-tor-bridge.sh")
	}
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		_ = os.RemoveAll(prepared.RuntimeDir)
		return nil, errors.New("native Tor bridge helper is missing")
	}
	if err := registerActiveDNSRuntimeConfig(a, profile.ID, "external-tor-bridge", filepath.Join(prepared.RuntimeDir, "sing-box.json")); err != nil {
		_ = os.RemoveAll(prepared.RuntimeDir)
		return nil, fmt.Errorf("register Tor DNS runtime identity: %w", err)
	}
	cmd := exec.Command("bash", helper, "up", prepared.RuntimeDir, prepared.BridgeEndpoint, strconv.Itoa(prepared.SocksPort), prepared.TorBinary, prepared.SingBoxBinary)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"HOMEVPN_ROOT="+root,
		"HOMEVPN_PROFILE_ID="+profile.ID,
		"HOMEVPN_POLICY_PROFILE_ID="+profile.ID,
		"HOMEVPN_ENDPOINT="+prepared.BridgeEndpoint,
		"HOMEVPN_TOR_TRANSPORT="+prepared.Transport,
		"HOMEVPN_TOR_PT_BINARY="+prepared.PTBinary,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
