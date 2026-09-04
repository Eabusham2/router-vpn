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
	Obfs4Binary    string
	SingBoxBinary  string
	BridgeEndpoint string
	SocksPort      int
}

func torBridgeRuntimeCapability() standardExitCapability {
	cap := standardExitCapability{Protocol: "tor-bridge", Implemented: true}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		cap.Reason = "Tor obfs4 bridge full-device runtime is currently implemented on Linux/macOS only; this platform remains unavailable instead of faking Tor"
		return cap
	}
	for _, binary := range []string{"tor", "obfs4proxy", "sing-box"} {
		path, err := exec.LookPath(binary)
		if err != nil || strings.TrimSpace(path) == "" {
			cap.Reason = binary + " is required for the real Tor obfs4 bridge runtime"
			return cap
		}
		if strings.ContainsAny(path, "\r\n\x00") {
			cap.Reason = binary + " resolved to an unsafe executable path"
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
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("profile is not a Tor obfs4 bridge node")
	}
	cfg := *profile.External.TorBridge
	cfg.Bridges = append([]string(nil), profile.External.TorBridge.Bridges...)
	if len(cfg.Bridges) != 1 {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("current strict Tor runtime requires exactly one obfs4 bridge per profile so the kill switch owns exactly that physical public endpoint; create separate Tor profiles for additional bridges")
	}
	fields := strings.Fields(cfg.Bridges[0])
	if len(fields) < 3 || fields[0] != "obfs4" {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("normalized Tor bridge line is invalid")
	}
	host, port, err := net.SplitHostPort(fields[1])
	if err != nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("normalized Tor bridge endpoint is invalid")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("Tor bridge physical endpoint must remain a public literal IP")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, "", errors.New("Tor bridge physical endpoint port is invalid")
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
	bridgeFields := strings.Fields(cfg.Bridges[0])
	_, bridgePort, err := net.SplitHostPort(bridgeFields[1])
	if err != nil {
		return torBridgeRuntime{}, err
	}
	bridgeEndpoint := net.JoinHostPort(bridgeHost, bridgePort)

	torBinary, _ := exec.LookPath("tor")
	obfs4Binary, _ := exec.LookPath("obfs4proxy")
	singBoxBinary, _ := exec.LookPath("sing-box")
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
	if err != nil { return cleanup(err) }
	quotedObfs4, err := torrcQuote(obfs4Binary)
	if err != nil { return cleanup(err) }
	quotedLog, err := torrcQuote(logPath)
	if err != nil { return cleanup(err) }
	torrc := strings.Join([]string{
		"ClientOnly 1",
		"AvoidDiskWrites 1",
		"SafeLogging 1",
		fmt.Sprintf("SocksPort 127.0.0.1:%d", cfg.SocksPort),
		"DataDirectory " + quotedData,
		"UseBridges 1",
		"ClientTransportPlugin obfs4 exec " + quotedObfs4,
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
	if err != nil { return cleanup(err) }
	if len(raw) > 4<<20 { return cleanup(errors.New("Tor bridge sing-box config exceeds safety limit")) }
	if err := writePrivateRuntimeFile(filepath.Join(runtimeDir, "sing-box.json"), append(raw, '\n')); err != nil {
		return cleanup(err)
	}
	return torBridgeRuntime{
		RuntimeDir: runtimeDir, TorBinary: torBinary, Obfs4Binary: obfs4Binary, SingBoxBinary: singBoxBinary,
		BridgeEndpoint: bridgeHost, SocksPort: cfg.SocksPort,
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
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
