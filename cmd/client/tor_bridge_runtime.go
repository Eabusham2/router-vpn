package main

import (
	"errors"
	"fmt"
	"net"
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
	NativeBinary     string
	TorSHA256        string
	Transport        string
	PluginTransports []string
	BridgeEndpoint   string
	SocksPort        int
	Launch           *desktopNodeLaunch
}

func desktopTorProtocol(protocol string) bool {
	return protocol == "tor" || protocol == "tor-bridge"
}

func desktopTorRuntimeID(mode string) bool {
	return mode == "external-tor" || mode == "external-tor-bridge"
}

func desktopTorProfileRuntime(profile common.RouterProfile) string {
	if profile.External == nil || !desktopTorProtocol(profile.External.Protocol) {
		return ""
	}
	return "external-" + profile.External.Protocol
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

func desktopTorExecutable(root string) (string, error) {
	var path string
	var err error
	switch runtime.GOOS {
	case "windows":
		if _, err = windowsTorHostCompatibility(); err != nil {
			return "", err
		}
		path, err = windowsTorRuntimeExecutable(root, "tor.exe")
	case "linux", "darwin":
		path, err = safeExecutable("tor")
	default:
		return "", errors.New("standalone native Tor is unavailable on this platform")
	}
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve platform package-manager links once. Every later admission uses
	// this canonical regular executable and its separately captured byte hash.
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return safePinnedRuntimeExecutable(path, "captured standalone Tor")
}

func torBridgeRuntimeCapabilityForRoot(root string) standardExitCapability {
	return torBridgeRuntimeCapabilityForExecution(root, "local")
}

func torBridgeRuntimeCapabilityForExecution(root, execution string) standardExitCapability {
	cap := standardExitCapability{Protocol: "tor-bridge", Implemented: true}
	if desktopTorExecution(execution) == "" || runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		cap.Reason = "Tor requires a supported native desktop execution owner"
		return cap
	}
	if execution != "server" {
		if _, err := desktopTorExecutable(root); err != nil {
			cap.Reason = err.Error()
			return cap
		}
	}
	if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
		cap.Reason = "the verified Router VPN native engine is required for Tor transports: " + err.Error()
		return cap
	}
	cap.Supported = true
	return cap
}

func desktopTorPolicyRuntimeCapability(policy common.RouterProfile) standardExitCapability {
	return torBridgeRuntimeCapabilityForExecution(filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client")), policy.MultihopExecution)
}

func torBridgeRuntimeCapability() standardExitCapability {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	local := torBridgeRuntimeCapabilityForRoot(root)
	if local.Supported {
		return local
	}
	if server := torBridgeRuntimeCapabilityForExecution(root, "server"); server.Supported {
		return server
	}
	return local
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
	if profile.NodeKind != "external" || profile.External == nil || !desktopTorProtocol(profile.External.Protocol) {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", errors.New("profile is not a Tor node")
	}
	if profile.External.Protocol == "tor" {
		// Plain Tor has no fixed guard endpoint or bridge credentials. The
		// owned native proxy selects actual guards inside the captured path.
		return profile, common.ExternalTorBridgeConfig{Transport: "tor", SocksPort: common.ExternalTorDefaultSocksPort}, nil, "", nil
	}
	if profile.External.TorBridge == nil {
		return common.RouterProfile{}, common.ExternalTorBridgeConfig{}, nil, "", errors.New("Tor bridge node lost its bridge selection")
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
