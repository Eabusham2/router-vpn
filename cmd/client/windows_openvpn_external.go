package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"router-vpn/internal/common"
)

func windowsOpenVPNRuntimeCapability() standardExitCapability {
	cap := standardExitCapability{Protocol: "openvpn", Implemented: true}
	if runtime.GOOS != "windows" {
		cap.Reason = "native Windows OpenVPN adapter is only used on Windows"
		return cap
	}
	binary, err := findOpenVPNBinary()
	if err != nil {
		cap.Reason = err.Error()
		return cap
	}
	if err = checkOpenVPN27(binary); err != nil {
		cap.Reason = err.Error()
		return cap
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	helper := filepath.Join(root, "client", "native-openvpn-windows.ps1")
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		cap.Reason = "native-openvpn-windows.ps1 is missing from the Router VPN package"
		return cap
	}
	cap.Supported = true
	return cap
}

func externalProfileProtocolCapabilities() []standardExitCapability {
	caps := standardExitCapabilities()
	if runtime.GOOS != "windows" {
		return caps
	}
	windows := windowsOpenVPNRuntimeCapability()
	for i := range caps {
		if caps[i].Protocol == "openvpn" {
			caps[i] = windows
			return caps
		}
	}
	return append(caps, windows)
}

func prepareWindowsOpenVPNRuntime(root string, control, entry common.RouterProfile, exit standardExit, direct bool) (string, string, error) {
	if runtime.GOOS != "windows" {
		return "", "", errors.New("Windows OpenVPN runtime requested on a non-Windows platform")
	}
	if err := normalizeOpenVPNStandardExit(&exit); err != nil {
		return "", "", err
	}
	binary, err := findOpenVPNBinary()
	if err != nil {
		return "", "", err
	}
	if err = checkOpenVPN27(binary); err != nil {
		return "", "", err
	}
	if !direct {
		if entry.ID == "" {
			return "", "", errors.New("OpenVPN hop requires a linked entry")
		}
		if !openVPNProtocolIsTCP(exit.Method) {
			return "", "", errors.New("hopped OpenVPN on Windows requires a TCP OpenVPN profile because the controlled entry bridge is SOCKS5")
		}
	}
	dnsLines, err := openVPNDNSLines(control, direct)
	if err != nil {
		return "", "", err
	}
	lanLines, err := openVPNLANLines(control)
	if err != nil {
		return "", "", err
	}
	dir, err := newOpenVPNRuntimeDir(root)
	if err != nil {
		return "", "", err
	}
	cleanup := func(e error) (string, string, error) { _ = os.RemoveAll(dir); return "", "", e }
	if !direct {
		if _, err = writeOpenVPNEntryBridge(root, dir, entry); err != nil {
			return cleanup(err)
		}
	}
	lines := []string{
		strings.TrimSpace(exit.OpenVPNConfig), "", "# Router VPN-owned Windows policy below",
		"script-security 1", "auth-nocache", "auth-retry nointeract", "route-nopull",
		"redirect-gateway def1", "pull-filter ignore \"redirect-gateway\"",
		"pull-filter ignore \"route \"", "pull-filter ignore \"route-ipv6\"",
		"pull-filter ignore \"dhcp-option DNS\"", "pull-filter ignore \"dns \"",
		"connect-retry-max 1", "dev tun",
	}
	if !direct {
		lines = append(lines, fmt.Sprintf("socks-proxy 127.0.0.1 %d", openVPNEntrySOCKSPort))
	}
	if strings.ToLower(strings.TrimSpace(control.IPv6Mode)) == "off" {
		lines = append(lines, "block-ipv6")
	} else {
		lines = append(lines, "redirect-gateway ipv6")
	}
	lines = append(lines, dnsLines...)
	lines = append(lines, lanLines...)
	if exit.Username != "" {
		auth := filepath.Join(dir, "auth.txt")
		if err = writePrivateFile(auth, exit.Username+"\r\n"+exit.Password+"\r\n"); err != nil {
			return cleanup(err)
		}
		quoted := strings.ReplaceAll(strings.ReplaceAll(auth, `\`, `\\`), `"`, `\"`)
		lines = append(lines, `auth-user-pass "`+quoted+`"`)
	}
	configPath := filepath.Join(dir, "client.ovpn")
	if err = writePrivateFile(configPath, strings.Join(lines, "\r\n")+"\r\n"); err != nil {
		return cleanup(err)
	}
	return dir, binary, nil
}

func windowsOpenVPNStandardExitCommand(a *app, control, entry common.RouterProfile, exit standardExit, direct bool) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	dir, binary, err := prepareWindowsOpenVPNRuntime(root, control, entry, exit, direct)
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(root, "client", "native-openvpn-windows.ps1")
	if _, err = os.Stat(helper); err != nil {
		helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-openvpn-windows.ps1")
	}
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		_ = os.RemoveAll(dir)
		return nil, errors.New("native Windows OpenVPN helper is missing")
	}
	endpoint := exit.Server
	runtimeProfileID := control.ID
	if !direct {
		endpoint = entry.Endpoint
		runtimeProfileID = entry.ID
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", dir, "-Endpoint", endpoint, "-OpenVPNBin", binary)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+runtimeProfileID, "HOMEVPN_POLICY_PROFILE_ID="+control.ID, "HOMEVPN_ENDPOINT="+endpoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
