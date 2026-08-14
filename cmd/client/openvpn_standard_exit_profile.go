package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const openVPNMaxConfig = 256 << 10

type openVPNParsed struct {
	Clean  string
	Server string
	Port   int
	Proto  string
}

func normalizeOpenVPNProto(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "udp", "udp4", "udp6":
		if value == "" { value = "udp" }
		return value, nil
	case "tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client":
		if value == "tcp" { value = "tcp-client" }
		if value == "tcp4" { value = "tcp4-client" }
		if value == "tcp6" { value = "tcp6-client" }
		return value, nil
	default:
		return "", fmt.Errorf("unsupported OpenVPN client protocol %q", value)
	}
}

func parseOpenVPNRemote(fields []string, fallbackProto string) (host string, port int, proto string, err error) {
	if len(fields) < 2 || len(fields) > 4 { return "", 0, "", errors.New("OpenVPN remote directive is invalid") }
	host, err = normalizeEndpoint(fields[1])
	if err != nil { return "", 0, "", fmt.Errorf("OpenVPN remote: %w", err) }
	// A strict pre-connect kill switch cannot depend on an ordinary system-DNS
	// lookup. Hostname support can be added later with an explicitly pinned
	// pre-resolver; until then a literal remote keeps the exception truthful.
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		return "", 0, "", errors.New("OpenVPN custom exit currently requires a literal remote IPv4/IPv6 address for fail-closed pre-tunnel routing")
	}
	port = 1194
	if len(fields) >= 3 {
		p, parseErr := strconv.Atoi(fields[2])
		if parseErr != nil || p < 1 || p > 65535 { return "", 0, "", errors.New("OpenVPN remote port is invalid") }
		port = p
	}
	proto = fallbackProto
	if len(fields) == 4 { proto = fields[3] }
	proto, err = normalizeOpenVPNProto(proto)
	return
}

// sanitizeOpenVPNConfig treats imported .ovpn text strictly as untrusted data.
// Router VPN can run an OpenVPN client with elevated networking privileges, so
// an import may not execute scripts/plugins, include arbitrary host files,
// create management listeners, choose its own proxy/DNS/routing policy, or use
// a Layer-2 TAP device. Certificate/key material must be inline.
func sanitizeOpenVPNConfig(raw string) (openVPNParsed, error) {
	if strings.TrimSpace(raw) == "" { return openVPNParsed{}, errors.New("OpenVPN custom exit requires openvpn_config") }
	if len(raw) > openVPNMaxConfig { return openVPNParsed{}, errors.New("OpenVPN config exceeds 256 KiB") }
	if strings.IndexByte(raw, 0) >= 0 { return openVPNParsed{}, errors.New("OpenVPN config contains NUL bytes") }

	blocked := map[string]bool{
		"script-security": true, "up": true, "down": true, "down-pre": true,
		"route-up": true, "route-pre-down": true, "ipchange": true,
		"client-connect": true, "client-disconnect": true, "learn-address": true,
		"auth-user-pass-verify": true, "tls-verify": true, "plugin": true,
		"config": true, "management": true, "management-client-auth": true,
		"management-external-key": true, "management-external-cert": true,
		"management-query-passwords": true, "management-hold": true,
		"management-signal": true, "iproute": true, "log": true,
		"log-append": true, "status": true, "status-version": true,
		"writepid": true, "tmp-dir": true, "cd": true, "chroot": true,
		"user": true, "group": true, "daemon": true, "askpass": true,
		"auth-user-pass": true, "auth-retry": true, "http-proxy": true,
		"http-proxy-option": true, "http-proxy-user-pass": true,
		"socks-proxy": true, "tls-export-cert": true, "pkcs11-providers": true,
		"pkcs11-id": true, "cryptoapicert": true, "engine": true,
		"ca": true, "cert": true, "key": true, "pkcs12": true,
		"tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
		"secret": true, "crl-verify": true, "dh": true, "extra-certs": true,
		"peer-fingerprint": true, "verify-hash": true,
		"dev": true, "dev-node": true, "dev-type": true,
		"route": true, "route-ipv6": true, "route-gateway": true,
		"route-ipv6-gateway": true, "route-nopull": true,
		"redirect-gateway": true, "redirect-private": true,
		"pull-filter": true, "allow-pull-fqdn": true,
		"block-outside-dns": true, "register-dns": true,
		"dhcp-option": true, "dns": true, "dns-updown": true,
		"setenv": true, "setenv-safe": true, "env-filter": true,
		"remote-random": true, "remote-random-hostname": true,
		"compress": true, "comp-lzo": true, "capath": true,
		"auth-gen-token-secret": true, "tls-crypt-v2-verify": true,
	}
	inlineEnd := map[string]string{
		"<ca>": "</ca>", "<cert>": "</cert>", "<key>": "</key>",
		"<pkcs12>": "</pkcs12>", "<tls-auth>": "</tls-auth>",
		"<tls-crypt>": "</tls-crypt>", "<tls-crypt-v2>": "</tls-crypt-v2>",
		"<extra-certs>": "</extra-certs>", "<peer-fingerprint>": "</peer-fingerprint>",
	}

	globalProto := "udp"
	remoteCount := 0
	remoteHost := ""
	remotePort := 0
	remoteProto := ""
	activeInline := ""
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(raw, "\r\n", "\n")))
	scanner.Buffer(make([]byte, 64<<10), openVPNMaxConfig)
	for scanner.Scan() {
		original := scanner.Text()
		line := strings.TrimSpace(original)
		lower := strings.ToLower(line)
		if activeInline != "" {
			out = append(out, original)
			if lower == inlineEnd[activeInline] { activeInline = "" }
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			out = append(out, original)
			continue
		}
		if _, ok := inlineEnd[lower]; ok {
			activeInline = lower
			out = append(out, original)
			continue
		}
		if strings.HasPrefix(lower, "<connection") || strings.HasPrefix(lower, "</connection") {
			return openVPNParsed{}, errors.New("OpenVPN <connection> blocks are not accepted; import one deterministic remote endpoint")
		}
		if strings.HasPrefix(lower, "<") {
			return openVPNParsed{}, fmt.Errorf("OpenVPN inline block %q is not allowed in Router VPN imports", line)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 { continue }
		directive := strings.ToLower(fields[0])
		if blocked[directive] { return openVPNParsed{}, fmt.Errorf("OpenVPN directive %q is not allowed in Router VPN imports", directive) }
		switch directive {
		case "proto":
			if len(fields) != 2 { return openVPNParsed{}, errors.New("OpenVPN proto directive is invalid") }
			p, err := normalizeOpenVPNProto(fields[1]); if err != nil { return openVPNParsed{}, err }
			globalProto = p
		case "remote":
			h, p, proto, err := parseOpenVPNRemote(fields, globalProto); if err != nil { return openVPNParsed{}, err }
			remoteCount++; remoteHost, remotePort, remoteProto = h, p, proto
		case "mode":
			if len(fields) > 1 && strings.ToLower(fields[1]) != "p2p" { return openVPNParsed{}, errors.New("OpenVPN server mode is not accepted") }
		case "server", "server-bridge", "server-ipv6", "ifconfig-pool", "ifconfig-pool-persist":
			return openVPNParsed{}, errors.New("OpenVPN server-mode directives are not accepted")
		}
		out = append(out, original)
	}
	if err := scanner.Err(); err != nil { return openVPNParsed{}, fmt.Errorf("OpenVPN config read failed: %w", err) }
	if activeInline != "" { return openVPNParsed{}, fmt.Errorf("OpenVPN inline block %s is not closed", activeInline) }
	if remoteCount != 1 { return openVPNParsed{}, fmt.Errorf("OpenVPN custom exit requires exactly one remote directive; found %d", remoteCount) }
	if remoteProto == "" { remoteProto = globalProto }
	return openVPNParsed{Clean: strings.Join(out, "\n") + "\n", Server: remoteHost, Port: remotePort, Proto: remoteProto}, nil
}

func normalizeOpenVPNStandardExit(e *standardExit) error {
	parsed, err := sanitizeOpenVPNConfig(e.OpenVPNConfig)
	if err != nil { return err }
	e.OpenVPNConfig = parsed.Clean
	e.Server = parsed.Server
	e.ServerPort = parsed.Port
	e.Method = parsed.Proto
	if (e.Username == "") != (e.Password == "") { return errors.New("OpenVPN username/password must either both be set or both be empty") }
	return nil
}

func findOpenVPNBinary() (string, error) {
	candidates := []string{}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("ProgramFiles"); v != "" { candidates = append(candidates, filepath.Join(v, "OpenVPN", "bin", "openvpn.exe")) }
		if v := os.Getenv("ProgramFiles(x86)"); v != "" { candidates = append(candidates, filepath.Join(v, "OpenVPN", "bin", "openvpn.exe")) }
		candidates = append(candidates, "openvpn.exe")
	} else {
		candidates = append(candidates, "openvpn", "/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/opt/homebrew/sbin/openvpn", "/opt/homebrew/bin/openvpn", "/usr/local/bin/openvpn")
	}
	for _, candidate := range candidates {
		if strings.ContainsRune(candidate, os.PathSeparator) {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() { return candidate, nil }
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil { return path, nil }
	}
	return "", errors.New("OpenVPN 2.7.x runtime was not found")
}

func checkOpenVPN27(path string) error {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil { return fmt.Errorf("OpenVPN runtime check failed: %w", err) }
	first := strings.SplitN(string(out), "\n", 2)[0]
	if !strings.Contains(first, "OpenVPN 2.7.") { return fmt.Errorf("Router VPN OpenVPN adapter requires stable OpenVPN 2.7.x; found %q", strings.TrimSpace(first)) }
	return nil
}

func openVPNRuntimeCapability() standardExitCapability {
	if runtime.GOOS == "android" || runtime.GOOS == "ios" { return standardExitCapability{Protocol: "openvpn", Supported: false, Reason: "native OpenVPN custom-exit engine is not implemented on this mobile platform yet"} }
	if runtime.GOOS == "windows" { return standardExitCapability{Protocol: "openvpn", Supported: false, Reason: "OpenVPN profile import is implemented, but strict Windows lifecycle cleanup is not release-ready yet; use Linux/macOS until the Windows adapter passes native leak tests"} }
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" { return standardExitCapability{Protocol: "openvpn", Supported: false, Reason: "native OpenVPN custom-exit runtime is currently implemented on Linux and macOS"} }
	path, err := findOpenVPNBinary()
	if err != nil { return standardExitCapability{Protocol: "openvpn", Supported: false, Reason: err.Error()} }
	if err = checkOpenVPN27(path); err != nil { return standardExitCapability{Protocol: "openvpn", Supported: false, Reason: err.Error()} }
	return standardExitCapability{Protocol: "openvpn", Supported: true}
}
