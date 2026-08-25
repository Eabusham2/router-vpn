package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

func openVPNDNSLines(control common.RouterProfile, direct bool) ([]string, error) {
	mode := strings.ToLower(strings.TrimSpace(control.DNSMode))
	protocol := strings.ToLower(strings.TrimSpace(control.DNSProtocol))
	host := strings.TrimSpace(control.DNSHost)
	port := control.DNSPort
	sni := strings.TrimSpace(control.DNSServerName)
	if mode == "" {
		mode = "home"
	}
	switch mode {
	case "home":
		// A chained OpenVPN data channel is carried through the entry WireGuard
		// endpoint by a loopback SOCKS bridge, but that bridge is not an OS route
		// to the entry node's private AdGuard address. Do not pretend 10.77/10.78
		// DNS remains reachable after OpenVPN owns the default route.
		if direct {
			return nil, errors.New("Home AdGuard DNS requires a Router VPN DNS bridge; choose Fastest, Custom, DoH, DoT or Rescue for a direct OpenVPN exit")
		}
		return nil, errors.New("Home AdGuard DNS over a Router VPN -> OpenVPN hop is not enabled until private DNS is explicitly bridged through the entry; choose Fastest, Custom, DoH, DoT or Rescue")
	case "fastest":
		host = strings.TrimSpace(control.FastestDNSHost)
		protocol, port, sni = "udp", 53, ""
	case "doh":
		protocol = "doh"
		if port == 0 {
			port = 443
		}
	case "dot":
		protocol = "dot"
		if port == 0 {
			port = 853
		}
	case "doh3":
		return nil, errors.New("OpenVPN 2.7 does not expose a DoH3 DNS transport; choose DoH/DoT/plain DNS or use a Router VPN sing-box mode")
	case "rescue":
		protocol = "doh"
		if host == "" {
			host = "1.1.1.1"
		}
		if port == 0 {
			port = 443
		}
		if sni == "" {
			sni = "cloudflare-dns.com"
		}
	case "custom":
		if protocol == "https" {
			protocol = "doh"
		}
		if protocol == "tls" {
			protocol = "dot"
		}
		if protocol == "h3" {
			return nil, errors.New("OpenVPN 2.7 does not expose a DoH3 DNS transport")
		}
		if port == 0 {
			if protocol == "doh" {
				port = 443
			} else if protocol == "dot" {
				port = 853
			} else {
				port = 53
			}
		}
	default:
		return nil, fmt.Errorf("unsupported DNS mode %q for OpenVPN custom exit", mode)
	}
	if host == "" {
		return nil, errors.New("selected OpenVPN DNS server is empty")
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return nil, errors.New("OpenVPN custom exit requires a literal selected DNS address")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("selected DNS port is invalid")
	}
	addr := host
	if strings.Contains(host, ":") {
		addr = "[" + host + "]"
	}
	addr = fmt.Sprintf("%s:%d", addr, port)
	transport := "plain"
	if protocol == "doh" {
		transport = "DoH"
	}
	if protocol == "dot" {
		transport = "DoT"
	}
	if (transport == "DoH" || transport == "DoT") && sni == "" {
		return nil, errors.New("encrypted OpenVPN DNS requires a TLS server name")
	}
	if sni != "" && strings.ContainsAny(sni, " \t\r\n#;\"") {
		return nil, errors.New("OpenVPN DNS TLS server name contains unsafe characters")
	}
	lines := []string{fmt.Sprintf("dns server -1 address %s", addr), fmt.Sprintf("dns server -1 transport %s", transport)}
	if sni != "" {
		lines = append(lines, fmt.Sprintf("dns server -1 sni %s", sni))
	}
	return lines, nil
}

func openVPNLANLines(control common.RouterProfile) ([]string, error) {
	if !control.HomeLANAccess {
		return nil, nil
	}
	lines := []string{}
	for _, raw := range control.HomeLANCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid home LAN CIDR %q", raw)
		}
		if network.IP.To4() != nil {
			mask := net.IP(network.Mask).String()
			lines = append(lines, fmt.Sprintf("route %s %s net_gateway", network.IP.String(), mask))
		} else {
			ones, _ := network.Mask.Size()
			lines = append(lines, fmt.Sprintf("route-ipv6 %s/%d net_gateway", network.IP.String(), ones))
		}
	}
	return lines, nil
}

func writePrivateFile(path, text string) error {
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func openVPNProtocolIsTCP(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "tcp-client", "tcp4", "tcp4-client", "tcp6", "tcp6-client":
		return true
	default:
		return false
	}
}

func prepareOpenVPNRuntime(root string, control, entry common.RouterProfile, exit standardExit, direct bool) (string, string, error) {
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
			return "", "", errors.New("OpenVPN hop requires a linked Router VPN entry")
		}
		if !openVPNProtocolIsTCP(exit.Method) {
			return "", "", errors.New("Router VPN -> external OpenVPN hopping currently supports TCP OpenVPN profiles only because OpenVPN SOCKS5 transport is TCP; UDP profiles remain unavailable instead of leaking around the entry")
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
	configPath := filepath.Join(dir, "client.ovpn")
	lines := []string{
		strings.TrimSpace(exit.OpenVPNConfig), "", "# Router VPN-owned policy below",
		"script-security 1", "auth-nocache", "auth-retry nointeract", "route-nopull",
		"redirect-gateway def1", "pull-filter ignore \"redirect-gateway\"",
		"pull-filter ignore \"route \"", "pull-filter ignore \"route-ipv6\"",
		"pull-filter ignore \"dhcp-option DNS\"", "pull-filter ignore \"dns \"", "connect-retry-max 1",
	}
	if !direct {
		lines = append(lines, fmt.Sprintf("socks-proxy 127.0.0.1 %d", openVPNEntrySOCKSPort))
	}
	if strings.ToLower(strings.TrimSpace(control.IPv6Mode)) == "off" {
		lines = append(lines, "block-ipv6")
	} else {
		lines = append(lines, "redirect-gateway ipv6")
	}
	if runtime.GOOS == "linux" {
		lines = append(lines, "dev router-vpn", "dev-type tun")
	} else {
		lines = append(lines, "dev tun", "dev-node utun")
	}
	lines = append(lines, dnsLines...)
	lines = append(lines, lanLines...)
	if exit.Username != "" {
		auth := filepath.Join(dir, "auth.txt")
		if err = writePrivateFile(auth, exit.Username+"\n"+exit.Password+"\n"); err != nil {
			return cleanup(err)
		}
		quotedAuth := strings.ReplaceAll(strings.ReplaceAll(auth, `\`, `\\`), `"`, `\"`)
		lines = append(lines, `auth-user-pass "`+quotedAuth+`"`)
	}
	if err = writePrivateFile(configPath, strings.Join(lines, "\n")+"\n"); err != nil {
		return cleanup(err)
	}
	return dir, binary, nil
}

func openVPNStandardExitCommand(a *app, control, entry common.RouterProfile, exit standardExit, direct bool) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	dir, binary, err := prepareOpenVPNRuntime(root, control, entry, exit, direct)
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(root, "modes", "native-openvpn-standard-exit.sh")
	if _, err = os.Stat(helper); err != nil {
		helper = filepath.Join(a.cfg.ScriptsDir, "native-openvpn-standard-exit.sh")
	}
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		_ = os.RemoveAll(dir)
		return nil, errors.New("native OpenVPN standard-exit helper is missing")
	}
	endpoint := exit.Server
	runtimeProfileID := control.ID
	if !direct {
		endpoint = entry.Endpoint
		runtimeProfileID = entry.ID
	}
	cmd := exec.Command("bash", helper, "up", dir, endpoint, binary)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+runtimeProfileID, "HOMEVPN_POLICY_PROFILE_ID="+control.ID, "HOMEVPN_ENDPOINT="+endpoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func proveOpenVPNStandardExit(expected string) error {
	expectedIP := net.ParseIP(strings.TrimSpace(expected))
	if expectedIP == nil {
		return errors.New("expected public exit IP is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
	endpoints := []string{"https://api64.ipify.org", "https://api.ipify.org"}
	deadline := time.Now().Add(14 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		for _, endpoint := range endpoints {
			resp, err := client.Get(endpoint)
			if err != nil {
				last = err
				continue
			}
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
			_ = resp.Body.Close()
			if readErr != nil {
				last = readErr
				continue
			}
			if resp.StatusCode/100 != 2 {
				last = fmt.Errorf("OpenVPN exit proof returned HTTP %d", resp.StatusCode)
				continue
			}
			observed := net.ParseIP(strings.TrimSpace(string(raw)))
			if observed == nil {
				last = errors.New("OpenVPN exit proof returned a non-IP value")
				continue
			}
			if observed.Equal(expectedIP) {
				return nil
			}
			last = fmt.Errorf("OpenVPN custom exit reached public address %s, expected %s", observed.String(), expectedIP.String())
		}
		time.Sleep(250 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("OpenVPN public exit proof timed out")
	}
	return last
}

func registerStandardExitDispatchRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/standard-exit/connect", a.standardExitConnectDispatch)
}

func (a *app) standardExitConnectDispatch(w http.ResponseWriter, r *http.Request) {
	_, finish, guardErr := a.beginConnectionOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer finish()

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var q standardExitConnectRequest
	if err = json.Unmarshal(raw, &q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	exit, err := standardExitByID(strings.TrimSpace(q.StandardExitID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if exit.Protocol != "openvpn" {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		a.standardExitConnect(w, r)
		return
	}
	a.openVPNStandardExitConnect(w, r, q, exit)
}

func (a *app) openVPNStandardExitConnect(w http.ResponseWriter, r *http.Request, q standardExitConnectRequest, exit standardExit) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		http.Error(w, "native OpenVPN custom exits are source-enabled on Linux/macOS first; this platform remains unavailable instead of faking Connected", http.StatusNotImplemented)
		return
	}
	if !q.Direct && normalizeBase(q.Base) != "" && normalizeBase(q.Base) != "auto" && normalizeBase(q.Base) != "wg" {
		http.Error(w, "OpenVPN custom exit hopping currently requires a standard WireGuard Router VPN entry", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	control, ok := a.profileByIDLocked(a.profiles.SelectedID)
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "select a Router VPN policy profile first", http.StatusBadRequest)
		return
	}
	entry := common.RouterProfile{}
	if !q.Direct {
		entryID := strings.TrimSpace(q.EntryID)
		if entryID == "" {
			entryID = strings.TrimSpace(control.MultihopEntryID)
		}
		entry, ok = profileByID(profiles, entryID)
		if !ok {
			http.Error(w, "choose a linked Router VPN entry node", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(entry.Endpoint) == "" {
			http.Error(w, "entry node needs a public endpoint", http.StatusBadRequest)
			return
		}
	}
	sessionBase := "external"
	if !q.Direct {
		sessionBase = "wg"
	}
	sessionTrackerFor(a).declareRequest("standard-exit", sessionBase)
	if err := a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cmd, err := openVPNStandardExitCommand(a, control, entry, exit, q.Direct)
	if err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err = cmd.Start(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stateID := "standard:" + exit.ID
	a.mu.Lock()
	a.cmd = cmd
	a.state.Mode = "standard-exit"
	a.state.LogicalMode = "standard-exit"
	a.state.RuntimeMode = "standard-openvpn"
	a.state.Base = sessionBase
	a.state.RouterID = stateID
	a.state.Connected = false
	a.state.Phase = "standard-exit:openvpn:proving-public-exit"
	a.state.LastError = ""
	a.mu.Unlock()
	if err = proveOpenVPNStandardExit(exit.ExpectedPublicIP); err != nil {
		_ = a.stopMode()
		msg := "OpenVPN standard exit proof failed: " + err.Error()
		a.mu.Lock()
		a.state.Mode = "standard-exit"
		a.state.LogicalMode = "standard-exit"
		a.state.RuntimeMode = "standard-openvpn"
		a.state.Base = sessionBase
		a.state.RouterID = stateID
		a.state.Phase = "failed"
		a.state.LastError = msg
		a.state.Connected = false
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(msg)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}
	if err = a.checkConnectionOperation(); err != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.mu.Lock()
	if a.cmd != cmd {
		a.mu.Unlock()
		http.Error(w, "OpenVPN runtime changed during proof", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	if !q.Direct {
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == entry.ID {
				a.profiles.Profiles[i].UseCount++
			}
		}
	}
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
	}
	a.mu.Unlock()
	if persistErr != nil {
		_ = a.stopMode()
		sessionTrackerFor(a).markRequestFailure(persistErr.Error())
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	route := "client OpenVPN TUN -> direct external OpenVPN node -> Internet"
	entryID, entryName := "", ""
	if !q.Direct {
		route = "client OpenVPN TUN -> loopback SOCKS -> Router VPN WireGuard entry -> external OpenVPN node -> Internet"
		entryID = entry.ID
		entryName = entry.Name
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": "standard-exit", "direct": q.Direct, "entry_id": entryID, "entry_name": entryName, "standard_exit_id": exit.ID, "standard_exit_name": exit.Name, "protocol": "openvpn", "expected_public_ip": exit.ExpectedPublicIP, "exit_path_proof": "expected-public-ip-passed", "route": route})
}
