package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type standardExitConnectRequest struct {
	EntryID        string `json:"entry_id"`
	StandardExitID string `json:"standard_exit_id"`
	Base           string `json:"base"`
}

func registerStandardExitRuntimeRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/standard-exit/connect", a.standardExitConnect)
}

func selectedStandardExitDNS(control common.RouterProfile) (map[string]any, error) {
	mode := strings.ToLower(strings.TrimSpace(control.DNSMode))
	protocol := strings.ToLower(strings.TrimSpace(control.DNSProtocol))
	host := strings.TrimSpace(control.DNSHost)
	port := control.DNSPort
	serverName := strings.TrimSpace(control.DNSServerName)
	path := strings.TrimSpace(control.DNSPath)
	detour := "custom-exit"
	if path == "" { path = "/dns-query" }

	switch mode {
	case "", "home":
		host = strings.TrimSpace(control.AdGuardIPv4)
		if host == "" { host = strings.TrimSpace(control.AdGuardIPv6) }
		protocol = "udp"; port = 53; serverName = ""; detour = "entry-wg"
	case "fastest":
		host = strings.TrimSpace(control.FastestDNSHost)
		protocol = "udp"; port = 53; serverName = ""
	case "doh":
		protocol = "https"; if port == 0 { port = 443 }
	case "dot":
		protocol = "tls"; if port == 0 { port = 853 }
	case "doh3":
		protocol = "h3"; if port == 0 { port = 443 }
	case "rescue":
		protocol = "https"; if port == 0 { port = 443 }
		if host == "" { host = "1.1.1.1" }
		if serverName == "" { serverName = "cloudflare-dns.com" }
	case "custom":
	default:
		return nil, fmt.Errorf("unsupported DNS mode %q for standard exit", mode)
	}
	if host == "" { host = strings.TrimSpace(control.FastestDNSHost) }
	if host == "" { host = "1.1.1.1" }
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return nil, errors.New("custom standard exit currently requires a literal DNS server address so DNS cannot escape through an implicit system resolver")
	}
	if port == 0 { port = 53 }
	if port < 1 || port > 65535 { return nil, errors.New("selected DNS port is invalid") }
	switch protocol {
	case "udp", "tcp":
	case "tls", "https", "h3":
		if serverName == "" { return nil, errors.New("selected encrypted DNS requires a TLS server name") }
	default:
		return nil, fmt.Errorf("unsupported DNS protocol %q for standard exit", protocol)
	}
	server := map[string]any{"type":protocol, "tag":"selected-dns", "server":host, "server_port":port, "detour":detour}
	if protocol == "tls" || protocol == "https" || protocol == "h3" {
		server["tls"] = map[string]any{"enabled":true, "server_name":serverName}
		if protocol == "https" || protocol == "h3" { server["path"] = path }
	}
	return server, nil
}

func buildNativeStandardExitConfig(control common.RouterProfile, entryWG nativeWG, exit standardExit) (map[string]any, error) {
	endpoint, outbound, err := standardExitRuntimeParts(exit, "entry-wg")
	if err != nil { return nil, err }
	dnsServer, err := selectedStandardExitDNS(control)
	if err != nil { return nil, err }
	endpoints := []any{nativeWGEndpoint(entryWG)}
	if endpoint != nil { endpoints = append(endpoints, endpoint) }
	outbounds := []any{}
	if outbound != nil { outbounds = append(outbounds, outbound) }
	mtu := 1280
	if control.EffectiveMTU >= 1280 && control.EffectiveMTU <= 9000 { mtu = control.EffectiveMTU }
	cfg := map[string]any{
		"log": map[string]any{"level":"warn", "timestamp":true},
		"dns": map[string]any{"servers":[]any{dnsServer}, "final":"selected-dns"},
		"inbounds": []any{
			map[string]any{"type":"tun", "tag":"tun-in", "interface_name":"router-vpn-standard-exit", "address":[]any{"172.29.91.1/30", "fd29:91::1/126"}, "mtu":mtu, "auto_route":true, "strict_route":true, "stack":"system"},
			map[string]any{"type":"mixed", "tag":"standard-exit-proof", "listen":"127.0.0.1", "listen_port":1099},
		},
		"endpoints": endpoints,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{map[string]any{"protocol":"dns", "action":"hijack-dns"}},
			"final":"custom-exit", "auto_detect_interface":true,
		},
	}
	return cfg, nil
}

func prepareNativeStandardExit(root string, control, entry common.RouterProfile, exit standardExit) (string, string, error) {
	entryDir, err := nativeGeneratedDir(root, entry.ID, "wg")
	if err != nil { return "", "", err }
	wg, err := parseNativeWG(filepath.Join(entryDir, "wg.conf"))
	if err != nil { return "", "", err }
	cfg, err := buildNativeStandardExitConfig(control, wg, exit)
	if err != nil { return "", "", err }
	base := filepath.Join(root, "run", "native-standard-exit")
	if err = os.MkdirAll(base, 0o700); err != nil { return "", "", err }
	random := make([]byte, 12); if _, err = rand.Read(random); err != nil { return "", "", err }
	runtimeDir := filepath.Join(base, hex.EncodeToString(random))
	if err = os.Mkdir(runtimeDir, 0o700); err != nil { return "", "", err }
	raw, err := json.MarshalIndent(cfg, "", "  "); if err != nil { _ = os.RemoveAll(runtimeDir); return "", "", err }
	if len(raw) > 4<<20 { _ = os.RemoveAll(runtimeDir); return "", "", errors.New("prepared standard exit config exceeds safety limit") }
	if err = os.WriteFile(filepath.Join(runtimeDir, "sing-box.json"), append(raw, '\n'), 0o600); err != nil { _ = os.RemoveAll(runtimeDir); return "", "", err }
	return runtimeDir, "router-vpn-standard-exit", nil
}

func nativeStandardExitCommand(a *app, control, entry common.RouterProfile, exit standardExit) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	runtimeDir, tunAlias, err := prepareNativeStandardExit(root, control, entry, exit)
	if err != nil { return nil, err }
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		helper := filepath.Join(root, "client", "native-multihop-windows.ps1")
		if _, err = os.Stat(helper); err != nil { helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-multihop-windows.ps1") }
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() { return nil, errors.New("native Windows standard-exit helper is missing") }
		cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "up", "-RuntimeDir", runtimeDir, "-Endpoint", entry.Endpoint, "-TunnelAlias", tunAlias)
	case "darwin":
		helper := filepath.Join(root, "modes", "native-multihop-darwin.sh")
		if _, err = os.Stat(helper); err != nil { helper = filepath.Join(a.cfg.ScriptsDir, "native-multihop-darwin.sh") }
		if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() { return nil, errors.New("native macOS standard-exit helper is missing") }
		cmd = exec.Command("bash", helper, "up", runtimeDir, entry.Endpoint, tunAlias)
	default:
		return nil, errors.New("native standard exit runtime is currently implemented on Windows and macOS; Linux wiring is separate")
	}
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+root, "HOMEVPN_PROFILE_ID="+entry.ID, "HOMEVPN_POLICY_PROFILE_ID="+control.ID, "HOMEVPN_ENDPOINT="+entry.Endpoint)
	cmd.Stdout = os.Stdout; cmd.Stderr = os.Stderr
	return cmd, nil
}

func proveStandardExit(expected string) error {
	expectedIP := net.ParseIP(strings.TrimSpace(expected)); if expectedIP == nil { return errors.New("expected public exit IP is invalid") }
	proxyURL, err := url.Parse(multihopProofProxy); if err != nil { return err }
	transport := http.DefaultTransport.(*http.Transport).Clone(); transport.Proxy = http.ProxyURL(proxyURL); transport.ForceAttemptHTTP2 = false
	client := &http.Client{Transport:transport, Timeout:2*time.Second}
	providers := []string{"https://api64.ipify.org", "https://api.ipify.org"}
	deadline := time.Now().Add(10*time.Second); var last error
	for time.Now().Before(deadline) {
		for _, endpoint := range providers {
			resp, reqErr := client.Get(endpoint)
			if reqErr != nil { last = reqErr; continue }
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256)); _ = resp.Body.Close()
			if readErr != nil { last = readErr; continue }
			if resp.StatusCode/100 != 2 { last = fmt.Errorf("exit address proof returned HTTP %d", resp.StatusCode); continue }
			observed := net.ParseIP(strings.TrimSpace(string(body)))
			if observed == nil { last = errors.New("exit address proof returned a non-IP value"); continue }
			if observed.Equal(expectedIP) { return nil }
			last = fmt.Errorf("custom exit reached public address %s, expected %s", observed.String(), expectedIP.String())
		}
		time.Sleep(250*time.Millisecond)
	}
	if last == nil { last = errors.New("custom exit public-address proof timed out") }
	return last
}

func (a *app) standardExitConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" { http.Error(w, "custom standard exit runtime is not yet wired on this platform; it remains unavailable instead of faking a connection", http.StatusNotImplemented); return }
	var q standardExitConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	if normalizeBase(q.Base) != "" && normalizeBase(q.Base) != "auto" && normalizeBase(q.Base) != "wg" { http.Error(w, "native custom standard exits currently require a standard WireGuard entry", http.StatusBadRequest); return }
	a.mu.Lock(); control, ok := a.profileByIDLocked(a.profiles.SelectedID); profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...); a.mu.Unlock()
	if !ok { http.Error(w, "select a Router VPN control profile first", http.StatusBadRequest); return }
	entryID := strings.TrimSpace(q.EntryID); if entryID == "" { entryID = strings.TrimSpace(control.MultihopEntryID) }
	entry, ok := profileByID(profiles, entryID); if !ok { http.Error(w, "choose a linked Router VPN entry node", http.StatusBadRequest); return }
	if strings.TrimSpace(entry.Endpoint) == "" { http.Error(w, "entry node needs a public endpoint", http.StatusBadRequest); return }
	exit, err := standardExitByID(strings.TrimSpace(q.StandardExitID)); if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	sessionTrackerFor(a).declareRequest("standard-exit", "wg")
	if err = a.stopMode(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }
	cmd, err := nativeStandardExitCommand(a, control, entry, exit); if err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusBadRequest); return }
	if err = cmd.Start(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }
	stateID := "standard:"+exit.ID
	a.mu.Lock(); a.cmd=cmd; a.state.Mode="standard-exit"; a.state.LogicalMode="standard-exit"; a.state.RuntimeMode="standard-"+exit.Protocol; a.state.Base="wg"; a.state.RouterID=stateID; a.state.Connected=false; a.state.Phase="standard-exit:proving-public-exit"; a.state.LastError=""; a.mu.Unlock()
	if err = proveStandardExit(exit.ExpectedPublicIP); err != nil {
		_ = a.stopMode(); msg := "standard exit proof failed: "+err.Error(); a.mu.Lock(); a.state.Mode="standard-exit";a.state.LogicalMode="standard-exit";a.state.RuntimeMode="standard-"+exit.Protocol;a.state.Base="wg";a.state.RouterID=stateID;a.state.Phase="failed";a.state.LastError=msg;a.state.Connected=false;a.mu.Unlock();sessionTrackerFor(a).markRequestFailure(msg);http.Error(w,msg,http.StatusBadGateway);return
	}
	a.mu.Lock(); if a.cmd!=cmd { a.mu.Unlock(); http.Error(w,"standard exit runtime changed during proof",http.StatusConflict);return }; a.state.Connected=true;a.state.Phase="connected";a.state.LastError="";for i:=range a.profiles.Profiles{if a.profiles.Profiles[i].ID==entry.ID{a.profiles.Profiles[i].UseCount++}};persistErr:=a.persistProfilesLocked();a.mu.Unlock()
	if persistErr!=nil{_ = a.stopMode();sessionTrackerFor(a).markRequestFailure(persistErr.Error());http.Error(w,persistErr.Error(),http.StatusInternalServerError);return}
	w.Header().Set("content-type","application/json"); _ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"mode":"standard-exit","entry_id":entry.ID,"entry_name":entry.Name,"standard_exit_id":exit.ID,"standard_exit_name":exit.Name,"protocol":exit.Protocol,"expected_public_ip":exit.ExpectedPublicIP,"exit_path_proof":"expected-public-ip-passed","route":"client TUN -> entry WireGuard -> custom standard exit -> Internet"})
}
