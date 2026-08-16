package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const mtuRetestTimeout = 2 * time.Minute

func registerMTURetestRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/mtu/retest", a.retestMTU)
	registerDNSPolicyRoute(h, a)
	registerHomeSummaryRoute(h, a)
	registerProfileSettingsRoute(h, a)
}

func (a *app) retestMTU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	p, err := a.activeProfile(); if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil { http.Error(w, "MTU retest currently requires a connected Router VPN node with private path proof", http.StatusConflict); return }
	a.mu.Lock(); st := a.state; a.mu.Unlock()
	if !st.Connected { http.Error(w, "connect the selected Router VPN node first; MTU Retest benchmarks only the proven private tunnel path", http.StatusConflict); return }
	if st.Mode == "multihop" { http.Error(w, "disconnect multihop and retest each single-hop path separately; one MTU result must not be mislabeled as both hops", http.StatusConflict); return }
	if strings.ToLower(strings.TrimSpace(p.MTUPolicy)) != "auto" { http.Error(w, "set this node MTU policy to Auto before Retest", http.StatusConflict); return }
	root := filepath.Clean(getenv("HOMEVPN_ROOT", filepath.Dir(a.cfg.ProfilesFile)))
	mode := strings.TrimSpace(st.RuntimeMode); if mode == "" { mode = strings.TrimSpace(st.Mode) }
	if mode == "" || mode == "off" { http.Error(w, "connected runtime mode is unknown; refusing an unkeyed MTU retest", http.StatusConflict); return }
	cmd, err := mtuRetestCommand(a.cfg.ScriptsDir); if err != nil { http.Error(w, err.Error(), http.StatusNotImplemented); return }
	ctx, cancel := context.WithTimeout(r.Context(), mtuRetestTimeout); defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.Env = append(os.Environ(), mtuRetestEnvironment(root, p, st, mode)...)
	out, runErr := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) { http.Error(w, "MTU Retest exceeded its bounded two-minute budget and was stopped", http.StatusGatewayTimeout); return }
	if runErr != nil { detail := strings.TrimSpace(string(out)); if len(detail) > 4096 { detail = detail[len(detail)-4096:] }; http.Error(w, "MTU Retest failed closed: "+detail, http.StatusBadGateway); return }
	result := map[string]any{}; trimmed := strings.TrimSpace(string(out)); if start, end := strings.Index(trimmed, "{"), strings.LastIndex(trimmed, "}"); start >= 0 && end >= start { _ = json.Unmarshal([]byte(trimmed[start:end+1]), &result) }
	updated, reloadErr := reloadMTUProfileStore(a); if reloadErr != nil { http.Error(w, "MTU Retest completed but the updated profile could not be reloaded: "+reloadErr.Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": mode, "effective_mtu": updated.EffectiveMTU, "effective_mtu_source": updated.EffectiveMTUSource, "effective_mtu_tested_at": updated.EffectiveMTUTestedAt, "result": result, "note": "bounded private-node loss/RTT/throughput comparison; the result is cached by network/path context and does not claim MTU caused any earlier cellular regression"})
}

func mtuRetestScriptPath(scriptsDir, goos string) (string, string, error) {
	scriptsDir = filepath.Clean(scriptsDir)
	if scriptsDir == "." || scriptsDir == string(filepath.Separator) { return "", "", errors.New("invalid MTU scripts directory") }
	immutableRoot := filepath.Dir(scriptsDir)
	if goos == "windows" {
		script := filepath.Join(immutableRoot, "client", "Optimize-RouterVPN-MTU.ps1")
		if !safeMTUScriptPath(immutableRoot, script) { return "", "", errors.New("unsafe Windows MTU optimizer path") }
		return script, "powershell", nil
	}
	name := "mtu-throughput-tuner.py"
	if goos == "darwin" { name = "mtu-throughput-tuner-platform.py" }
	script := filepath.Join(scriptsDir, name)
	if !safeMTUScriptPath(immutableRoot, script) { return "", "", errors.New("unsafe MTU optimizer path") }
	return script, "python", nil
}

func mtuRetestCommand(scriptsDir string) (*exec.Cmd, error) {
	script, runner, err := mtuRetestScriptPath(scriptsDir, runtime.GOOS); if err != nil { return nil, err }
	if info, statErr := os.Stat(script); statErr != nil || !info.Mode().IsRegular() { return nil, fmt.Errorf("MTU optimizer is not installed in the packaged runtime: %s", filepath.Base(script)) }
	if runner == "powershell" { return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "optimize"), nil }
	python, err := exec.LookPath("python3"); if err != nil { return nil, errors.New("python3 is required for MTU Retest on this desktop runtime") }
	return exec.Command(python, script, "optimize"), nil
}

func safeMTUScriptPath(root, script string) bool {
	rootAbs, err := filepath.Abs(filepath.Clean(root)); if err != nil { return false }
	scriptAbs, err := filepath.Abs(filepath.Clean(script)); if err != nil { return false }
	rel, err := filepath.Rel(rootAbs, scriptAbs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func mtuRetestEnvironment(root string, p common.RouterProfile, st state, mode string) []string {
	family := ""; if ip := net.ParseIP(strings.Trim(strings.TrimSpace(p.Endpoint), "[]")); ip != nil { if ip.To4() != nil { family = "4" } else { family = "6" } }
	return []string{"HOMEVPN_ROOT=" + root, "HOMEVPN_PROFILE_ID=" + p.ID, "HOMEVPN_ENDPOINT=" + p.Endpoint, "HOMEVPN_MODE=" + mode, "HOMEVPN_LOGICAL_MODE=" + st.LogicalMode, "HOMEVPN_BASE=" + st.Base, "HOMEVPN_IP_FAMILY=" + family}
}

func reloadMTUProfileStore(a *app) (common.RouterProfile, error) {
	raw, err := os.ReadFile(a.cfg.ProfilesFile); if err != nil { return common.RouterProfile{}, err }
	var store common.RouterProfileStore; if err := json.Unmarshal(raw, &store); err != nil { return common.RouterProfile{}, err }
	if store.SelectedID == "" { return common.RouterProfile{}, errors.New("updated router profile store has no selected node") }
	var selected common.RouterProfile; found := false
	for _, profile := range store.Profiles { if profile.ID == store.SelectedID { selected = profile; found = true; break } }
	if !found { return common.RouterProfile{}, fmt.Errorf("updated selected router %q is missing", store.SelectedID) }
	a.mu.Lock(); a.profiles = store; a.state.RouterID = store.SelectedID; a.mu.Unlock()
	return selected, nil
}
