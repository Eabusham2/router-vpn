package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"router-vpn/internal/common"
)

func registerDesktopMultihopRoutes(h *http.ServeMux, a *app) {
	if runtime.GOOS == "linux" {
		registerMultihopRoutes(h, a)
		return
	}
	h.HandleFunc("/api/multihop/status", a.nativeMultihopStatus)
	h.HandleFunc("/api/multihop/connect", a.nativeMultihopConnect)
}

func nativeMultihopPlatformSupported() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "darwin"
}

func resolveNativeMultihopSelection(control common.RouterProfile, profiles []common.RouterProfile, q multihopConnectRequest) (multihopSelection, error) {
	entryID := strings.TrimSpace(q.EntryID)
	exitID := strings.TrimSpace(q.ExitID)
	if entryID == "" { entryID = strings.TrimSpace(control.MultihopEntryID) }
	if exitID == "" { exitID = strings.TrimSpace(control.MultihopExitID) }
	if entryID == "" || exitID == "" { return multihopSelection{}, errors.New("choose both an entry and an exit node") }
	if entryID == exitID { return multihopSelection{}, errors.New("multihop entry and exit nodes must be different") }
	entry, ok := profileByID(profiles, entryID); if !ok { return multihopSelection{}, fmt.Errorf("entry node %q is not linked", entryID) }
	exit, ok := profileByID(profiles, exitID); if !ok { return multihopSelection{}, fmt.Errorf("exit node %q is not linked", exitID) }
	if strings.TrimSpace(entry.Endpoint) == "" || strings.TrimSpace(exit.Endpoint) == "" { return multihopSelection{}, errors.New("both multihop nodes need public endpoints") }
	base := normalizeBase(q.Base)
	if base == "" || base == "auto" { base = normalizeBase(entry.BaseTunnel) }
	if base == "" || base == "auto" { base = normalizeBase(control.BaseTunnel) }
	if base == "" || base == "auto" { base = "wg" }
	if base != "wg" { return multihopSelection{}, errors.New("first native Windows/macOS multihop path supports standard WireGuard entry only") }
	exitMode := strings.TrimSpace(q.ExitMode); if exitMode == "" { exitMode = "shadowsocks" }
	if exitMode != "shadowsocks" && exitMode != "hysteria2" { return multihopSelection{}, errors.New("native desktop multihop supports only Shadowsocks or Hysteria2 as the exit transport") }
	return multihopSelection{Control: control, Entry: entry, Exit: exit, Base: base, ExitMode: exitMode}, nil
}

func (a *app) nativeMultihopStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	a.mu.Lock(); control, _ := a.profileByIDLocked(a.profiles.SelectedID); profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...); state := a.state; a.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"platform": runtime.GOOS,
		"platform_supported": nativeMultihopPlatformSupported(),
		"entry_id": control.MultihopEntryID,
		"exit_id": control.MultihopExitID,
		"enabled": control.MultihopEnabled,
		"supported_entry_bases": []string{"wg"},
		"supported_exit_modes": []string{"shadowsocks", "hysteria2"},
		"connected": state.Connected && state.Mode == "multihop",
		"actual_exit_id": func() string { if state.Mode == "multihop" { return state.RouterID }; return "" }(),
		"runtime_exit_mode": func() string { if state.Mode == "multihop" { return state.RuntimeMode }; return "" }(),
		"nodes": multihopNodeSummaries(profiles),
	})
}

func nativeMultihopPlatformCommand(a *app, sel multihopSelection) (*exec.Cmd, error) {
	if runtime.GOOS == "windows" { return nativeWindowsMultihopCommand(a, sel) }
	if runtime.GOOS == "darwin" { return nativeDarwinMultihopCommand(a, sel) }
	return nil, errors.New("real native multihop is not implemented on this desktop platform")
}

func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	if !nativeMultihopPlatformSupported() { http.Error(w, "real multihop is unavailable on this platform instead of faking a chain", http.StatusNotImplemented); return }
	var q multihopConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	a.mu.Lock(); control, ok := a.profileByIDLocked(a.profiles.SelectedID); profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...); a.mu.Unlock()
	if !ok { http.Error(w, "select a Router VPN control profile first", http.StatusBadRequest); return }
	sel, err := resolveNativeMultihopSelection(control, profiles, q); if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	sessionTrackerFor(a).declareRequest("multihop", sel.Base)
	if err = a.stopMode(); err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusInternalServerError); return }
	cmd, err := nativeMultihopPlatformCommand(a, sel); if err != nil { sessionTrackerFor(a).markRequestFailure(err.Error()); http.Error(w, err.Error(), http.StatusBadRequest); return }
	if err = cmd.Start(); err != nil { a.mu.Lock(); a.state.Phase="failed";a.state.LastError=err.Error();a.state.Connected=false;a.mu.Unlock();sessionTrackerFor(a).markRequestFailure(err.Error());http.Error(w,err.Error(),http.StatusInternalServerError);return }
	a.mu.Lock();a.cmd=cmd;a.state.Mode="multihop";a.state.LogicalMode="multihop";a.state.RuntimeMode=sel.ExitMode;a.state.Base=sel.Base;a.state.RouterID=sel.Exit.ID;a.state.Connected=false;a.state.Phase="multihop:proving-exit";a.state.LastError="";a.mu.Unlock()
	if err = a.proveMultihopExit(sel.Exit); err != nil {
		_ = a.stopMode(); msg := "multihop exit proof failed: " + err.Error(); a.mu.Lock();a.state.Mode="multihop";a.state.LogicalMode="multihop";a.state.RuntimeMode=sel.ExitMode;a.state.Base=sel.Base;a.state.RouterID=sel.Exit.ID;a.state.Phase="failed";a.state.LastError=msg;a.state.Connected=false;a.mu.Unlock();sessionTrackerFor(a).markRequestFailure(msg);http.Error(w,msg,http.StatusBadGateway);return
	}
	a.mu.Lock();if a.cmd!=cmd{a.mu.Unlock();http.Error(w,"multihop runtime changed during exit proof",http.StatusConflict);return};a.state.Connected=true;a.state.Phase="connected";a.state.LastError="";for i:=range a.profiles.Profiles{if a.profiles.Profiles[i].ID==sel.Entry.ID||a.profiles.Profiles[i].ID==sel.Exit.ID{a.profiles.Profiles[i].UseCount++}};persistErr:=a.persistProfilesLocked();a.mu.Unlock()
	if persistErr!=nil{_ = a.stopMode();sessionTrackerFor(a).markRequestFailure(persistErr.Error());http.Error(w,persistErr.Error(),http.StatusInternalServerError);return}
	w.Header().Set("content-type","application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok":true,"mode":"multihop","entry_id":sel.Entry.ID,"entry_name":sel.Entry.Name,"exit_id":sel.Exit.ID,"exit_name":sel.Exit.Name,"entry_base":sel.Base,"exit_mode":sel.ExitMode,"exit_path_proof":"passed-through-exit-only-local-proxy","route":"client TUN -> exit proxy outbound -> entry WireGuard endpoint -> exit node -> Internet"})
}
