#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

SAVE_PROFILE = r'''func (a *app) saveProfile(w http.ResponseWriter, r *http.Request) {
	var p common.RouterProfile
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Home Router"
	}
	var err error
	p.Endpoint, err = normalizeEndpoint(p.Endpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	applyProfileDefaults(&p)
	if p.ID == "" {
		p.ID = newID()
	} else if !validProfileID(p.ID) {
		http.Error(w, "invalid router profile id", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" {
		a.mu.Unlock()
		http.Error(w, "disconnect before changing router settings", http.StatusConflict)
		return
	}
	found := false
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != p.ID {
			continue
		}
		found = true
		existing := a.profiles.Profiles[i]
		// A linked node's proof identity is immutable. Normal settings edits may
		// omit it, but they may never erase or replace it. Legacy linked profiles
		// are upgraded from their saved WireGuard server public key when possible.
		identity := strings.TrimSpace(existing.NodeProofID)
		if derived, deriveErr := expectedNodeProofID(existing); deriveErr == nil {
			if identity != "" && identity != derived {
				a.mu.Unlock()
				http.Error(w, "stored router node proof identity no longer matches its saved WireGuard server key", http.StatusConflict)
				return
			}
			identity = derived
		}
		incoming := strings.TrimSpace(p.NodeProofID)
		if identity != "" {
			if incoming != "" && incoming != identity {
				a.mu.Unlock()
				http.Error(w, "linked router node proof identity cannot be changed; import it as a new node instead", http.StatusConflict)
				return
			}
			p.NodeProofID = identity
		} else if incoming != "" {
			a.mu.Unlock()
			http.Error(w, "node proof identity is established only by a validated router bundle import", http.StatusBadRequest)
			return
		}
		a.profiles.Profiles[i] = p
		break
	}
	if !found {
		if strings.TrimSpace(p.NodeProofID) != "" {
			a.mu.Unlock()
			http.Error(w, "node proof identity is established only by a validated router bundle import", http.StatusBadRequest)
			return
		}
		a.profiles.Profiles = append(a.profiles.Profiles, p)
	}
	a.profiles.SelectedID = p.ID
	a.state.RouterID = p.ID
	err = a.persistProfilesLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": p})
}
'''

IMPORT_PROFILE = r'''func (a *app) importProfileBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var b profileBundle
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&b); err != nil {
		http.Error(w, "invalid router bundle", http.StatusBadRequest)
		return
	}

	// Refuse expensive private staging if the client is currently changing or
	// using its routing state. Re-check under the same lock immediately before
	// commit so a connection cannot race the import.
	a.mu.Lock()
	busy := a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking"
	a.mu.Unlock()
	if busy {
		http.Error(w, "disconnect before importing a router", http.StatusConflict)
		return
	}

	p := common.RouterProfile{ID: newID(), Name: "Home Router"}
	if len(b.RouterProfiles) > 0 {
		selected := b.RouterProfiles[0]
		for _, candidate := range b.RouterProfiles {
			if b.SelectedRouterID != "" && candidate.ID == b.SelectedRouterID {
				selected = candidate
				break
			}
		}
		p = selected
		p.ID = newID()
		if strings.TrimSpace(p.Name) == "" {
			p.Name = "Home Router"
		}
	}
	if strings.TrimSpace(b.Endpoint) != "" {
		endpoint, err := normalizeEndpoint(b.Endpoint)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.Endpoint = endpoint
	} else if strings.TrimSpace(p.Endpoint) != "" {
		endpoint, err := normalizeEndpoint(p.Endpoint)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.Endpoint = endpoint
	}
	if top := strings.TrimSpace(b.NodeProofID); top != "" {
		if !common.ValidNodeProofID(top) {
			http.Error(w, "invalid router bundle node proof id", http.StatusBadRequest)
			return
		}
		if p.NodeProofID != "" && p.NodeProofID != top {
			http.Error(w, "router bundle node proof ids disagree", http.StatusBadRequest)
			return
		}
		p.NodeProofID = top
	}
	if b.RouterAPI != "" { p.RouterAPI = b.RouterAPI }
	if b.APIToken != "" { p.APIToken = b.APIToken }
	if b.AdGuardIPv4 != "" { p.AdGuardIPv4 = b.AdGuardIPv4 }
	if b.AdGuardIPv6 != "" { p.AdGuardIPv6 = b.AdGuardIPv6 }
	if b.Socks5Host != "" { p.SocksHost = b.Socks5Host }
	if b.Socks5Port != 0 { p.SocksPort = b.Socks5Port }
	if b.Socks5Username != "" { p.SocksUsername = b.Socks5Username }
	if b.Socks5Password != "" { p.SocksPassword = b.Socks5Password }
	if len(b.DNSBenchmark.Results) > 0 { p.DNSResults = b.DNSBenchmark.Results }
	if b.DNSBenchmark.Winner.Address != "" {
		p.FastestDNSHost = b.DNSBenchmark.Winner.Address
		p.FastestDNSName = b.DNSBenchmark.Winner.Name
		p.FastestDNSLatencyMs = b.DNSBenchmark.Winner.LatencyMs
	}
	applyProfileDefaults(&p)

	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	stage, err := newStagedBundle(root, p.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stage.cleanup()
	if err := stage.writeProfiles(b.Profiles); err != nil {
		http.Error(w, "invalid router bundle profiles: "+err.Error(), http.StatusBadRequest)
		return
	}
	wgPath := filepath.Join(stage.profileDir, "wg", "wg.conf")
	wgData, err := os.ReadFile(wgPath)
	if err != nil {
		http.Error(w, "router bundle has no standard WireGuard identity profile", http.StatusBadRequest)
		return
	}
	derivedNodeID, err := nodeProofIDFromWGConfig(wgData)
	if err != nil {
		http.Error(w, "router bundle identity proof failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.NodeProofID != "" && p.NodeProofID != derivedNodeID {
		http.Error(w, "router bundle node proof id does not match its WireGuard server public key", http.StatusBadRequest)
		return
	}
	p.NodeProofID = derivedNodeID
	if err := common.NormalizeRouterProfile(&p); err != nil {
		http.Error(w, "invalid router profile: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" {
		a.mu.Unlock()
		http.Error(w, "disconnect before importing a router", http.StatusConflict)
		return
	}
	oldSelected := a.profiles.SelectedID
	oldRouterID := a.state.RouterID
	oldLen := len(a.profiles.Profiles)
	if err := stage.commit(root, p.ID); err != nil {
		a.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	finalProfileRoot := filepath.Join(root, "generated", p.ID)
	a.profiles.Profiles = append(a.profiles.Profiles, p)
	a.profiles.SelectedID = p.ID
	a.state.RouterID = p.ID
	err = a.persistProfilesLocked()
	if err != nil {
		a.profiles.Profiles = a.profiles.Profiles[:oldLen]
		a.profiles.SelectedID = oldSelected
		a.state.RouterID = oldRouterID
	}
	a.mu.Unlock()
	if err != nil {
		_ = os.RemoveAll(finalProfileRoot)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": p, "profiles_written": len(b.Profiles)})
}
'''


def replace_function(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError(f"missing function marker: {start_marker}")
    end = text.find(end_marker, start)
    if end < 0:
        raise RuntimeError(f"missing next function marker: {end_marker}")
    return text[:start] + replacement + "\n" + text[end:]


def patch_main() -> bool:
    path = ROOT / "cmd/client/main.go"
    text = path.read_text(encoding="utf-8")
    changed = False
    if "linked router node proof identity cannot be changed" not in text:
        text = replace_function(text, "func (a *app) saveProfile", "func (a *app) selectProfile", SAVE_PROFILE)
        changed = True
    if "stage, err := newStagedBundle(root, p.ID)" not in text:
        text = replace_function(text, "func (a *app) importProfileBundle", "func (a *app) loadProfiles", IMPORT_PROFILE)
        changed = True
    if changed:
        path.write_text(text, encoding="utf-8")
    return changed


def patch_compose() -> bool:
    path = ROOT / "server/portainer-current.yaml"
    text = path.read_text(encoding="utf-8")
    old = "/src/server/scripts/setup-center-server.py"
    new = "/src/server/scripts/setup-center-ai-server.py"
    if old not in text:
        if new in text or "run-setup-center.sh" in text:
            return False
        raise RuntimeError("production compose has no recognized Setup Center entrypoint")
    text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    changed = []
    if patch_main(): changed.append("cmd/client/main.go")
    if patch_compose(): changed.append("server/portainer-current.yaml")
    print("release-gap wiring changed:", ", ".join(changed) if changed else "nothing (already wired)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
