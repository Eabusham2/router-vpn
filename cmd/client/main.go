package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

//go:embed ui.html logical_ui.js
var uiFS embed.FS

type state struct {
	Connected   bool   `json:"connected"`
	Mode        string `json:"mode"`
	LogicalMode string `json:"logical_mode,omitempty"`
	RuntimeMode string `json:"runtime_mode,omitempty"`
	Base        string `json:"base,omitempty"`
	RouterID    string `json:"router_id"`
	DAITA       bool   `json:"daita"`
	Jumbo       bool   `json:"jumbo"`
	Socks       bool   `json:"socks"`
	Phase       string `json:"phase,omitempty"`
	LastError   string `json:"last_error"`
}

type app struct {
	cfg         common.ClientConfig
	modes       []common.Mode
	profiles    common.RouterProfileStore
	mu          sync.Mutex
	state       state
	cmd         *exec.Cmd
	daitaCancel context.CancelFunc
}

func main() {
	configPath := getenv("HOMEVPN_CLIENT_CONFIG", "./client.json")
	var c common.ClientConfig
	b, err := os.ReadFile(configPath)
	if err == nil {
		if err = json.Unmarshal(b, &c); err != nil {
			log.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8788"
	}
	if c.HealthURL == "" {
		c.HealthURL = "http://10.77.0.1:8787/health"
	}
	if c.AutoTestSeconds == 0 {
		c.AutoTestSeconds = 8
	}
	configDir := filepath.Dir(configPath)
	if c.ModesFile == "" {
		c.ModesFile = filepath.Join(configDir, "modes.json")
	} else if !filepath.IsAbs(c.ModesFile) {
		c.ModesFile = filepath.Join(configDir, c.ModesFile)
	}
	if c.StateFile == "" {
		c.StateFile = filepath.Join(configDir, "state.json")
	} else if !filepath.IsAbs(c.StateFile) {
		c.StateFile = filepath.Join(configDir, c.StateFile)
	}
	if c.ScriptsDir == "" {
		c.ScriptsDir = filepath.Join(configDir, "modes")
	} else if !filepath.IsAbs(c.ScriptsDir) {
		c.ScriptsDir = filepath.Join(configDir, c.ScriptsDir)
	}
	if c.ProfilesFile == "" {
		c.ProfilesFile = filepath.Join(configDir, "routers.json")
	} else if !filepath.IsAbs(c.ProfilesFile) {
		c.ProfilesFile = filepath.Join(configDir, c.ProfilesFile)
	}
	if _, err = os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err = persistClientConfig(configPath, c); err != nil {
			log.Fatal(err)
		}
	}

	mb, err := os.ReadFile(c.ModesFile)
	if err != nil {
		log.Fatal(err)
	}
	var modes []common.Mode
	if err = json.Unmarshal(mb, &modes); err != nil {
		log.Fatal(err)
	}

	a := &app{cfg: c, modes: modes, state: state{Mode: "off", Phase: "off"}}
	if err = a.loadProfiles(); err != nil {
		log.Fatal(err)
	}
	a.state.RouterID = a.profiles.SelectedID

	h := http.NewServeMux()
	h.HandleFunc("/", a.index)
	h.HandleFunc("/logical-ui.js", a.logicalUI)
	h.HandleFunc("/api/status", a.status)
	h.HandleFunc("/api/modes", a.listModes)
	h.HandleFunc("/api/info", a.info)
	h.HandleFunc("/api/profiles", a.listProfiles)
	h.HandleFunc("/api/profile/save", a.saveProfile)
	h.HandleFunc("/api/profile/select", a.selectProfile)
	h.HandleFunc("/api/profile/delete", a.deleteProfile)
	h.HandleFunc("/api/profile/import", a.importProfileBundle)
	h.HandleFunc("/api/connect", a.connect)
	h.HandleFunc("/api/disconnect", a.disconnect)
	h.HandleFunc("/api/auto", a.auto)
	h.HandleFunc("/api/options", a.options)
	h.HandleFunc("/api/forward", a.forward)
	h.HandleFunc("/api/forward/clear", a.clearForward)
	extraRoutes(h, a)
	log.Printf("Router VPN client UI: http://%s", c.Listen)
	log.Fatal(http.ListenAndServe(c.Listen, h))
}

func persistClientConfig(path string, c common.ClientConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func getenv(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
}

func (a *app) index(w http.ResponseWriter, _ *http.Request) {
	b, _ := uiFS.ReadFile("ui.html")
	b = bytes.Replace(b, []byte("</body>"), []byte("<script src=\"/logical-ui.js\"></script></body>"), 1)
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("cache-control", "no-cache")
	_, _ = w.Write(b)
}

func (a *app) logicalUI(w http.ResponseWriter, _ *http.Request) {
	b, _ := uiFS.ReadFile("logical_ui.js")
	w.Header().Set("content-type", "application/javascript; charset=utf-8")
	w.Header().Set("cache-control", "no-cache")
	_, _ = w.Write(b)
}

func (a *app) status(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(a.state)
}

func (a *app) info(w http.ResponseWriter, _ *http.Request) {
	p, _ := a.activeProfile()
	a.mu.Lock()
	selectedID := a.profiles.SelectedID
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"router": publicProfileFor(p), "selected_id": selectedID, "profiles_file": a.cfg.ProfilesFile,
		"client_listen": a.cfg.Listen, "health_url": a.cfg.HealthURL, "auto_test_secs": a.cfg.AutoTestSeconds,
	})
}

func (a *app) listProfiles(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	store := publicProfileStoreFor(a.profiles)
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(store)
}

func validProfileID(id string) bool {
	if len(id) < 1 || len(id) > 64 || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (a *app) saveProfile(w http.ResponseWriter, r *http.Request) {
	var p common.RouterProfile
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		http.Error(w, "external profiles must be created or updated through /api/external-profile/import", http.StatusBadRequest)
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
		if strings.EqualFold(strings.TrimSpace(existing.NodeKind), "external") || existing.External != nil {
			a.mu.Unlock()
			http.Error(w, "external profiles cannot be overwritten through /api/profile/save; use /api/external-profile/import", http.StatusConflict)
			return
		}
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
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": publicProfileFor(p)})
}

func (a *app) selectProfile(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !validProfileID(q.ID) {
		http.Error(w, "invalid router profile id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	if a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" {
		a.mu.Unlock()
		http.Error(w, "disconnect before switching routers", http.StatusConflict)
		return
	}
	if _, ok := a.profileByIDLocked(q.ID); !ok {
		a.mu.Unlock()
		http.Error(w, "unknown router profile", http.StatusNotFound)
		return
	}
	a.profiles.SelectedID = q.ID
	a.state.RouterID = q.ID
	err := a.persistProfilesLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}

func (a *app) deleteProfile(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID string `json:"id"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !validProfileID(q.ID) {
		http.Error(w, "invalid router profile id", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" {
		a.mu.Unlock()
		http.Error(w, "disconnect before deleting a router", http.StatusConflict)
		return
	}
	if _, ok := a.profileByIDLocked(q.ID); !ok {
		a.mu.Unlock()
		http.Error(w, "unknown router profile", http.StatusNotFound)
		return
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	stage, err := stageGeneratedProfileDeletion(root, q.ID)
	if err != nil {
		a.mu.Unlock()
		http.Error(w, "cannot safely stage router profile deletion: "+err.Error(), http.StatusInternalServerError)
		return
	}
	oldStore := a.profiles
	oldStore.Profiles = append([]common.RouterProfile(nil), a.profiles.Profiles...)
	oldRouterID := a.state.RouterID
	out := make([]common.RouterProfile, 0, len(a.profiles.Profiles))
	for _, p := range a.profiles.Profiles {
		if p.ID != q.ID {
			out = append(out, p)
		}
	}
	a.profiles.Profiles = out
	if a.profiles.SelectedID == q.ID {
		a.profiles.SelectedID = ""
		if len(out) > 0 {
			a.profiles.SelectedID = out[0].ID
		}
	}
	a.state.RouterID = a.profiles.SelectedID
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.profiles = oldStore
		a.state.RouterID = oldRouterID
		rollbackErr := stage.rollback()
		a.mu.Unlock()
		if rollbackErr != nil {
			http.Error(w, fmt.Sprintf("delete metadata failed: %v; profile rollback also failed: %v", persistErr, rollbackErr), http.StatusInternalServerError)
			return
		}
		http.Error(w, persistErr.Error(), http.StatusInternalServerError)
		return
	}
	a.mu.Unlock()
	if err := stage.commitCleanup(); err != nil {
		log.Printf("profile %s deleted but private tombstone cleanup failed: %v", q.ID, err)
	}
	fmt.Fprint(w, `{"ok":true}`)
}

type profileBundle struct {
	Endpoint         string                       `json:"endpoint"`
	NodeProofID      string                       `json:"nodeProofId"`
	APIToken         string                       `json:"apiToken"`
	RouterAPI        string                       `json:"routerAPI"`
	AdGuardIPv4      string                       `json:"adGuardIPv4"`
	AdGuardIPv6      string                       `json:"adGuardIPv6"`
	Socks5Host       string                       `json:"socks5Host"`
	Socks5Port       int                          `json:"socks5Port"`
	Socks5Username   string                       `json:"socks5Username"`
	Socks5Password   string                       `json:"socks5Password"`
	DNSBenchmark     dnsBenchmarkPayload          `json:"dnsBenchmark"`
	RouterProfiles   []common.RouterProfile       `json:"routerProfiles"`
	SelectedRouterID string                       `json:"selectedRouterID"`
	Profiles         map[string]map[string]string `json:"profiles"`
}

func (a *app) importProfileBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var b profileBundle
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&b); err != nil {
		http.Error(w, "invalid router bundle", http.StatusBadRequest)
		return
	}
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
	if b.RouterAPI != "" {
		p.RouterAPI = b.RouterAPI
	}
	if b.APIToken != "" {
		p.APIToken = b.APIToken
	}
	if b.AdGuardIPv4 != "" {
		p.AdGuardIPv4 = b.AdGuardIPv4
	}
	if b.AdGuardIPv6 != "" {
		p.AdGuardIPv6 = b.AdGuardIPv6
	}
	if b.Socks5Host != "" {
		p.SocksHost = b.Socks5Host
	}
	if b.Socks5Port != 0 {
		p.SocksPort = b.Socks5Port
	}
	if b.Socks5Username != "" {
		p.SocksUsername = b.Socks5Username
	}
	if b.Socks5Password != "" {
		p.SocksPassword = b.Socks5Password
	}
	if len(b.DNSBenchmark.Results) > 0 {
		p.DNSResults = b.DNSBenchmark.Results
	}
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
		cleanup, cleanupErr := stageGeneratedProfileDeletion(stage.baseRoot, p.ID)
		if cleanupErr == nil {
			cleanupErr = cleanup.commitCleanup()
		}
		if cleanupErr != nil {
			log.Printf("router profile metadata rollback left a private generated profile tombstone/orphan: %v", cleanupErr)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": publicProfileFor(p), "profiles_written": len(b.Profiles)})
}

func (a *app) loadProfiles() error {
	b, err := os.ReadFile(a.cfg.ProfilesFile)
	if err == nil {
		if err = json.Unmarshal(b, &a.profiles); err != nil {
			return fmt.Errorf("read router profiles: %w", err)
		}
		for i := range a.profiles.Profiles {
			if !validProfileID(a.profiles.Profiles[i].ID) {
				return fmt.Errorf("invalid router profile id in %s", a.cfg.ProfilesFile)
			}
			applyProfileDefaults(&a.profiles.Profiles[i])
		}
		if a.profiles.SelectedID != "" && !validProfileID(a.profiles.SelectedID) {
			return fmt.Errorf("invalid selected router profile id in %s", a.cfg.ProfilesFile)
		}
		if a.profiles.SelectedID == "" && len(a.profiles.Profiles) > 0 {
			a.profiles.SelectedID = a.profiles.Profiles[0].ID
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	legacy := common.RouterProfile{ID: "home", Name: "Home Router", RouterAPI: a.cfg.RouterAPI, APIToken: a.cfg.APIToken, AdGuardIPv4: a.cfg.AdGuardIPv4, AdGuardIPv6: a.cfg.AdGuardIPv6, SocksHost: a.cfg.SocksHost, SocksPort: a.cfg.SocksPort, SocksUsername: a.cfg.SocksUsername, SocksPassword: a.cfg.SocksPassword, DAITAHost: a.cfg.DAITAHost, DAITAPort: a.cfg.DAITAPort, DAITARateKbps: a.cfg.DAITARateKbps}
	applyProfileDefaults(&legacy)
	if legacy.APIToken != "" || legacy.AdGuardIPv4 != "" || legacy.SocksUsername != "" {
		a.profiles = common.RouterProfileStore{SelectedID: legacy.ID, Profiles: []common.RouterProfile{legacy}}
	} else {
		a.profiles = common.RouterProfileStore{Profiles: []common.RouterProfile{}}
	}
	return a.persistProfiles()
}

func (a *app) persistProfiles() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.persistProfilesLocked()
}

func (a *app) persistProfilesLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.ProfilesFile), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a.profiles, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := a.cfg.ProfilesFile + ".tmp"
	if err = os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfg.ProfilesFile)
}

func (a *app) profileByIDLocked(id string) (common.RouterProfile, bool) {
	for _, p := range a.profiles.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return common.RouterProfile{}, false
}

func (a *app) activeProfile() (common.RouterProfile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.profileByIDLocked(a.profiles.SelectedID)
	if !ok {
		return common.RouterProfile{}, errors.New("add and select your home router first")
	}
	if p.Endpoint == "" {
		return common.RouterProfile{}, errors.New("selected router has no public IP or hostname")
	}
	return p, nil
}

func applyProfileDefaults(p *common.RouterProfile) {
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		// External exits own their own transport/DNS/proof semantics. Never inject
		// this home Router VPN node's private API, AdGuard, SOCKS, DAITA, base
		// tunnel, or path-probe defaults when an external profile is reloaded.
		if p.Location == "" {
			p.Location = p.Name
		}
		return
	}
	if p.RouterAPI == "" {
		p.RouterAPI = "http://10.77.0.1:8787"
	}
	if p.AdGuardIPv4 == "" {
		p.AdGuardIPv4 = "10.77.0.1"
	}
	if p.AdGuardIPv6 == "" {
		p.AdGuardIPv6 = "fd77:77::1"
	}
	if p.SocksHost == "" {
		p.SocksHost = "10.77.0.1"
	}
	if p.SocksPort == 0 {
		p.SocksPort = 1080
	}
	if p.DAITAHost == "" {
		p.DAITAHost = p.SocksHost
	}
	if p.DAITAPort == 0 {
		p.DAITAPort = 45999
	}
	if p.DAITARateKbps == 0 {
		p.DAITARateKbps = 192
	}
	if p.BaseTunnel == "" {
		p.BaseTunnel = "wg"
	}
	if p.DNSMode == "" {
		p.DNSMode = "home"
	}
	if p.DNSProtocol == "" {
		p.DNSProtocol = "udp"
	}
	if p.DNSHost == "" {
		if p.DNSMode == "fastest" && p.FastestDNSHost != "" {
			p.DNSHost = p.FastestDNSHost
		} else {
			p.DNSHost = p.AdGuardIPv4
		}
	}
	if p.DNSPort == 0 {
		p.DNSPort = 53
	}
	if p.DNSPath == "" {
		p.DNSPath = "/dns-query"
	}
	if p.PathProbeURL == "" {
		p.PathProbeURL = "http://10.77.0.1:8787/health"
	}
	if p.Location == "" {
		p.Location = p.Name
	}
}

func normalizeEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("enter the router public IPv4, IPv6, or hostname")
	}
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" {
			return "", errors.New("invalid router address")
		}
		value = u.Hostname()
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if strings.ContainsAny(value, " /\\?#@") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", errors.New("invalid router hostname")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid router hostname")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return "", errors.New("invalid router hostname")
			}
		}
	}
	return strings.ToLower(value), nil
}

func newID() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("router-%d", time.Now().Unix())
	}
	return "router-" + hex.EncodeToString(b)
}

func (a *app) listModes(w http.ResponseWriter, _ *http.Request) {
	out := make([]common.ModeStatus, 0, len(a.modes))
	for _, m := range a.modes {
		ok, reason := a.checkMode(m)
		out = append(out, common.ModeStatus{Mode: m, Available: ok, Reason: reason})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (a *app) checkMode(m common.Mode) (bool, string) {
	if len(m.CheckCommand) == 0 {
		return true, ""
	}
	cmd := exec.Command(m.CheckCommand[0], m.CheckCommand[1:]...)
	cmd.Dir = a.cfg.ScriptsDir
	a.mu.Lock()
	profileID := a.profiles.SelectedID
	a.mu.Unlock()
	cmd.Env = append(os.Environ(), "HOMEVPN_ROOT="+filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client")), "HOMEVPN_PROFILE_ID="+profileID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		reason := strings.TrimSpace(string(out))
		if reason == "" {
			reason = err.Error()
		}
		return false, reason
	}
	return true, strings.TrimSpace(string(out))
}

func (a *app) mode(id string) (common.Mode, error) {
	for _, m := range a.modes {
		if m.ID == id {
			return m, nil
		}
	}
	return common.Mode{}, errors.New("unknown mode")
}

func (a *app) connect(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Mode string `json:"mode"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := a.startMode(q.Mode); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}

func (a *app) disconnect(w http.ResponseWriter, _ *http.Request) {
	if err := a.stopMode(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}

func (a *app) options(w http.ResponseWriter, r *http.Request) {
	var q struct {
		DAITA *bool `json:"daita"`
		Jumbo *bool `json:"jumbo"`
		Socks *bool `json:"socks"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	if q.DAITA != nil {
		a.state.DAITA = *q.DAITA
	}
	if q.Jumbo != nil {
		a.state.Jumbo = *q.Jumbo
	}
	if q.Socks != nil {
		a.state.Socks = *q.Socks
	}
	a.mu.Unlock()
	fmt.Fprint(w, `{"ok":true}`)
}

func (a *app) startMode(id string) error {
	return a.startModeAttempt(id, false)
}

func (a *app) startModeAttempt(id string, holdOnFailure bool) error {
	p, err := a.activeProfile()
	if err != nil {
		return err
	}
	m, err := a.mode(id)
	if err != nil {
		return err
	}
	if ok, reason := a.checkMode(m); !ok {
		return fmt.Errorf("mode unavailable: %s", reason)
	}
	a.mu.Lock()
	daita, jumbo := a.state.DAITA, a.state.Jumbo
	a.mu.Unlock()
	if daita && !m.DAITASupported {
		return errors.New("DAITA is not available for this mode")
	}
	if jumbo && !m.JumboSupported {
		return errors.New("Jumbo TUN is not available for this mode; leave it off for WireGuard/AWG")
	}
	if err = a.stopModeWithIntent(true); err != nil {
		return err
	}

	a.mu.Lock()
	env := append(os.Environ(), fmt.Sprintf("HOMEVPN_DAITA=%t", a.state.DAITA), fmt.Sprintf("HOMEVPN_JUMBO=%t", a.state.Jumbo), fmt.Sprintf("HOMEVPN_SOCKS=%t", a.state.Socks), fmt.Sprintf("HOMEVPN_MTU=%d", m.MTU), "HOMEVPN_PROFILE_ID="+p.ID, "HOMEVPN_ENDPOINT="+p.Endpoint, "HOMEVPN_ADGUARD4="+p.AdGuardIPv4, "HOMEVPN_ADGUARD6="+p.AdGuardIPv6, "HOMEVPN_SOCKS_HOST="+p.SocksHost, fmt.Sprintf("HOMEVPN_SOCKS_PORT=%d", p.SocksPort), "HOMEVPN_SOCKS_USER="+p.SocksUsername, "HOMEVPN_SOCKS_PASSWORD="+p.SocksPassword)
	a.mu.Unlock()
	if len(m.Command) == 0 {
		if !holdOnFailure {
			_ = a.releaseTransitionKillSwitch()
		}
		return errors.New("mode has no command")
	}
	cmd := exec.Command(m.Command[0], m.Command[1:]...)
	cmd.Env = env
	cmd.Dir = a.cfg.ScriptsDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		if !holdOnFailure {
			_ = a.releaseTransitionKillSwitch()
		}
		return err
	}

	a.mu.Lock()
	a.cmd = cmd
	a.state.Connected = false
	a.state.Mode = id
	a.state.LogicalMode = ""
	a.state.RuntimeMode = id
	a.state.Base = ""
	a.state.RouterID = p.ID
	a.state.Phase = "starting"
	a.state.LastError = ""
	a.mu.Unlock()

	time.Sleep(1200 * time.Millisecond)
	a.mu.Lock()
	a.state.Phase = "checking"
	a.mu.Unlock()
	latency, healthErr := a.testHealth(p)
	if healthErr != nil {
		failure := fmt.Errorf("%s started but selected-router path proof failed: %w", m.Name, healthErr)
		_ = a.stopModeWithIntent(holdOnFailure)
		a.mu.Lock()
		a.state.LastError = failure.Error()
		a.state.Phase = "failed"
		a.mu.Unlock()
		return failure
	}

	a.mu.Lock()
	a.state.Connected = true
	a.state.Phase = "connected"
	daitaEnabled := a.state.DAITA
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == p.ID {
			a.profiles.Profiles[i].UseCount++
			a.profiles.Profiles[i].LastUsedAt = time.Now().UTC().Format(time.RFC3339)
			break
		}
	}
	_ = a.persistProfilesLocked()
	a.mu.Unlock()
	if daitaEnabled {
		a.startCoverTraffic(p)
	}
	log.Printf("mode %s selected-router path proof OK in %.2f ms", id, float64(latency.Microseconds())/1000)
	return nil
}

func (a *app) stopMode() error {
	return a.stopModeWithIntent(false)
}

func (a *app) stopModeWithIntent(holdKillSwitch bool) error {
	a.mu.Lock()
	cmd := a.cmd
	modeID := a.state.Mode
	coverCancel := a.daitaCancel
	a.daitaCancel = nil
	a.cmd = nil
	a.state.Connected = false
	a.state.Mode = "off"
	a.state.LogicalMode = ""
	a.state.RuntimeMode = ""
	a.state.Base = ""
	a.state.Phase = "stopping"
	a.mu.Unlock()
	if coverCancel != nil {
		coverCancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	if modeID != "off" {
		if m, err := a.mode(modeID); err == nil && len(m.StopCommand) > 0 {
			c := exec.Command(m.StopCommand[0], m.StopCommand[1:]...)
			c.Dir = a.cfg.ScriptsDir
			c.Env = a.stopCommandEnv(holdKillSwitch)
			_ = c.Run()
		}
	}
	if !holdKillSwitch {
		if err := a.releaseTransitionKillSwitch(); err != nil {
			a.mu.Lock()
			a.state.Phase = "failed"
			a.state.LastError = err.Error()
			a.mu.Unlock()
			return err
		}
	}
	a.mu.Lock()
	a.state.Phase = "off"
	a.mu.Unlock()
	return nil
}

func (a *app) auto(w http.ResponseWriter, _ *http.Request) {
	if _, err := a.activeProfile(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var failures []string
	for _, m := range a.modes {
		if !m.AutoEligible {
			continue
		}
		a.mu.Lock()
		a.state.Phase = "auto:trying:" + m.ID
		a.mu.Unlock()
		if err := a.startModeAttempt(m.ID, true); err != nil {
			failures = append(failures, m.ID+": "+err.Error())
			continue
		}
		a.mu.Lock()
		a.state.LogicalMode = "auto"
		a.state.RuntimeMode = m.ID
		a.state.Phase = "connected"
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": m.ID, "runtime_mode": m.ID, "logical_mode": "auto"})
		return
	}
	if err := a.releaseTransitionKillSwitch(); err != nil {
		failures = append(failures, err.Error())
	}
	a.mu.Lock()
	a.state.LastError = strings.Join(failures, " • ")
	a.state.Phase = "failed"
	a.mu.Unlock()
	http.Error(w, "no working mode: "+strings.Join(failures, " • "), http.StatusServiceUnavailable)
}

func (a *app) testHealth(p common.RouterProfile) (time.Duration, error) {
	target := strings.TrimSpace(p.PathProbeURL)
	if target == "" {
		target = strings.TrimSpace(a.cfg.HealthURL)
	}
	if target == "" {
		return 0, errors.New("selected router has no private path proof URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.cfg.AutoTestSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, fmt.Errorf("invalid path proof URL: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport}
	t := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("path proof %s", resp.Status)
	}
	if err := validateSelectedNodeProof(p, body); err != nil {
		return 0, err
	}
	return time.Since(t), nil
}

func (a *app) startCoverTraffic(p common.RouterProfile) {
	a.mu.Lock()
	if a.daitaCancel != nil {
		a.daitaCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.daitaCancel = cancel
	host, port, rate := p.DAITAHost, p.DAITAPort, p.DAITARateKbps
	a.mu.Unlock()
	go func() {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		c, err := net.Dial("udp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		if rate < 32 {
			rate = 32
		}
		bytesPerTick := rate * 1000 / 8 / 20
		if bytesPerTick < 256 {
			bytesPerTick = 256
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n := bytesPerTick
				var jitter [1]byte
				_, _ = rand.Read(jitter[:])
				n = n * int(75+int(jitter[0])%51) / 100
				if n > 1200 {
					n = 1200
				}
				buf := make([]byte, n)
				_, _ = rand.Read(buf)
				_, _ = c.Write(buf)
			}
		}
	}()
}

func (a *app) forward(w http.ResponseWriter, r *http.Request) { proxyJSON(a, w, r, "/api/forward") }
func (a *app) clearForward(w http.ResponseWriter, r *http.Request) {
	proxyJSON(a, w, r, "/api/forward/clear")
}

func proxyJSON(a *app, w http.ResponseWriter, r *http.Request, path string) {
	p, err := a.activeProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(p.RouterAPI, "/")+path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
