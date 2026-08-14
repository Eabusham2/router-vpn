package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	standardExitStoreVersion = 1
	standardExitMaxStore     = int64(512 << 10)
)

type standardExit struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Protocol         string   `json:"protocol"`
	Server           string   `json:"server"`
	ServerPort       int      `json:"server_port"`
	ExpectedPublicIP string   `json:"expected_public_ip"`
	Username         string   `json:"username,omitempty"`
	Password         string   `json:"password,omitempty"`
	Method           string   `json:"method,omitempty"`
	Secret           string   `json:"secret,omitempty"`
	TLSServerName    string   `json:"tls_server_name,omitempty"`
	WGAddresses      []string `json:"wg_addresses,omitempty"`
	WGPrivateKey     string   `json:"wg_private_key,omitempty"`
	WGPeerPublicKey  string   `json:"wg_peer_public_key,omitempty"`
	WGPreSharedKey   string   `json:"wg_pre_shared_key,omitempty"`
	WGAllowedIPs     []string `json:"wg_allowed_ips,omitempty"`
	WGMTU            int      `json:"wg_mtu,omitempty"`
}

type standardExitStore struct {
	SchemaVersion int            `json:"schema_version"`
	Exits         []standardExit `json:"exits"`
}

type standardExitCapability struct {
	Protocol  string `json:"protocol"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

type standardExitSummary struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	Server           string `json:"server"`
	ServerPort       int    `json:"server_port"`
	ExpectedPublicIP string `json:"expected_public_ip"`
	HasCredentials   bool   `json:"has_credentials"`
	HasSecret        bool   `json:"has_secret"`
	HasWireGuardKey  bool   `json:"has_wireguard_key"`
}

func standardExitCapabilities() []standardExitCapability {
	return []standardExitCapability{
		{Protocol: "wireguard", Supported: true},
		{Protocol: "socks5", Supported: true},
		{Protocol: "shadowsocks", Supported: true},
		{Protocol: "hysteria2", Supported: true},
		{Protocol: "openvpn", Supported: false, Reason: "production is pinned to sing-box 1.13.x, which has no OpenVPN endpoint; do not expose OpenVPN until a stable pinned dataplane is validated"},
	}
}

func normalizeStandardExitProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "wg", "wireguard":
		return "wireguard"
	case "socks", "socks5":
		return "socks5"
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "hy2", "hysteria2":
		return "hysteria2"
	case "ovpn", "openvpn":
		return "openvpn"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func standardExitStorePath() string {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	return filepath.Join(root, "standard-exits.json")
}

func newStandardExitID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "exit-local"
	}
	return "exit-" + hex.EncodeToString(b)
}

func validateWGKey(value, label string, optional bool) error {
	value = strings.TrimSpace(value)
	if value == "" && optional {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%s must be a 32-byte base64 WireGuard key", label)
	}
	return nil
}

func validateCIDRs(values []string, label string, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("%s is required", label)
	}
	if len(values) > 32 {
		return fmt.Errorf("%s has too many entries", label)
	}
	for _, raw := range values {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid %s %q", label, raw)
		}
	}
	return nil
}

func validateStandardExit(e *standardExit) error {
	if e == nil {
		return errors.New("standard exit is required")
	}
	e.ID = strings.TrimSpace(e.ID)
	if e.ID == "" {
		e.ID = newStandardExitID()
	}
	if !validProfileID(e.ID) {
		return errors.New("invalid standard exit id")
	}
	e.Name = strings.TrimSpace(e.Name)
	if e.Name == "" {
		e.Name = "Custom Exit"
	}
	if len(e.Name) > 120 {
		return errors.New("standard exit name is too long")
	}
	e.Protocol = normalizeStandardExitProtocol(e.Protocol)
	if e.Protocol == "openvpn" {
		return errors.New("OpenVPN custom exit is unavailable: production is pinned to sing-box 1.13.x, which has no OpenVPN endpoint; wait for a stable pinned and validated dataplane")
	}
	switch e.Protocol {
	case "wireguard", "socks5", "shadowsocks", "hysteria2":
	default:
		return fmt.Errorf("unsupported standard exit protocol %q", e.Protocol)
	}
	server, err := normalizeEndpoint(e.Server)
	if err != nil {
		return fmt.Errorf("standard exit server: %w", err)
	}
	e.Server = server
	if e.ServerPort < 1 || e.ServerPort > 65535 {
		return errors.New("standard exit server port must be 1..65535")
	}
	ip := net.ParseIP(strings.TrimSpace(e.ExpectedPublicIP))
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return errors.New("expected_public_ip must be the public address expected after traffic really exits through this custom exit")
	}
	e.ExpectedPublicIP = ip.String()
	for label, value := range map[string]string{
		"username": e.Username, "password": e.Password, "secret": e.Secret,
		"tls_server_name": e.TLSServerName, "wg_private_key": e.WGPrivateKey,
		"wg_peer_public_key": e.WGPeerPublicKey, "wg_pre_shared_key": e.WGPreSharedKey,
	} {
		if len(value) > 4096 {
			return fmt.Errorf("%s is too long", label)
		}
	}

	switch e.Protocol {
	case "socks5":
		if (e.Username == "") != (e.Password == "") {
			return errors.New("SOCKS5 username/password must either both be set or both be empty")
		}
	case "shadowsocks":
		allowed := map[string]bool{
			"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
			"2022-blake3-chacha20-poly1305": true, "aes-128-gcm": true,
			"aes-256-gcm": true, "chacha20-ietf-poly1305": true,
		}
		e.Method = strings.ToLower(strings.TrimSpace(e.Method))
		if !allowed[e.Method] {
			return errors.New("unsupported or insecure Shadowsocks method")
		}
		if strings.TrimSpace(e.Secret) == "" {
			return errors.New("Shadowsocks password/PSK is required")
		}
	case "hysteria2":
		if strings.TrimSpace(e.Secret) == "" {
			return errors.New("Hysteria2 password is required")
		}
		e.TLSServerName = strings.TrimSpace(e.TLSServerName)
		if e.TLSServerName == "" || strings.ContainsAny(e.TLSServerName, " /\\?#@") {
			return errors.New("Hysteria2 requires a valid TLS server name")
		}
	case "wireguard":
		if err := validateWGKey(e.WGPrivateKey, "WireGuard private key", false); err != nil { return err }
		if err := validateWGKey(e.WGPeerPublicKey, "WireGuard peer public key", false); err != nil { return err }
		if err := validateWGKey(e.WGPreSharedKey, "WireGuard preshared key", true); err != nil { return err }
		if err := validateCIDRs(e.WGAddresses, "WireGuard interface addresses", true); err != nil { return err }
		if err := validateCIDRs(e.WGAllowedIPs, "WireGuard allowed IPs", true); err != nil { return err }
		if e.WGMTU != 0 && (e.WGMTU < 1280 || e.WGMTU > 9000) {
			return errors.New("WireGuard MTU must be 1280..9000 when specified")
		}
	}
	return nil
}

func standardExitSummaryFor(e standardExit) standardExitSummary {
	return standardExitSummary{
		ID: e.ID, Name: e.Name, Protocol: e.Protocol, Server: e.Server,
		ServerPort: e.ServerPort, ExpectedPublicIP: e.ExpectedPublicIP,
		HasCredentials: e.Username != "" || e.Password != "",
		HasSecret: e.Secret != "" || e.WGPreSharedKey != "",
		HasWireGuardKey: e.WGPrivateKey != "" || e.WGPeerPublicKey != "",
	}
}

func loadStandardExitStore() (standardExitStore, error) {
	path := standardExitStorePath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return standardExitStore{SchemaVersion: standardExitStoreVersion, Exits: []standardExit{}}, nil
	}
	if err != nil { return standardExitStore{}, err }
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return standardExitStore{}, errors.New("standard-exits.json must be a regular non-symlink file")
	}
	if info.Size() > standardExitMaxStore {
		return standardExitStore{}, errors.New("standard-exits.json exceeds size limit")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return standardExitStore{}, errors.New("standard-exits.json permissions are too broad; expected 0600")
	}
	raw, err := os.ReadFile(path); if err != nil { return standardExitStore{}, err }
	var store standardExitStore
	if err = json.Unmarshal(raw, &store); err != nil { return standardExitStore{}, err }
	if store.SchemaVersion != standardExitStoreVersion {
		return standardExitStore{}, fmt.Errorf("unsupported standard exit store schema %d", store.SchemaVersion)
	}
	seen := map[string]bool{}
	for i := range store.Exits {
		if err := validateStandardExit(&store.Exits[i]); err != nil { return standardExitStore{}, fmt.Errorf("exit %d: %w", i, err) }
		if seen[store.Exits[i].ID] { return standardExitStore{}, errors.New("duplicate standard exit id") }
		seen[store.Exits[i].ID] = true
	}
	return store, nil
}

func persistStandardExitStore(store standardExitStore) error {
	store.SchemaVersion = standardExitStoreVersion
	if len(store.Exits) > 64 { return errors.New("too many standard exits") }
	for i := range store.Exits {
		if err := validateStandardExit(&store.Exits[i]); err != nil { return err }
	}
	path := standardExitStorePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil { return err }
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace symlink standard-exits.json")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) { return err }
	raw, err := json.MarshalIndent(store, "", "  "); if err != nil { return err }
	if int64(len(raw)) > standardExitMaxStore { return errors.New("standard exit store exceeds size limit") }
	tmp, err := os.CreateTemp(dir, ".standard-exits-*.tmp"); if err != nil { return err }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err != nil { _ = tmp.Close(); return err }
	if _, err = tmp.Write(append(raw, '\n')); err != nil { _ = tmp.Close(); return err }
	if err = tmp.Sync(); err != nil { _ = tmp.Close(); return err }
	if err = tmp.Close(); err != nil { return err }
	return os.Rename(tmpName, path)
}

func standardExitByID(id string) (standardExit, error) {
	if !validProfileID(strings.TrimSpace(id)) { return standardExit{}, errors.New("invalid standard exit id") }
	store, err := loadStandardExitStore(); if err != nil { return standardExit{}, err }
	for _, e := range store.Exits { if e.ID == id { return e, nil } }
	return standardExit{}, errors.New("standard exit not found")
}

func standardExitRuntimeParts(e standardExit, detour string) (map[string]any, map[string]any, error) {
	if err := validateStandardExit(&e); err != nil { return nil, nil, err }
	if strings.TrimSpace(detour) == "" { return nil, nil, errors.New("standard exit requires a controlled upstream detour") }
	if e.Protocol == "wireguard" {
		peer := map[string]any{"address": e.Server, "port": e.ServerPort, "public_key": e.WGPeerPublicKey, "allowed_ips": e.WGAllowedIPs}
		if e.WGPreSharedKey != "" { peer["pre_shared_key"] = e.WGPreSharedKey }
		endpoint := map[string]any{"type":"wireguard", "tag":"custom-exit", "address":e.WGAddresses, "private_key":e.WGPrivateKey, "peers":[]any{peer}, "detour":detour}
		if e.WGMTU != 0 { endpoint["mtu"] = e.WGMTU }
		return endpoint, nil, nil
	}
	out := map[string]any{"tag":"custom-exit", "server":e.Server, "server_port":e.ServerPort, "detour":detour}
	switch e.Protocol {
	case "socks5":
		out["type"] = "socks"; out["version"] = "5"
		if e.Username != "" { out["username"] = e.Username; out["password"] = e.Password }
	case "shadowsocks":
		out["type"] = "shadowsocks"; out["method"] = e.Method; out["password"] = e.Secret
	case "hysteria2":
		out["type"] = "hysteria2"; out["password"] = e.Secret
		out["tls"] = map[string]any{"enabled":true, "server_name":e.TLSServerName}
	default:
		return nil, nil, fmt.Errorf("unsupported standard exit protocol %q", e.Protocol)
	}
	return nil, out, nil
}

func registerStandardExitRoutes(h *http.ServeMux) {
	h.HandleFunc("/api/standard-exits/capabilities", standardExitCapabilitiesHandler)
	h.HandleFunc("/api/standard-exits", standardExitListHandler)
	h.HandleFunc("/api/standard-exit/save", standardExitSaveHandler)
	h.HandleFunc("/api/standard-exit/delete", standardExitDeleteHandler)
}

func standardExitCapabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema_version":standardExitStoreVersion, "capabilities":standardExitCapabilities()})
}

func standardExitListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { http.Error(w, "GET only", http.StatusMethodNotAllowed); return }
	store, err := loadStandardExitStore(); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	rows := make([]standardExitSummary, 0, len(store.Exits)); for _, e := range store.Exits { rows = append(rows, standardExitSummaryFor(e)) }
	sort.Slice(rows, func(i,j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	w.Header().Set("content-type", "application/json"); _ = json.NewEncoder(w).Encode(map[string]any{"schema_version":store.SchemaVersion, "exits":rows})
}

func standardExitSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var candidate standardExit
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&candidate); err != nil { http.Error(w, "bad json", http.StatusBadRequest); return }
	if err := validateStandardExit(&candidate); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	store, err := loadStandardExitStore(); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	found := false
	for i := range store.Exits { if store.Exits[i].ID == candidate.ID { store.Exits[i] = candidate; found = true; break } }
	if !found { store.Exits = append(store.Exits, candidate) }
	if err = persistStandardExitStore(store); err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json"); _ = json.NewEncoder(w).Encode(map[string]any{"ok":true, "exit":standardExitSummaryFor(candidate)})
}

func standardExitDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
	var q struct{ ID string `json:"id"` }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil || !validProfileID(strings.TrimSpace(q.ID)) { http.Error(w, "invalid standard exit id", http.StatusBadRequest); return }
	store, err := loadStandardExitStore(); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	out := store.Exits[:0]; found := false
	for _, e := range store.Exits { if e.ID == q.ID { found = true; continue }; out = append(out, e) }
	if !found { http.Error(w, "standard exit not found", http.StatusNotFound); return }
	store.Exits = out
	if err = persistStandardExitStore(store); err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json"); _, _ = w.Write([]byte(`{"ok":true}`))
}
