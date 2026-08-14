package common

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	ExternalExitSchemaVersion = 1
	ExternalExitStoreVersion  = 1
	MaxExternalConfigBytes    = 256 << 10
)

// ExternalExit is private local client state for a non-Router-VPN exit/hop.
// It is deliberately separate from RouterProfile: an arbitrary provider does
// not gain Router VPN node-proof/admin semantics merely because it can carry
// traffic. Config/credentials are persisted only in the private local store
// and must never be returned by public/list APIs.
type ExternalExit struct {
	SchemaVersion int    `json:"schema_version,omitempty"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"` // wireguard | openvpn | shadowsocks | socks5
	Endpoint      string `json:"endpoint,omitempty"`
	Port          int    `json:"port,omitempty"`

	// Protocol-private material. WireGuard/OpenVPN use Config. Proxy protocols
	// use the structured secret fields. These values are redacted from all
	// normal list/status responses.
	Config     string `json:"config,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	Location  string  `json:"location,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	UseCount  int     `json:"use_count,omitempty"`
	LastUsed  string  `json:"last_used_at,omitempty"`
}

type ExternalExitStore struct {
	SchemaVersion int            `json:"schema_version,omitempty"`
	SelectedID    string         `json:"selected_id,omitempty"`
	Exits         []ExternalExit `json:"exits"`
}

// ExternalExitPublic is safe to return to the loopback UI. Secret/config
// material is intentionally not representable in this type.
type ExternalExitPublic struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Protocol   string  `json:"protocol"`
	Endpoint   string  `json:"endpoint,omitempty"`
	Port       int     `json:"port,omitempty"`
	ServerName string  `json:"server_name,omitempty"`
	Location   string  `json:"location,omitempty"`
	Latitude   float64 `json:"latitude,omitempty"`
	Longitude  float64 `json:"longitude,omitempty"`
	UseCount   int     `json:"use_count,omitempty"`
	LastUsed   string  `json:"last_used_at,omitempty"`
	Configured bool    `json:"configured"`
}

func ExternalExitPublicView(x ExternalExit) ExternalExitPublic {
	configured := false
	switch x.Protocol {
	case "wireguard", "openvpn":
		configured = strings.TrimSpace(x.Config) != ""
	case "shadowsocks":
		configured = x.Endpoint != "" && x.Port > 0 && x.Cipher != "" && x.Password != ""
	case "socks5":
		configured = x.Endpoint != "" && x.Port > 0
	}
	return ExternalExitPublic{
		ID: x.ID, Name: x.Name, Protocol: x.Protocol, Endpoint: x.Endpoint, Port: x.Port,
		ServerName: x.ServerName, Location: x.Location, Latitude: x.Latitude, Longitude: x.Longitude,
		UseCount: x.UseCount, LastUsed: x.LastUsed, Configured: configured,
	}
}

func normalizeExternalProtocol(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "wg", "wireguard":
		return "wireguard"
	case "ovpn", "openvpn":
		return "openvpn"
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "socks", "socks5", "socks-5":
		return "socks5"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func validExternalID(id string) bool {
	if len(id) < 1 || len(id) > 80 || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func normalizeExternalHost(v string) (string, error) {
	v = strings.TrimSpace(strings.Trim(v, "[]"))
	if v == "" {
		return "", errors.New("external exit endpoint is empty")
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String(), nil
	}
	if len(v) > 253 || strings.ContainsAny(v, " /\\?#@:") || strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
		return "", errors.New("external exit endpoint is not a valid hostname")
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("external exit endpoint is not a valid hostname")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return "", errors.New("external exit endpoint is not a valid hostname")
			}
		}
	}
	return strings.ToLower(v), nil
}

func NormalizeExternalExit(x *ExternalExit) error {
	if x.SchemaVersion > ExternalExitSchemaVersion {
		return fmt.Errorf("external exit schema %d is newer than supported schema %d", x.SchemaVersion, ExternalExitSchemaVersion)
	}
	x.SchemaVersion = ExternalExitSchemaVersion
	x.ID = strings.TrimSpace(x.ID)
	if !validExternalID(x.ID) {
		return errors.New("invalid external exit id")
	}
	x.Name = strings.TrimSpace(x.Name)
	if x.Name == "" {
		x.Name = x.ID
	}
	if len(x.Name) > 128 {
		return errors.New("external exit name is too long")
	}
	x.Protocol = normalizeExternalProtocol(x.Protocol)
	if len(x.Config) > MaxExternalConfigBytes {
		return errors.New("external exit config exceeds 256 KiB")
	}

	switch x.Protocol {
	case "openvpn":
		clean, endpoint, port, err := SanitizeOpenVPNConfig(x.Config)
		if err != nil {
			return err
		}
		x.Config, x.Endpoint, x.Port = clean, endpoint, port
	case "wireguard":
		if strings.TrimSpace(x.Config) == "" {
			return errors.New("WireGuard external exit requires a config")
		}
		if !strings.Contains(x.Config, "[Interface]") || !strings.Contains(x.Config, "[Peer]") {
			return errors.New("WireGuard external exit config must contain Interface and Peer sections")
		}
	case "shadowsocks":
		host, err := normalizeExternalHost(x.Endpoint)
		if err != nil { return err }
		x.Endpoint = host
		if x.Port < 1 || x.Port > 65535 { return errors.New("Shadowsocks external exit port is invalid") }
		x.Cipher = strings.TrimSpace(x.Cipher)
		if x.Cipher == "" || strings.TrimSpace(x.Password) == "" { return errors.New("Shadowsocks external exit requires cipher and password") }
	case "socks5":
		host, err := normalizeExternalHost(x.Endpoint)
		if err != nil { return err }
		x.Endpoint = host
		if x.Port < 1 || x.Port > 65535 { return errors.New("SOCKS5 external exit port is invalid") }
		if (x.Username == "") != (x.Password == "") { return errors.New("SOCKS5 username/password must either both be set or both be empty") }
	default:
		return fmt.Errorf("unsupported external exit protocol %q", x.Protocol)
	}
	return nil
}

func NormalizeExternalExitStore(s *ExternalExitStore) error {
	if s.SchemaVersion > ExternalExitStoreVersion {
		return fmt.Errorf("external exit store schema %d is newer than supported schema %d", s.SchemaVersion, ExternalExitStoreVersion)
	}
	s.SchemaVersion = ExternalExitStoreVersion
	seen := map[string]bool{}
	for i := range s.Exits {
		if err := NormalizeExternalExit(&s.Exits[i]); err != nil {
			return fmt.Errorf("external exit %q: %w", s.Exits[i].ID, err)
		}
		if seen[s.Exits[i].ID] { return fmt.Errorf("duplicate external exit id %q", s.Exits[i].ID) }
		seen[s.Exits[i].ID] = true
	}
	if s.SelectedID != "" && !seen[s.SelectedID] {
		return errors.New("selected external exit does not exist")
	}
	return nil
}

// SanitizeOpenVPNConfig accepts a self-contained client profile but rejects
// directives that can execute commands/plugins, read arbitrary host files, or
// write arbitrary host files when Router VPN later launches OpenVPN elevated.
// For a predictable kill-switch exception it currently requires exactly one
// remote endpoint. Credentials, if needed, are supplied separately by Router
// VPN rather than through auth-user-pass <path>.
func SanitizeOpenVPNConfig(raw string) (clean, endpoint string, port int, err error) {
	if len(raw) == 0 { return "", "", 0, errors.New("OpenVPN external exit requires a config") }
	if len(raw) > MaxExternalConfigBytes { return "", "", 0, errors.New("OpenVPN external exit config exceeds 256 KiB") }
	if strings.IndexByte(raw, 0) >= 0 { return "", "", 0, errors.New("OpenVPN config contains NUL bytes") }

	blocked := map[string]bool{
		"script-security":true, "up":true, "down":true, "route-up":true, "route-pre-down":true,
		"ipchange":true, "client-connect":true, "client-disconnect":true, "learn-address":true,
		"auth-user-pass-verify":true, "tls-verify":true, "plugin":true, "config":true,
		"management":true, "management-client-auth":true, "management-external-key":true,
		"management-external-cert":true, "management-query-passwords":true, "iproute":true,
		"log":true, "log-append":true, "status":true, "writepid":true, "tmp-dir":true,
		"askpass":true, "auth-user-pass":true, "http-proxy-user-pass":true, "tls-export-cert":true,
		"ca":true, "cert":true, "key":true, "pkcs12":true, "tls-auth":true, "tls-crypt":true,
		"tls-crypt-v2":true, "secret":true, "crl-verify":true, "dh":true, "extra-certs":true,
		"client-crresponse":true,
	}
	inline := map[string]bool{"<ca>":true,"<cert>":true,"<key>":true,"<pkcs12>":true,"<tls-auth>":true,"<tls-crypt>":true,"<tls-crypt-v2>":true,"<extra-certs>":true}
	inlineEnd := map[string]string{"<ca>":"</ca>","<cert>":"</cert>","<key>":"</key>","<pkcs12>":"</pkcs12>","<tls-auth>":"</tls-auth>","<tls-crypt>":"</tls-crypt>","<tls-crypt-v2>":"</tls-crypt-v2>","<extra-certs>":"</extra-certs>"}

	var out []string
	var remoteHost string
	remotePort := 1194
	remoteCount := 0
	activeInline := ""
	s := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(raw, "\r\n", "\n")))
	buf := make([]byte, 64<<10)
	s.Buffer(buf, MaxExternalConfigBytes)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if activeInline != "" {
			out = append(out, s.Text())
			if line == inlineEnd[activeInline] { activeInline = "" }
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			out = append(out, s.Text())
			continue
		}
		lowerLine := strings.ToLower(line)
		if inline[lowerLine] {
			activeInline = lowerLine
			out = append(out, s.Text())
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 { continue }
		directive := strings.ToLower(fields[0])
		if blocked[directive] {
			return "", "", 0, fmt.Errorf("OpenVPN directive %q is not allowed in Router VPN imports", directive)
		}
		if directive == "dev" && len(fields) > 1 && strings.HasPrefix(strings.ToLower(fields[1]), "tap") {
			return "", "", 0, errors.New("OpenVPN TAP/Layer-2 profiles are not supported; use a TUN client profile")
		}
		if directive == "remote" {
			if len(fields) < 2 || len(fields) > 4 { return "", "", 0, errors.New("OpenVPN remote directive is invalid") }
			host, hostErr := normalizeExternalHost(fields[1])
			if hostErr != nil { return "", "", 0, fmt.Errorf("OpenVPN remote: %w", hostErr) }
			p := 1194
			if len(fields) >= 3 {
				parsed, parseErr := strconv.Atoi(fields[2])
				if parseErr != nil || parsed < 1 || parsed > 65535 { return "", "", 0, errors.New("OpenVPN remote port is invalid") }
				p = parsed
			}
			remoteCount++
			remoteHost, remotePort = host, p
		}
		out = append(out, s.Text())
	}
	if err := s.Err(); err != nil { return "", "", 0, fmt.Errorf("OpenVPN config read failed: %w", err) }
	if activeInline != "" { return "", "", 0, fmt.Errorf("OpenVPN inline block %s is not closed", activeInline) }
	if remoteCount != 1 { return "", "", 0, fmt.Errorf("OpenVPN external exit currently requires exactly one remote directive; found %d", remoteCount) }
	joined := strings.Join(out, "\n") + "\n"
	return joined, remoteHost, remotePort, nil
}
