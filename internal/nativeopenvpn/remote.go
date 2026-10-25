package nativeopenvpn

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var errRemote = errors.New("OpenVPN remote proof requires the exact connected native transport and every captured public remote")
var ErrRemotePending = errors.New("owned native OpenVPN transport is not connected")

// Remote identifies the actual provider transport, independently of the
// virtual tunnel address and the server's proved public egress address.
type Remote struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

// RemoteReceipt contains no certificate, provider identity, challenge or
// credential. Generation changes on every new physical OpenVPN transport,
// including a reconnect to the same address. Its owner supplies liveness.
type RemoteReceipt struct {
	Remote
	Generation  uint64 `json:"generation"`
	ConnectedAt int64  `json:"connected_at"`
}

func remotePublicHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.String() == host && ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func (remote Remote) Validate() error {
	if !remotePublicHost(remote.Host) || remote.Port < 1 || remote.Port > 65535 || remote.Network != "tcp" && remote.Network != "udp" {
		return errRemote
	}
	return nil
}

func ParseRemote(address, network string) (Remote, error) {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	remote := Remote{Host: host, Port: port, Network: network}
	if err != nil || portErr != nil || portText != strconv.Itoa(port) || remote.Validate() != nil {
		return Remote{}, errRemote
	}
	return remote, nil
}

func (receipt RemoteReceipt) Validate() error {
	if receipt.Remote.Validate() != nil || receipt.Generation == 0 || receipt.Generation > 1<<53-1 || receipt.ConnectedAt <= 0 || receipt.ConnectedAt > 1<<53-1 {
		return errRemote
	}
	return nil
}

func (receipt *RemoteReceipt) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 2048)
	if err != nil || len(object) != 5 {
		return errRemote
	}
	for _, key := range []string{"host", "network"} {
		if _, ok := object[key].(string); !ok {
			return errRemote
		}
	}
	for _, key := range []string{"port", "generation", "connected_at"} {
		if _, ok := object[key].(float64); !ok {
			return errRemote
		}
	}
	type plain RemoteReceipt
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || RemoteReceipt(decoded).Validate() != nil {
		return errRemote
	}
	*receipt = RemoteReceipt(decoded)
	return nil
}

// Remotes retains every original port and protocol. The paired transport
// descriptor must already have passed the inline profile compiler; this helper
// also checks the bounded shape before using it as receipt authority.
func Remotes(endpoint map[string]any) ([]Remote, error) {
	var servers []any
	if value, exists := endpoint["servers"]; exists {
		var ok bool
		servers, ok = value.([]any)
		if !ok || len(servers) < 2 || len(servers) > 16 || endpoint["server"] != nil || endpoint["server_port"] != nil {
			return nil, errRemote
		}
		first, ok := servers[0].(map[string]any)
		if !ok || endpoint["network"] != first["network"] {
			return nil, errRemote
		}
	} else {
		servers = []any{map[string]any{"server": endpoint["server"], "server_port": endpoint["server_port"], "network": endpoint["network"]}}
	}
	result := make([]Remote, 0, len(servers))
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok || len(server) != 3 {
			return nil, errRemote
		}
		host, hostOK := server["server"].(string)
		port, portOK := server["server_port"].(float64)
		network, networkOK := server["network"].(string)
		if !hostOK || !portOK || !networkOK || port != float64(int(port)) {
			return nil, errRemote
		}
		switch network {
		case "tcp4", "tcp6":
			network = "tcp"
		case "udp4", "udp6":
			network = "udp"
		}
		remote := Remote{Host: host, Port: int(port), Network: network}
		if remote.Validate() != nil {
			return nil, errRemote
		}
		result = append(result, remote)
	}
	return result, nil
}

func (receipt RemoteReceipt) Matches(endpoint map[string]any) bool {
	if receipt.Validate() != nil {
		return false
	}
	remotes, err := Remotes(endpoint)
	if err != nil {
		return false
	}
	for _, remote := range remotes {
		if remote == receipt.Remote {
			return true
		}
	}
	return false
}

type ResponseEndpoint struct {
	URL        string `json:"url"`
	ServerName string `json:"server_name,omitempty"`
}

// ResponseProbes is private provider configuration. A multi-host comparison
// needs a TLS-verified response endpoint on every possible connected host;
// none is inferred from the first remote or from an unrelated internet echo.
type ResponseProbes map[string]ResponseEndpoint

func (probe ResponseEndpoint) Validate(host string) error {
	u, err := url.Parse(probe.URL)
	if err != nil || !remotePublicHost(host) || len(probe.URL) > 2048 || strings.TrimSpace(probe.URL) != probe.URL || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Opaque != "" || u.Hostname() != host || strings.HasSuffix(u.Host, ":") {
		return errRemote
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errRemote
		}
	}
	if name := probe.ServerName; name != "" {
		if len(name) > 253 || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") || strings.EqualFold(name, "localhost") {
			return errRemote
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return errRemote
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errRemote
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return errRemote
				}
			}
		}
	}
	return nil
}

func (probes *ResponseProbes) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 40<<10)
	if err != nil || len(object) < 2 || len(object) > 16 {
		return errRemote
	}
	result := ResponseProbes{}
	for host, value := range object {
		fields, ok := value.(map[string]any)
		if !ok || len(fields) < 1 || len(fields) > 2 {
			return errRemote
		}
		url, urlOK := fields["url"].(string)
		name := ""
		if rawName, exists := fields["server_name"]; exists {
			var ok bool
			name, ok = rawName.(string)
			if !ok {
				return errRemote
			}
		}
		for key := range fields {
			if key != "url" && key != "server_name" {
				return errRemote
			}
		}
		probe := ResponseEndpoint{URL: url, ServerName: name}
		if !urlOK || probe.Validate(host) != nil {
			return errRemote
		}
		result[host] = probe
	}
	*probes = result
	return nil
}

func (probes ResponseProbes) Validate(endpoint map[string]any) error {
	remotes, err := Remotes(endpoint)
	if err != nil || len(probes) < 2 || len(probes) > 16 {
		return errRemote
	}
	hosts := map[string]bool{}
	for _, remote := range remotes {
		hosts[remote.Host] = true
		probe, ok := probes[remote.Host]
		if !ok || probe.Validate(remote.Host) != nil {
			return errRemote
		}
	}
	if len(hosts) != len(probes) {
		return errRemote
	}
	return nil
}

func ValidateResponseProbesJSON(profileJSON, probesJSON string) error {
	var profile Profile
	var probes ResponseProbes
	if json.Unmarshal([]byte(profileJSON), &profile) != nil || json.Unmarshal([]byte(probesJSON), &probes) != nil {
		return errRemote
	}
	endpoint, err := CompileProfile(profile, "exit", "")
	if err != nil {
		return errRemote
	}
	return probes.Validate(endpoint)
}
