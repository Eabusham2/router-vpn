package nativeopenvpn

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ValidateEndpoint accepts only a native endpoint that the original inline
// compiler can produce. Reconstructing and recompiling its directives keeps
// relay and Start Layer validation on the same bounded parser as Local, and
// rejects extra native options, host paths and another system tunnel.
func ValidateEndpoint(endpoint map[string]any) (map[string]any, error) {
	var validStrings func(any) bool
	validStrings = func(value any) bool {
		switch value := value.(type) {
		case string:
			return utf8.ValidString(value)
		case map[string]any:
			for key, child := range value {
				if !utf8.ValidString(key) || !validStrings(child) {
					return false
				}
			}
		case []any:
			for _, child := range value {
				if !validStrings(child) {
					return false
				}
			}
		case []string:
			for _, child := range value {
				if !utf8.ValidString(child) {
					return false
				}
			}
		}
		return true
	}
	if !validStrings(endpoint) {
		return nil, errPairing
	}
	raw, err := json.Marshal(endpoint)
	if err != nil {
		return nil, errPairing
	}
	p, err := pairingObject(raw, 2*MaxProfileBytes)
	if err != nil {
		return nil, errPairing
	}
	var source strings.Builder
	failed := false
	emit := func(name string, values ...string) {
		if failed {
			return
		}
		source.WriteString(name)
		for _, value := range values {
			if strings.ContainsAny(value, "\x00\r\n") {
				failed = true
				return
			}
			source.WriteString(" \"")
			source.WriteString(strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value))
			source.WriteByte('"')
		}
		source.WriteByte('\n')
	}
	text := func(value any) string {
		s, ok := value.(string)
		if !ok {
			failed = true
		}
		return s
	}
	number := func(value any) string {
		n, ok := value.(float64)
		if !ok || n < 0 || n > 604800 || n != float64(int(n)) {
			failed = true
			return ""
		}
		return strconv.Itoa(int(n))
	}
	array := func(value any) []string {
		values, ok := value.([]any)
		if !ok || len(values) == 0 {
			failed = true
			return nil
		}
		result := make([]string, len(values))
		for i, value := range values {
			result[i] = text(value)
		}
		return result
	}
	emit("client")
	if servers, exists := p["servers"]; exists {
		list, ok := servers.([]any)
		if !ok || len(list) < 2 || len(list) > 16 {
			return nil, errPairing
		}
		for _, raw := range list {
			server, ok := raw.(map[string]any)
			if !ok || len(server) != 3 {
				return nil, errPairing
			}
			emit("remote", text(server["server"]), number(server["server_port"]), text(server["network"]))
		}
	} else {
		emit("remote", text(p["server"]), number(p["server_port"]), text(p["network"]))
	}
	for field, directive := range map[string]string{"auth_retry": "auth-retry", "cipher": "cipher", "data_ciphers_fallback": "data-ciphers-fallback", "auth": "auth", "allow_compression": "allow-compression", "compression": "compress", "compression_lzo": "comp-lzo"} {
		if value, exists := p[field]; exists {
			emit(directive, text(value))
		}
	}
	for field, directive := range map[string]string{"mtu": "tun-mtu", "fragment": "fragment", "explicit_exit_notify": "explicit-exit-notify"} {
		if value, exists := p[field]; exists {
			emit(directive, number(value))
		}
	}
	for field, directive := range map[string]string{"ping_interval": "ping", "ping_restart": "ping-restart", "renegotiate_interval": "reneg-sec", "handshake_window": "hand-window", "tls_timeout": "tls-timeout"} {
		if value, exists := p[field]; exists {
			duration := text(value)
			if !strings.HasSuffix(duration, "s") {
				return nil, errPairing
			}
			emit(directive, strings.TrimSuffix(duration, "s"))
		}
	}
	if value, exists := p["data_ciphers"]; exists {
		emit("data-ciphers", strings.Join(array(value), ":"))
	}
	for field, directive := range map[string]string{"remote_random": "remote-random", "route_no_pull": "route-nopull"} {
		if value, exists := p[field]; exists {
			if value != true {
				return nil, errPairing
			}
			emit(directive)
		}
	}
	if value, exists := p["renegotiate_disabled"]; exists {
		if value != true {
			return nil, errPairing
		}
		emit("reneg-sec", "0")
	}
	if value, exists := p["mss_fix"]; exists {
		args := []string{number(value)}
		if mode, exists := p["mss_fix_mode"]; exists {
			args = append(args, text(mode))
		}
		emit("mssfix", args...)
	}
	if value, exists := p["mss_fix_disabled"]; exists {
		if value != true {
			return nil, errPairing
		}
		args := []string{"0"}
		if mode, exists := p["mss_fix_mode"]; exists {
			args = append(args, text(mode))
		}
		emit("mssfix", args...)
	}
	if value, exists := p["redirect_gateway"]; exists {
		if value != true {
			return nil, errPairing
		}
		var args []string
		if flags, exists := p["redirect_gateway_flags"]; exists {
			args = array(flags)
		}
		emit("redirect-gateway", args...)
	}
	if value, exists := p["pull_filters"]; exists {
		filters, ok := value.([]any)
		if !ok || len(filters) == 0 || len(filters) > 32 {
			return nil, errPairing
		}
		for _, value := range filters {
			filter, ok := value.(map[string]any)
			if !ok || len(filter) != 2 {
				return nil, errPairing
			}
			emit("pull-filter", text(filter["action"]), text(filter["text"]))
		}
	}
	tls, ok := p["tls"].(map[string]any)
	if !ok {
		return nil, errPairing
	}
	for field, directive := range map[string]string{"remote_certificate_tls": "remote-cert-tls", "version_min": "tls-version-min", "version_max": "tls-version-max", "cipher": "tls-cipher", "groups": "tls-groups"} {
		if value, exists := tls[field]; exists {
			emit(directive, text(value))
		}
	}
	if value, exists := tls["server_name"]; exists {
		emit("verify-x509-name", text(value), text(tls["server_name_type"]))
	}
	if value, exists := tls["peer_fingerprint"]; exists {
		values := array(value)
		if len(values) != 1 {
			return nil, errPairing
		}
		emit("peer-fingerprint", values[0])
	}
	block := func(name string, value any) {
		content, err := inlineStrings(value)
		if err != nil {
			failed = true
			return
		}
		source.WriteString("<" + name + ">\n" + content + "</" + name + ">\n")
	}
	for field, name := range map[string]string{"certificate": "ca", "client_certificate": "cert", "client_key": "key"} {
		if value, exists := tls[field]; exists {
			block(name, value)
		}
	}
	if value, exists := tls["control_wrap"]; exists {
		wrap, ok := value.(map[string]any)
		if !ok {
			return nil, errPairing
		}
		name := strings.ReplaceAll(text(wrap["type"]), "_", "-")
		if !routerOpenVPNOneOf(name, "tls-auth", "tls-crypt", "tls-crypt-v2") {
			return nil, errPairing
		}
		block(name, wrap["key"])
		if value, exists := wrap["direction"]; exists {
			switch value {
			case "client":
				emit("key-direction", "1")
			case "server":
				emit("key-direction", "0")
			default:
				return nil, errPairing
			}
		}
	}
	profile := Profile{Config: source.String()}
	if value, exists := p["username"]; exists {
		profile.Username = text(value)
	}
	if value, exists := p["password"]; exists {
		profile.Password = text(value)
	}
	tag := text(p["tag"])
	detour := ""
	if value, exists := p["detour"]; exists {
		detour = text(value)
	}
	if failed {
		return nil, errPairing
	}
	compiled, err := CompileProfile(profile, tag, detour)
	if err != nil || !reflect.DeepEqual(compiled, p) {
		return nil, errPairing
	}
	return compiled, nil
}
