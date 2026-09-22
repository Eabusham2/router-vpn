// This file is compiled once into each platform's existing Libbox Go runtime.
// The same source is tested here without gomobile or private network access.
package libbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

const routerOpenVPNMaxBytes = 256 * 1024

// RouterOpenVPNEndpoint compiles an inline .ovpn profile into the pinned native
// openvpn-client endpoint. It never executes a command, reads a referenced file,
// resolves a hostname, or installs an OS route. The enclosing mobile TUN retains
// route, DNS, lifecycle and public-exit proof ownership. Errors contain directive
// names/line numbers, never profile contents, private keys or credentials.
func RouterOpenVPNEndpoint(config, username, password, tag, detour string) (string, error) {
	if len(config) == 0 || len(config) > routerOpenVPNMaxBytes || !utf8.ValidString(config) || strings.ContainsRune(config, 0) {
		return "", errors.New("OpenVPN profile must be bounded UTF-8 text (at most 256 KiB)")
	}
	for _, value := range []string{username, password} {
		if len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("OpenVPN credential has an invalid size or encoding")
		}
	}
	if (username == "") != (password == "") {
		return "", errors.New("OpenVPN username and password must both be supplied or both be empty")
	}
	if !routerOpenVPNTag(tag) || (detour != "" && (!routerOpenVPNTag(detour) || tag == detour)) {
		return "", errors.New("OpenVPN graph tag or detour is invalid")
	}
	p := routerOpenVPNParser{
		endpoint: map[string]any{"type": "openvpn-client", "tag": tag, "system": false, "mode": "tls"},
		tls:      map[string]any{"remote_certificate_tls": "server", "version_min": "1.2"},
		seen:     make(map[string]bool), blocks: make(map[string]string), network: "udp", defaultPort: 1194,
	}
	text := strings.TrimPrefix(config, "\ufeff")
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if !routerOpenVPNOneOf(name, "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2") || p.blocks[name] != "" {
				return "", p.issue(i+1, "inline block is unknown or duplicated")
			}
			start := i + 1
			for i++; i < len(lines) && strings.TrimSpace(lines[i]) != "</"+name+">"; i++ {
				if strings.HasPrefix(strings.TrimSpace(lines[i]), "<") {
					return "", p.issue(i+1, "nested inline blocks are not supported")
				}
			}
			if i == len(lines) || strings.TrimSpace(strings.Join(lines[start:i], "\n")) == "" {
				return "", p.issue(start, "inline block is empty or unterminated")
			}
			p.blocks[name] = strings.Join(lines[start:i], "\n") + "\n"
			continue
		}
		words, err := routerOpenVPNWords(line)
		if err != nil {
			return "", p.issue(i+1, "invalid quoting or escape")
		}
		if len(words) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(words[0], "--"))
		if !routerOpenVPNDirective(name) {
			return "", p.issue(i+1, "invalid directive name")
		}
		if p.seen[name] && name != "remote" && name != "pull-filter" {
			return "", p.issue(i+1, "duplicate directive "+name)
		}
		p.seen[name] = true
		if err := p.option(name, words[1:]); err != nil {
			return "", p.issue(i+1, name+": "+err.Error())
		}
	}
	if len(p.remotes) == 0 {
		return "", errors.New("OpenVPN profile requires at least one literal remote")
	}
	for i := range p.remotes {
		if p.remotes[i]["network"] == "" {
			p.remotes[i]["network"] = p.network
		}
		if p.remotes[i]["server_port"] == 0 {
			p.remotes[i]["server_port"] = p.defaultPort
		}
		address, _ := netip.ParseAddr(p.remotes[i]["server"].(string))
		network := p.remotes[i]["network"].(string)
		if (strings.HasSuffix(network, "4") && !address.Is4()) || (strings.HasSuffix(network, "6") && !address.Is6()) {
			return "", errors.New("OpenVPN remote address does not match its requested IP family")
		}
	}
	p.endpoint["server"] = p.remotes[0]["server"]
	p.endpoint["server_port"] = p.remotes[0]["server_port"]
	p.endpoint["network"] = p.remotes[0]["network"]
	if len(p.remotes) > 1 {
		p.endpoint["servers"] = p.remotes
	}
	if detour != "" {
		p.endpoint["detour"] = detour
	}
	if p.seen["auth-user-pass"] && username == "" {
		return "", errors.New("OpenVPN profile requests username/password authentication")
	}
	if username != "" {
		p.endpoint["username"] = username
		p.endpoint["password"] = password
	}
	for directive, field := range map[string]string{"ca": "certificate", "cert": "client_certificate", "key": "client_key"} {
		if block := p.blocks[directive]; block != "" {
			p.tls[field] = []string{block}
		}
		if p.seen[directive] && p.blocks[directive] == "" {
			return "", errors.New("OpenVPN inline certificate/key declaration has no matching block")
		}
	}
	if (p.blocks["cert"] == "") != (p.blocks["key"] == "") {
		return "", errors.New("OpenVPN client certificate and key must both be supplied")
	}
	if p.blocks["ca"] == "" && p.tls["peer_fingerprint"] == nil {
		return "", errors.New("OpenVPN requires an inline CA or explicit peer fingerprint for server verification")
	}
	if p.blocks["cert"] == "" && username == "" {
		return "", errors.New("OpenVPN requires client certificate/key or username/password authentication")
	}
	wrapCount := 0
	for _, name := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
		block := p.blocks[name]
		if p.seen[name] && block == "" {
			return "", errors.New("OpenVPN control-key declaration has no matching inline block")
		}
		if block == "" {
			continue
		}
		wrapCount++
		wrap := map[string]any{"type": strings.ReplaceAll(name, "-", "_"), "key": []string{block}}
		if p.direction != "" {
			if name != "tls-auth" {
				return "", errors.New("OpenVPN key-direction is valid only with tls-auth")
			}
			wrap["direction"] = p.direction
		}
		p.tls["control_wrap"] = wrap
	}
	if wrapCount > 1 || (p.direction != "" && wrapCount == 0) {
		return "", errors.New("OpenVPN control-wrap/key-direction is ambiguous")
	}
	if low, _ := p.tls["version_min"].(string); low != "" {
		if high, _ := p.tls["version_max"].(string); high != "" && high < low {
			return "", errors.New("OpenVPN TLS version bounds are reversed")
		}
	}
	p.endpoint["tls"] = p.tls
	result, err := json.Marshal(p.endpoint)
	if err != nil || len(result) > 2*routerOpenVPNMaxBytes {
		return "", errors.New("OpenVPN generated endpoint exceeds its safety limit")
	}
	return string(result), nil
}

type routerOpenVPNParser struct {
	endpoint, tls      map[string]any
	seen               map[string]bool
	blocks             map[string]string
	remotes            []map[string]any
	network, direction string
	defaultPort        int
}

func (p *routerOpenVPNParser) issue(line int, message string) error {
	return fmt.Errorf("OpenVPN line %d: %s", line, message)
}
func routerOpenVPNOneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
func routerOpenVPNTag(s string) bool {
	if len(s) == 0 || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func routerOpenVPNDirective(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func routerOpenVPNNetwork(s string) (string, error) {
	s = strings.ToLower(s)
	switch s {
	case "tcp-client":
		s = "tcp"
	case "tcp4-client":
		s = "tcp4"
	case "tcp6-client":
		s = "tcp6"
	}
	if !routerOpenVPNOneOf(s, "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6") {
		return "", errors.New("unsupported client transport")
	}
	return s, nil
}
func routerOpenVPNNumber(s string, min, max int) (int, error) {
	if len(s) == 0 || len(s) > 10 {
		return 0, errors.New("invalid numeric value")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid numeric value")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < min || n > max {
		return 0, errors.New("numeric value outside supported range")
	}
	return n, nil
}
func (p *routerOpenVPNParser) option(name string, a []string) error {
	arity := func(lo, hi int) error {
		if len(a) < lo || len(a) > hi {
			return errors.New("invalid number of arguments")
		}
		return nil
	}
	number := func(field string, min, max int) error {
		if err := arity(1, 1); err != nil {
			return err
		}
		v, e := routerOpenVPNNumber(a[0], min, max)
		if e == nil {
			p.endpoint[field] = v
		}
		return e
	}
	duration := func(field string) error {
		if err := arity(1, 1); err != nil {
			return err
		}
		v, e := routerOpenVPNNumber(a[0], 0, 604800)
		if e == nil {
			p.endpoint[field] = strconv.Itoa(v) + "s"
		}
		return e
	}
	switch name {
	case "client", "tls-client", "pull":
		return arity(0, 0) // Native TLS client mode; pushed routes remain inside its userspace stack.
	case "dev", "dev-type":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] != "tun" {
			return errors.New("only the owned TUN device is supported")
		}
		return nil
	case "nobind", "persist-key", "persist-tun", "auth-nocache":
		return arity(0, 0) // Native socket/service lifecycle replaces command-line process persistence.
	case "verb", "mute":
		if err := arity(1, 1); err != nil {
			return err
		}
		_, e := routerOpenVPNNumber(a[0], 0, 100)
		return e // App owns bounded logging; config cannot increase verbosity.
	case "resolv-retry":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] == "infinite" {
			return nil
		}
		_, err := routerOpenVPNNumber(a[0], 0, 604800)
		return err // Literal remotes require no DNS lookup.
	case "auth-retry":
		if err := arity(1, 1); err != nil {
			return err
		}
		if !routerOpenVPNOneOf(a[0], "none", "nointeract") {
			return errors.New("interactive challenges require explicit UI support")
		}
		p.endpoint["auth_retry"] = a[0]
		return nil
	case "tls-cipher", "tls-groups":
		if err := arity(1, 1); err != nil {
			return err
		}
		if len(a[0]) == 0 || len(a[0]) > 2048 {
			return errors.New("invalid TLS negotiation policy")
		}
		field := "cipher"
		if name == "tls-groups" {
			field = "groups"
		}
		p.tls[field] = a[0]
		return nil
	case "proto":
		if err := arity(1, 1); err != nil {
			return err
		}
		n, e := routerOpenVPNNetwork(a[0])
		p.network = n
		return e
	case "port", "rport":
		if err := arity(1, 1); err != nil {
			return err
		}
		if name == "port" && p.seen["rport"] || name == "rport" && p.seen["port"] {
			return errors.New("conflicting default ports")
		}
		n, e := routerOpenVPNNumber(a[0], 1, 65535)
		p.defaultPort = n
		return e
	case "remote":
		if err := arity(1, 3); err != nil {
			return err
		}
		if len(p.remotes) >= 16 {
			return errors.New("too many remotes")
		}
		ip, err := netip.ParseAddr(a[0])
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.Is4In6() {
			return errors.New("remote must be an unscoped unicast literal IP")
		}
		port := 0
		network := ""
		if len(a) > 1 {
			port, err = routerOpenVPNNumber(a[1], 1, 65535)
			if err != nil {
				return err
			}
		}
		if len(a) > 2 {
			network, err = routerOpenVPNNetwork(a[2])
			if err != nil {
				return err
			}
		}
		p.remotes = append(p.remotes, map[string]any{"server": ip.String(), "server_port": port, "network": network})
		return nil
	case "remote-random":
		if err := arity(0, 0); err != nil {
			return err
		}
		p.endpoint["remote_random"] = true
		return nil
	case "auth-user-pass":
		if len(a) == 1 && a[0] == "[inline]" {
			return errors.New("supply credentials through the private app fields")
		}
		return arity(0, 0)
	case "ca", "cert", "key", "tls-crypt", "tls-crypt-v2":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] != "[inline]" {
			return errors.New("only inline material is allowed; file references are never read")
		}
		return nil
	case "tls-auth":
		if err := arity(1, 2); err != nil {
			return err
		}
		if a[0] != "[inline]" {
			return errors.New("only inline control keys are allowed")
		}
		if len(a) == 2 {
			return p.setDirection(a[1])
		}
		return nil
	case "key-direction":
		if err := arity(1, 1); err != nil {
			return err
		}
		return p.setDirection(a[0])
	case "remote-cert-tls":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] != "server" {
			return errors.New("server certificate verification cannot be disabled")
		}
		return nil
	case "verify-x509-name":
		if err := arity(1, 2); err != nil {
			return err
		}
		if len(a[0]) == 0 || len(a[0]) > 1024 {
			return errors.New("invalid certificate name")
		}
		kind := "subject"
		if len(a) == 2 {
			kind = a[1]
		}
		if !routerOpenVPNOneOf(kind, "subject", "name", "name-prefix") {
			return errors.New("unknown certificate name match")
		}
		p.tls["server_name"] = a[0]
		p.tls["server_name_type"] = kind
		return nil
	case "peer-fingerprint":
		if err := arity(1, 1); err != nil {
			return err
		}
		s := strings.ReplaceAll(a[0], ":", "")
		if len(s) != 64 {
			return errors.New("SHA-256 certificate fingerprint required")
		}
		for _, c := range s {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return errors.New("invalid certificate fingerprint")
			}
		}
		p.tls["peer_fingerprint"] = []string{a[0]}
		return nil
	case "tls-version-min", "tls-version-max":
		if err := arity(1, 1); err != nil {
			return err
		}
		if !routerOpenVPNOneOf(a[0], "1.2", "1.3") {
			return errors.New("TLS 1.2 or newer is required")
		}
		field := "version_min"
		if name == "tls-version-max" {
			field = "version_max"
		}
		p.tls[field] = a[0]
		return nil
	case "cipher", "data-ciphers-fallback":
		if err := arity(1, 1); err != nil {
			return err
		}
		if !routerOpenVPNCipher(a[0]) {
			return errors.New("unsupported or insecure data cipher")
		}
		p.endpoint[strings.ReplaceAll(name, "-", "_")] = strings.ToUpper(a[0])
		return nil
	case "data-ciphers", "ncp-ciphers":
		if err := arity(1, 1); err != nil {
			return err
		}
		if p.endpoint["data_ciphers"] != nil {
			return errors.New("cipher negotiation is duplicated")
		}
		ciphers := strings.Split(strings.ToUpper(a[0]), ":")
		if len(ciphers) > 8 {
			return errors.New("too many ciphers")
		}
		for _, c := range ciphers {
			if !routerOpenVPNCipher(c) {
				return errors.New("unsupported or insecure negotiated cipher")
			}
		}
		p.endpoint["data_ciphers"] = ciphers
		return nil
	case "auth":
		if err := arity(1, 1); err != nil {
			return err
		}
		v := strings.ToUpper(a[0])
		if !routerOpenVPNOneOf(v, "SHA1", "SHA256", "SHA384", "SHA512") {
			return errors.New("unsupported packet authentication digest")
		}
		p.endpoint["auth"] = v
		return nil
	case "tun-mtu":
		return number("mtu", 1280, 9000)
	case "mssfix":
		if err := arity(1, 2); err != nil {
			return err
		}
		v, e := routerOpenVPNNumber(a[0], 0, 9000)
		if e != nil {
			return e
		}
		if v == 0 {
			p.endpoint["mss_fix_disabled"] = true
		} else {
			p.endpoint["mss_fix"] = v
		}
		if len(a) == 2 {
			if !routerOpenVPNOneOf(a[1], "mtu", "fixed") {
				return errors.New("unsupported MSS mode")
			}
			p.endpoint["mss_fix_mode"] = a[1]
		}
		return nil
	case "fragment":
		return number("fragment", 576, 9000)
	case "ping":
		if p.seen["keepalive"] {
			return errors.New("ping conflicts with keepalive")
		}
		return duration("ping_interval")
	case "ping-restart":
		if p.seen["keepalive"] {
			return errors.New("ping-restart conflicts with keepalive")
		}
		return duration("ping_restart")
	case "reneg-sec":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] == "0" {
			p.endpoint["renegotiate_disabled"] = true
			return nil
		}
		return duration("renegotiate_interval")
	case "hand-window":
		return duration("handshake_window")
	case "tls-timeout":
		return duration("tls_timeout")
	case "keepalive":
		if err := arity(2, 2); err != nil {
			return err
		}
		if p.seen["ping"] || p.seen["ping-restart"] {
			return errors.New("keepalive conflicts with ping settings")
		}
		for i, f := range []string{"ping_interval", "ping_restart"} {
			v, e := routerOpenVPNNumber(a[i], 1, 604800)
			if e != nil {
				return e
			}
			p.endpoint[f] = strconv.Itoa(v) + "s"
		}
		return nil
	case "explicit-exit-notify":
		if err := arity(0, 1); err != nil {
			return err
		}
		v := 1
		var e error
		if len(a) == 1 {
			v, e = routerOpenVPNNumber(a[0], 0, 5)
		}
		p.endpoint["explicit_exit_notify"] = v
		return e
	case "allow-compression":
		if err := arity(1, 1); err != nil {
			return err
		}
		if a[0] != "no" {
			return errors.New("compression is disabled to protect encrypted traffic")
		}
		p.endpoint["allow_compression"] = "no"
		return nil
	case "compress", "comp-lzo":
		if err := arity(1, 1); err != nil {
			return err
		}
		if !routerOpenVPNOneOf(a[0], "no", "stub", "stub-v2", "disabled", "off") {
			return errors.New("active compression is not allowed")
		}
		field := "compression"
		if name == "comp-lzo" {
			if a[0] == "stub" || a[0] == "stub-v2" {
				return errors.New("invalid LZO stub mode")
			}
			field = "compression_lzo"
		}
		p.endpoint[field] = a[0]
		return nil
	case "pull-filter":
		if err := arity(2, 2); err != nil {
			return err
		}
		if !routerOpenVPNOneOf(a[0], "ignore", "reject") {
			return errors.New("only explicit ignore/reject pull filters are supported")
		}
		if len(a[1]) == 0 || len(a[1]) > 512 {
			return errors.New("invalid pull filter")
		}
		filters, _ := p.endpoint["pull_filters"].([]map[string]string)
		if len(filters) >= 32 {
			return errors.New("too many pull filters")
		}
		p.endpoint["pull_filters"] = append(filters, map[string]string{"action": a[0], "text": a[1]})
		return nil
	case "route-nopull":
		if err := arity(0, 0); err != nil {
			return err
		}
		p.endpoint["route_no_pull"] = true
		return nil
	case "redirect-gateway":
		// OpenVPN's internal endpoint routes do not modify the app's OS TUN.
		for _, v := range a {
			if !routerOpenVPNOneOf(v, "def1", "ipv6", "!ipv4", "local", "autolocal", "bypass-dhcp", "bypass-dns") {
				return errors.New("unknown redirect flag")
			}
		}
		p.endpoint["redirect_gateway"] = true
		if len(a) > 0 {
			p.endpoint["redirect_gateway_flags"] = a
		}
		return nil
	default:
		return errors.New("directive is not supported by the owned native client; scripts, plugins, management, local file and route/DNS overrides are never executed")
	}
}
func (p *routerOpenVPNParser) setDirection(v string) error {
	if !routerOpenVPNOneOf(v, "0", "1") {
		return errors.New("key direction must be 0 or 1")
	}
	d := "client"
	if v == "0" {
		d = "server"
	}
	if p.direction != "" && p.direction != d {
		return errors.New("conflicting key directions")
	}
	p.direction = d
	return nil
}
func routerOpenVPNCipher(v string) bool {
	return routerOpenVPNOneOf(strings.ToUpper(v), "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC")
}

// OpenVPN-style space separated options with quoted/escaped arguments. Comments
// start only at a token boundary; malformed quoted input never becomes another
// directive or silently loses an argument.
func routerOpenVPNWords(line string) ([]string, error) {
	var words []string
	var b strings.Builder
	var quote rune
	escaped, token := false, false
	for _, c := range line {
		if escaped {
			b.WriteRune(c)
			escaped = false
			token = true
			continue
		}
		if c == '\\' {
			escaped = true
			token = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
			token = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			token = true
			continue
		}
		if (c == '#' || c == ';') && !token {
			break
		}
		if c == ' ' || c == '\t' {
			if token {
				words = append(words, b.String())
				b.Reset()
				token = false
			}
			continue
		}
		if c < 0x20 || c == 0x7f {
			return nil, errors.New("invalid control character")
		}
		b.WriteRune(c)
		token = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("unfinished quoted option")
	}
	if token {
		words = append(words, b.String())
	}
	return words, nil
}
