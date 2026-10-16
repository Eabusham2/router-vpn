package multihoprelay

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// NaiveMode distinguishes the selected HTTP transport without replacing either
// one with an ordinary HTTP CONNECT proxy or dropping its UDP stream protocol.
func NaiveMode(mode string) bool { return mode == "naive-h2" || mode == "naive-h3" }

// ValidateNaiveTransport checks an independent, self-contained authenticated
// outbound. The graph/relay owner adds its sole detour only after this check.
// Inputs are decoded JSON values; no socket, resolver or certificate file opens.
func ValidateNaiveTransport(value map[string]any, mode string) error {
	bad := errors.New("Naive must retain its exact verified HTTP and UDP transport")
	if !NaiveMode(mode) || value["type"] != "naive" || !literalServer(value["server"]) || !validPort(value["server_port"]) {
		return bad
	}
	for key := range value {
		switch key {
		case "type", "tag", "server", "server_port", "username", "password", "quic", "udp_over_tcp", "tls":
		default:
			return errors.New("Naive contains an unowned dial, helper or transport option")
		}
	}
	if tag, exists := value["tag"]; exists {
		text, ok := tag.(string)
		if !ok || !ident.MatchString(text) {
			return bad
		}
	}
	for _, name := range []string{"username", "password"} {
		text, ok := value[name].(string)
		if !ok || text == "" || len(text) > 4096 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r\n") {
			return bad
		}
		if name == "username" && strings.Contains(text, ":") {
			return bad
		}
	}
	quic, ok := value["quic"].(bool)
	if !ok || quic != (mode == "naive-h3") {
		return errors.New("Naive HTTP version differs from the selected mode")
	}
	uot, ok := value["udp_over_tcp"].(map[string]any)
	if !ok || len(uot) != 2 || uot["enabled"] != true || uot["version"] != float64(2) {
		return errors.New("Naive requires version-2 UDP over streams on both H2 and H3")
	}
	tls, ok := value["tls"].(map[string]any)
	if !ok || tls["enabled"] != true || tls["insecure"] != nil && tls["insecure"] != false {
		return errors.New("Naive requires verified TLS")
	}
	for field := range tls {
		if field != "enabled" && field != "server_name" && field != "certificate" && field != "insecure" {
			return errors.New("Naive TLS policy is not a self-contained supported trust configuration")
		}
	}
	name, ok := tls["server_name"].(string)
	if !ok || !naiveTLSName(name) {
		return bad
	}
	if certificate, exists := tls["certificate"]; exists && !naiveCertificates(certificate) {
		return errors.New("Naive contains invalid inline certificate material")
	}
	return nil
}

func naiveTLSName(name string) bool {
	if name == "" || len(name) > 253 || name != strings.TrimSpace(name) {
		return false
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

func naiveCertificates(value any) bool {
	list, ok := value.([]any)
	if !ok {
		if s, valid := value.(string); valid {
			list = []any{s}
		} else {
			return false
		}
	}
	if len(list) == 0 || len(list) > 16 {
		return false
	}
	total, count := 0, 0
	for _, raw := range list {
		text, ok := raw.(string)
		total += len(text)
		if !ok || text == "" || total > 256<<10 || !utf8.ValidString(text) {
			return false
		}
		remaining := bytes.TrimSpace([]byte(text))
		if len(remaining) == 0 {
			return false
		}
		for len(remaining) > 0 {
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return false
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return false
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return false
			}
			count++
			if count > 16 {
				return false
			}
			remaining = bytes.TrimSpace(rest)
		}
	}
	return count > 0
}
