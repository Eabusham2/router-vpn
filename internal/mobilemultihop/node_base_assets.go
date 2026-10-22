package mobilemultihop

import (
	"errors"
	"net"
	"net/netip"
	"strings"

	"router-vpn/internal/applexray"
)

// SameNativeNodeHost compares captured outer hosts without resolving either
// name. Literal spellings may normalize to the same address, while a hostname
// can match only that same DNS name, never a previous resolution of it.
func SameNativeNodeHost(a, b string) bool {
	ipA, errA := netip.ParseAddr(a)
	ipB, errB := netip.ParseAddr(b)
	if errA == nil || errB == nil {
		return errA == nil && errB == nil && ipA.Zone() == "" && ipB.Zone() == "" && !ipA.Is4In6() && !ipB.Is4In6() && ipA == ipB
	}
	return applexray.ValidNodeHostname(a) && applexray.ValidNodeHostname(b) &&
		strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// NativeBaseSourceForEndpoint also binds the captured base transport to the
// saved node's outer host. An authentic peer key alone cannot authorize an old
// endpoint or a stale DNS answer. The source owns its port; it is never replaced
// with a default. Call this before any bootstrap and again after freezing.
func NativeBaseSourceForEndpoint(mode string, assets map[string][]byte, endpoint string) ([]byte, error) {
	full, err := NativeBaseSource(mode, assets)
	if err != nil {
		return nil, err
	}
	bad := errors.New("native base endpoint does not match the captured node host")
	section, captured := "", ""
	for _, line := range strings.Split(string(full), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			continue
		}
		if section != "[peer]" || captured != "" {
			return nil, bad
		}
		captured = strings.TrimSpace(value)
	}
	host, port, err := net.SplitHostPort(captured)
	if err != nil || !SameNativeNodeHost(host, endpoint) {
		return nil, bad
	}
	if _, err := wireGuardNumber(port, 1, 65535); err != nil {
		return nil, bad
	}
	return full, nil
}

// NativeBaseSource selects the full-device source from a generated base pair.
// Server bundles also carry a split-route *-socks.conf for kernel multihop. It
// is not another native peer: require its complete transport identity to match
// the full source before ignoring its DNS/AllowedIPs routing differences.
// Callers retain the original asset map in their source capture/digest.
func NativeBaseSource(mode string, assets map[string][]byte) ([]byte, error) {
	name, compatibility := "wg.conf", "wg-socks.conf"
	if mode == "awg2-fast" || mode == "awg2-strong" {
		name, compatibility = "awg.conf", "awg-socks.conf"
	} else if mode != "wg" {
		return nil, errors.New("native base source requires an exact WG or AWG mode")
	}
	bad := errors.New("native base requires its exact full source and matching optional split-route source")
	full := assets[name]
	if len(full) == 0 || len(assets) < 1 || len(assets) > 2 {
		return nil, bad
	}
	if len(assets) == 1 {
		return full, nil
	}
	compat := assets[compatibility]
	if len(compat) == 0 {
		return nil, bad
	}
	identity := func(body []byte) (map[string]string, error) {
		values := map[string]string{}
		sections := map[string]bool{}
		section := ""
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "[") {
				section = strings.ToLower(line)
				if (section != "[interface]" && section != "[peer]") || sections[section] {
					return nil, bad
				}
				sections[section] = true
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			key, value = section+strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			if !ok || section == "" || value == "" {
				return nil, bad
			}
			if _, duplicate := values[key]; duplicate {
				return nil, bad
			}
			values[key] = value
		}
		if len(sections) != 2 || values["[peer]allowedips"] == "" {
			return nil, bad
		}
		delete(values, "[interface]dns")
		delete(values, "[peer]allowedips")
		return values, nil
	}
	a, err := identity(full)
	if err != nil {
		return nil, err
	}
	b, err := identity(compat)
	if err != nil || len(a) != len(b) {
		return nil, bad
	}
	for key, value := range a {
		if b[key] != value {
			return nil, bad
		}
	}
	return full, nil
}
