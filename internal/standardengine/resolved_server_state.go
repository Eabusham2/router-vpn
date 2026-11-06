package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// The v257 monitor exports at most64 servers per captured scope plus fallback.
// This bound covers258 inventories of64 rows at2KiB each without truncation.
const MaxResolvedServerDump = 258 * 64 * 2048
const MaxResolvedServerState = 8192

type ResolvedServerRow struct {
	Server                 string `json:"Server"`
	Type                   string `json:"Type"`
	Interface              string `json:"Interface,omitempty"`
	InterfaceIndex         uint32 `json:"InterfaceIndex,omitempty"`
	VerifiedFeatureLevel   string `json:"VerifiedFeatureLevel"`
	PossibleFeatureLevel   string `json:"PossibleFeatureLevel"`
	DNSSECMode             string `json:"DNSSECMode"`
	DNSSECSupported        bool   `json:"DNSSECSupported"`
	ReceivedUDPFragmentMax uint32 `json:"ReceivedUDPFragmentMax"`
	FailedUDPAttempts      uint32 `json:"FailedUDPAttempts"`
	FailedTCPAttempts      uint32 `json:"FailedTCPAttempts"`
	PacketTruncated        bool   `json:"PacketTruncated"`
	PacketBadOpt           bool   `json:"PacketBadOpt"`
	PacketRRSIGMissing     bool   `json:"PacketRRSIGMissing"`
	PacketInvalid          bool   `json:"PacketInvalid"`
	PacketDoOff            bool   `json:"PacketDoOff"`
}
type ResolvedServerState struct {
	PolicySHA256 string            `json:"policy_sha256"`
	Name         string            `json:"name"`
	Index        int32             `json:"index"`
	Selected     ResolvedDNS       `json:"selected"`
	Row          ResolvedServerRow `json:"row"`
}

func resolvedServerText(server ResolvedDNS) (string, error) {
	if !resolvedDNSValid([]ResolvedDNS{server}) {
		return "", errors.New("server state omitted exact native DNS tuple")
	}
	address, _ := netip.ParseAddr(server.Address)
	text := address.String()
	if server.Port != 0 {
		if address.Is6() {
			text = "[" + text + "]"
		}
		text += ":" + strconv.Itoa(int(server.Port))
	}
	if address.Is6() && address.IsLinkLocalUnicast() && server.Index > 0 {
		text += "%" + strconv.Itoa(int(server.Index))
	}
	if server.ServerName != "" {
		text += "#" + server.ServerName
	}
	return text, nil
}
func (r ResolvedServerRow) valid() bool {
	if !resolvedChoice(r.Type, "system", "fallback", "link") || len(r.Server) > 512 || len(r.Interface) > 64 || !resolvedChoice(r.DNSSECMode, "no", "yes", "allow-downgrade") {
		return false
	}
	if r.Type == "link" {
		if r.InterfaceIndex == 0 || r.Interface == "" {
			return false
		}
	} else if r.InterfaceIndex != 0 || r.Interface != "" {
		return false
	}
	for _, level := range []string{r.VerifiedFeatureLevel, r.PossibleFeatureLevel} {
		if !resolvedChoice(level, "n/a", "TCP", "UDP", "UDP+EDNS0", "TLS+EDNS0", "UDP+EDNS0+DO", "TLS+EDNS0+DO") {
			return false
		}
	}
	// systemd v257 dns_server_dnssec_supported(): strict mode remains true;
	// otherwise these four exported facts completely determine current support.
	supported := r.DNSSECMode == "yes" || (!r.PacketBadOpt && !r.PacketRRSIGMissing && !r.PacketDoOff && r.FailedTCPAttempts < 3)
	return supported == r.DNSSECSupported
}
func (s ResolvedServerState) Canonical() ([]byte, error) {
	if !resolvedDigest(s.PolicySHA256, 32) || !ResolvedName(s.Name, false) || s.Index < 0 || !resolvedDNSValid([]ResolvedDNS{s.Selected}) || !s.Row.valid() {
		return nil, errors.New("invalid original server compatibility observation")
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxResolvedServerState {
		return nil, errors.New("unbounded original server observation")
	}
	return raw, nil
}
func (s ResolvedServerState) Matches(policy ResolvedPolicy, name string, index int32) bool {
	raw, err := policy.Canonical()
	if err != nil || s.PolicySHA256 != ResolvedPolicySHA256(raw) || s.Name != name || s.Index != index {
		return false
	}
	if _, err = s.Canonical(); err != nil {
		return false
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return false
	}
	for _, route := range routes {
		if route.Index != index {
			continue
		}
		if route.CurrentDNS == nil || *route.CurrentDNS != s.Selected || route.DNSSEC != s.Row.DNSSECMode {
			return false
		}
		expected, _ := resolvedServerText(s.Selected)
		if expected != s.Row.Server {
			return false
		}
		kind := "system"
		if index > 0 {
			kind = "link"
		} else if route.Fallback {
			kind = "fallback"
		}
		if s.Row.Type != kind {
			return false
		}
		if kind == "link" {
			return s.Row.InterfaceIndex == uint32(index) && s.Selected.Index == index
		}
		// Monitor omits explicit global ifindices for non-link-local addresses.
		// Such an ambiguous row cannot prove the originally captured routing tuple.
		address, _ := netip.ParseAddr(s.Selected.Address)
		return s.Selected.Index == 0 || (address.Is6() && address.IsLinkLocalUnicast())
	}
	return false
}

// AllowsCurrentIncompatibility proves only the original daemon's current
// decision. It never predicts private grace-period expiry or labels a generic
// validator failure an incompatibility result.
func (s ResolvedServerState) AllowsCurrentIncompatibility() bool {
	return s.Row.valid() && s.Row.DNSSECMode == "allow-downgrade" && !s.Row.DNSSECSupported
}
func DecodeResolvedServerState(raw []byte, policy ResolvedPolicy, name string, index int32) (ResolvedServerState, error) {
	var s ResolvedServerState
	if len(raw) > MaxResolvedServerState || json.Unmarshal(raw, &s) != nil {
		return s, errors.New("invalid original server-state frame")
	}
	canonical, err := s.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || !s.Matches(policy, name, index) {
		return ResolvedServerState{}, errors.New("server state changed original policy/selected tuple")
	}
	return s, nil
}
func SelectResolvedServerState(raw []byte, policy ResolvedPolicy, name string, index int32) (ResolvedServerState, error) {
	var zero ResolvedServerState
	if len(raw) == 0 || len(raw) > MaxResolvedServerDump {
		return zero, errors.New("server monitor response exceeded complete bounded inventory")
	}
	if err := resolvedServerJSONUnique(raw); err != nil {
		return zero, err
	}
	var envelope struct {
		Parameters struct {
			Dump []json.RawMessage `json:"dump"`
		} `json:"parameters"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return zero, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return zero, errors.New("multiple monitor responses cannot identify one original observation")
	}
	if len(envelope.Parameters.Dump) > 258*64 {
		return zero, errors.New("server monitor omitted complete bounded scope inventory")
	}
	policyRaw, err := policy.Canonical()
	if err != nil {
		return zero, err
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return zero, err
	}
	var selected *ResolvedDNS
	for _, route := range routes {
		if route.Index == index {
			selected = route.CurrentDNS
		}
	}
	if selected == nil {
		return zero, errors.New("monitor observation has no original current DNS server")
	}
	var found *ResolvedServerState
	for _, body := range envelope.Parameters.Dump {
		if len(body) > 2048 {
			return zero, errors.New("server monitor row exceeded original bound")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			return zero, errors.New("invalid monitor row")
		}
		// encoding/json accepts null into scalar Go fields as their zero value.
		// The native monitor emits concrete scalars: null must never fabricate a
		// false support flag, zero failure count or absent interface identity.
		for _, value := range fields {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return zero, errors.New("server monitor returned a null original field")
			}
		}
		for _, key := range []string{"Server", "Type", "VerifiedFeatureLevel", "PossibleFeatureLevel", "DNSSECMode", "DNSSECSupported", "ReceivedUDPFragmentMax", "FailedUDPAttempts", "FailedTCPAttempts", "PacketTruncated", "PacketBadOpt", "PacketRRSIGMissing", "PacketInvalid", "PacketDoOff"} {
			if _, ok := fields[key]; !ok {
				return zero, errors.New("server monitor omitted exact original field")
			}
		}
		expectedFields := 14
		var kind string
		_ = json.Unmarshal(fields["Type"], &kind)
		if kind == "link" {
			expectedFields = 16
		}
		if len(fields) != expectedFields {
			return zero, errors.New("monitor row omitted complete original fields")
		}
		var row ResolvedServerRow
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&row); err != nil || !row.valid() {
			return zero, errors.New("server monitor returned unknown or inconsistent original state")
		}
		candidate := ResolvedServerState{ResolvedPolicySHA256(policyRaw), name, index, *selected, row}
		if !candidate.Matches(policy, name, index) {
			continue
		}
		if found != nil {
			return zero, errors.New("server monitor repeated original selected tuple")
		}
		found = &candidate
	}
	if found == nil {
		return zero, errors.New("server monitor omitted exact original selected tuple")
	}
	return *found, nil
}

func resolvedServerJSONUnique(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("monitor JSON exceeded fixed nesting")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return errors.New("monitor JSON repeated an original field")
				}
				keys[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected monitor JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("monitor JSON has extra response data")
	}
	return nil
}
