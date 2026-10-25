package multihoprelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativeopenvpn"
)

// ExternalExit identifies a third-party transport by its exact public endpoint
// and separately proved egress address. It never claims a Router API identity.
// Credential-bearing proxy families share this exact last-node response and
// session authentication contract. Packet peers need independent server keys
// before they can participate in Local/Server comparison.
type ExternalExit struct {
	ExpectedPublicIP      string                       `json:"expected_public_ip"`
	ResponseProbe         ResponseProbe                `json:"response_probe"`
	Packet                *ExternalPacketPair          `json:"packet,omitempty"`
	OpenVPN               *ExternalOpenVPNPair         `json:"openvpn,omitempty"`
	OpenVPNResponseProbes nativeopenvpn.ResponseProbes `json:"openvpn_response_probes,omitempty"`
}

type ResponseProbe struct {
	URL        string `json:"url"`
	ServerName string `json:"server_name,omitempty"`
}

// Validate requires a response from this actual external server, not another
// internet echo or a Router administration API. TLS name validation is retained
// while the route dials only the captured literal address, without system DNS.
func (p ResponseProbe) Validate(host string) error {
	bad := errors.New("external response probe requires verified HTTPS on the captured external server")
	u, err := url.Parse(p.URL)
	if err != nil || len(p.URL) > 2048 || strings.TrimSpace(p.URL) != p.URL || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Opaque != "" || u.Hostname() != host || !externalPublicIP(host) || strings.HasSuffix(u.Host, ":") {
		return bad
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return bad
		}
	}
	if p.ServerName != "" && (!applexray.ValidNodeHostname(p.ServerName) || strings.HasSuffix(p.ServerName, ".")) {
		return bad
	}
	return nil
}

func externalPublicIP(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// ExternalFingerprint includes only public transport/proof parameters. Private
// passwords are neither hashed into the public catalog nor returned from it.
func ExternalFingerprint(exit Exit) (string, error) {
	transport, err := externalTransport(exit)
	if err != nil {
		return "", err
	}
	var value any
	if exit.Mode == "openvpn" {
		value = []any{"routervpn-external-openvpn-v4", exit.Mode, exit.External.OpenVPN.Local, exit.External.OpenVPN.Server, externalPublicLayer(exit.StartLayer), exit.External.ExpectedPublicIP, exit.External.ResponseProbe}
		if exit.External.OpenVPNResponseProbes != nil {
			value = []any{"routervpn-external-openvpn-v5", exit.Mode, exit.External.OpenVPN.Local, exit.External.OpenVPN.Server, exit.External.ExpectedPublicIP, exit.External.OpenVPNResponseProbes}
		}
	} else if ExternalPacketMode(exit.Mode) {
		value = []any{"routervpn-external-packet-v3", exit.Mode, exit.External.Packet.Local, exit.External.Packet.Server, externalPublicLayer(exit.StartLayer), exit.External.ExpectedPublicIP, exit.External.ResponseProbe}
	} else if exit.Mode == "shadowsocks" && exit.StartLayer == nil {
		// Preserve the published v1 identity for already-paired Shadowsocks nodes.
		value = []any{"routervpn-external-relay-v1", exit.Mode, transport["server"], transport["server_port"], transport["method"], exit.External.ExpectedPublicIP, exit.External.ResponseProbe}
	} else {
		public, _ := copyMap(transport)
		delete(public, "password")
		delete(public, "username")
		delete(public, "tag")
		var layer any
		if exit.StartLayer != nil {
			outer, _ := copyMap(exit.StartLayer.Transport)
			delete(outer, "password")
			delete(outer, "tag")
			layer = []any{exit.StartLayer.Mode, exit.StartLayer.API, outer}
		}
		value = []any{"routervpn-external-relay-v2", exit.Mode, public, layer, exit.External.ExpectedPublicIP, exit.External.ResponseProbe}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("external public transport identity could not be encoded")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// AuthenticateExternalRequest binds proof of the captured private credentials
// to this one random session, paired entry, exit and listener proposal. The
// password stays in the private registry and captured client profile. A digest
// of it is never published as a reusable capability or accepted as a Router ID.
func AuthenticateExternalRequest(exit Exit, request Request) (Request, error) {
	if err := validatePacketRequestShape(request, true); err != nil {
		return Request{}, err
	}
	fingerprint, err := ExternalFingerprint(exit)
	if err != nil {
		return Request{}, err
	}
	if request.ExitID != exit.ID || request.ExitMode != exit.Mode || request.ExitStartLayer != LayerMode(exit.StartLayer) ||
		!nonce.MatchString(request.SessionID) || !proofID.MatchString(request.EntryNodeID) ||
		request.Port < 1024 || request.Port > 65535 || !listenerSecret.MatchString(request.Username) || !listenerSecret.MatchString(request.Password) || request.Username == request.Password {
		return Request{}, ErrOwnership
	}
	request.ExternalFingerprint, request.ExternalAuthentication = fingerprint, ""
	encoded, err := json.Marshal(request)
	if err != nil {
		return Request{}, ErrOwnership
	}
	var key []byte
	domain := "routervpn-external-relay-auth-v1\x00"
	if exit.Mode == "openvpn" {
		key, err = externalOpenVPNAuthKey(exit, fingerprint)
		if err != nil {
			return Request{}, err
		}
		defer clear(key)
		domain = "routervpn-external-openvpn-auth-" + externalOpenVPNVersion(exit) + "\x00"
	} else if ExternalPacketMode(exit.Mode) {
		key, err = externalPacketAuthKey(exit, fingerprint)
		if err != nil {
			return Request{}, err
		}
		defer clear(key)
		domain = "routervpn-external-packet-auth-v3\x00"
	} else {
		key = []byte(exit.Transport["password"].(string))
	}
	if !ExternalIndependentMode(exit.Mode) && (exit.Mode != "shadowsocks" || exit.StartLayer != nil) {
		var outerSecret any
		if exit.StartLayer != nil {
			outerSecret = exit.StartLayer.Transport["password"]
		}
		key, err = json.Marshal([]any{exit.Mode, exit.Transport["username"], exit.Transport["password"], outerSecret})
		if err != nil {
			return Request{}, err
		}
		domain = "routervpn-external-relay-auth-v2\x00"
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(encoded)
	request.ExternalAuthentication = hex.EncodeToString(mac.Sum(nil))
	return request, nil
}

func externalPublicLayer(layer *StartLayer) any {
	if layer == nil {
		return nil
	}
	outer, _ := copyMap(layer.Transport)
	delete(outer, "password")
	delete(outer, "tag")
	return []any{layer.Mode, layer.API, outer}
}

func ValidateExternalRequest(exit Exit, request Request) error {
	if exit.External == nil {
		if request.ExternalFingerprint != "" || request.ExternalAuthentication != "" || validatePacketRequestShape(request, false) != nil {
			return ErrOwnership
		}
		return nil
	}
	expected, err := AuthenticateExternalRequest(exit, request)
	if err != nil || request.ExternalFingerprint != expected.ExternalFingerprint || !hmac.Equal([]byte(request.ExternalAuthentication), []byte(expected.ExternalAuthentication)) {
		return ErrOwnership
	}
	return nil
}
