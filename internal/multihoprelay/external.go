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
	"unicode/utf8"

	"router-vpn/internal/applexray"
)

// ExternalExit identifies a third-party transport by its exact public endpoint
// and separately proved egress address. It never claims a Router API identity.
// The first server-execution transport is native Shadowsocks. Other external
// families need their own real last-node response and credential contracts.
type ExternalExit struct {
	ExpectedPublicIP string        `json:"expected_public_ip"`
	ResponseProbe    ResponseProbe `json:"response_probe"`
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
	bad := errors.New("external relay requires its exact native transport and public proof address")
	if exit.External == nil || exit.NodeID != "" || exit.Mode != "shadowsocks" || exit.StartLayer != nil || !externalPublicIP(exit.External.ExpectedPublicIP) {
		return "", bad
	}
	transport, err := validateTransport(exit)
	if err != nil {
		return "", bad
	}
	host, _ := transport["server"].(string)
	password, _ := transport["password"].(string)
	if !externalPublicIP(host) || password == "" || !utf8.ValidString(password) || len(password) > 4096 {
		return "", bad
	}
	if exit.External.ResponseProbe.Validate(host) != nil {
		return "", bad
	}
	// A bounded exact native profile, not a second opaque configuration owner.
	for key := range transport {
		switch key {
		case "type", "tag", "server", "server_port", "method", "password":
		default:
			return "", bad
		}
	}
	encoded, err := json.Marshal([]any{"routervpn-external-relay-v1", exit.Mode, host, transport["server_port"], transport["method"], exit.External.ExpectedPublicIP, exit.External.ResponseProbe})
	if err != nil {
		return "", bad
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// AuthenticateExternalRequest binds proof of the captured Shadowsocks password
// to this one random session, paired entry, exit and listener proposal. The
// password stays in the private registry and captured client profile. A digest
// of it is never published as a reusable capability or accepted as a Router ID.
func AuthenticateExternalRequest(exit Exit, request Request) (Request, error) {
	fingerprint, err := ExternalFingerprint(exit)
	if err != nil {
		return Request{}, err
	}
	if request.ExitID != exit.ID || request.ExitMode != exit.Mode || request.ExitStartLayer != "" ||
		!nonce.MatchString(request.SessionID) || !proofID.MatchString(request.EntryNodeID) ||
		request.Port < 1024 || request.Port > 65535 || !listenerSecret.MatchString(request.Username) || !listenerSecret.MatchString(request.Password) || request.Username == request.Password {
		return Request{}, ErrOwnership
	}
	request.ExternalFingerprint, request.ExternalAuthentication = fingerprint, ""
	encoded, err := json.Marshal(request)
	if err != nil {
		return Request{}, ErrOwnership
	}
	mac := hmac.New(sha256.New, []byte(exit.Transport["password"].(string)))
	_, _ = mac.Write([]byte("routervpn-external-relay-auth-v1\x00"))
	_, _ = mac.Write(encoded)
	request.ExternalAuthentication = hex.EncodeToString(mac.Sum(nil))
	return request, nil
}

func ValidateExternalRequest(exit Exit, request Request) error {
	if exit.External == nil {
		if request.ExternalFingerprint != "" || request.ExternalAuthentication != "" {
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
