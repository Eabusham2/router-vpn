package nativeopenvpn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Profile always contains the original bounded inline source. A private relay
// retains its own provider credentials, not the Local client's certificate or
// password. Compiling it never reads files or opens an OS tunnel.
type Profile struct {
	Config   string `json:"config"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ProviderIdentity is carried only inside private pairing bundles/registries.
// It must never be returned by the public node API or capability catalog.
// Public-key identity catches reissued certificates using the same key; CN and
// username also catch providers that key their single-session limit on names.
type ProviderIdentity struct {
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	CommonName      string `json:"common_name,omitempty"`
	Username        string `json:"username,omitempty"`
}

type PublicDescriptor struct {
	PairingPublicKey string           `json:"pairing_public_key"`
	Transport        map[string]any   `json:"transport"`
	ProviderIdentity ProviderIdentity `json:"provider_identity"`
}

// Pairing is the client's private import. The server contributes only a public
// descriptor. Each role owns its own dedicated X25519 authentication secret;
// neither role derives a reusable credential from a published password hash.
type Pairing struct {
	PrivateKey string           `json:"private_key"`
	Server     PublicDescriptor `json:"server"`
}

var errPairing = errors.New("OpenVPN pairing requires independent private provider and authentication identities with matching verified transport policy")

func (p *Profile) UnmarshalJSON(raw []byte) error {
	// JSON can expand one valid source byte to six bytes (for example '<' in
	// a comment). Keep the original 256 KiB source limit in CompileEndpoint;
	// do not reject an otherwise unchanged Local profile during private import.
	object, err := pairingObject(raw, 8*MaxProfileBytes)
	if err != nil || len(object) < 1 || len(object) > 3 {
		return errPairing
	}
	for key, value := range object {
		if key != "config" && key != "username" && key != "password" {
			return errPairing
		}
		if _, ok := value.(string); !ok {
			return errPairing
		}
	}
	config, ok := object["config"].(string)
	if !ok {
		return errPairing
	}
	username, _ := object["username"].(string)
	password, _ := object["password"].(string)
	*p = Profile{Config: config, Username: username, Password: password}
	return nil
}

func (p *ProviderIdentity) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 8192)
	if err != nil || len(object) < 1 || len(object) > 3 {
		return errPairing
	}
	for key, value := range object {
		if key != "public_key_sha256" && key != "common_name" && key != "username" {
			return errPairing
		}
		if _, ok := value.(string); !ok {
			return errPairing
		}
	}
	type plain ProviderIdentity
	var result plain
	if json.Unmarshal(raw, &result) != nil || validateProviderIdentity(ProviderIdentity(result)) != nil {
		return errPairing
	}
	*p = ProviderIdentity(result)
	return nil
}

func (p *PublicDescriptor) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 2*MaxProfileBytes)
	if err != nil || len(object) != 3 {
		return errPairing
	}
	if _, ok := object["pairing_public_key"].(string); !ok {
		return errPairing
	}
	if _, ok := object["transport"].(map[string]any); !ok {
		return errPairing
	}
	if _, ok := object["provider_identity"].(map[string]any); !ok {
		return errPairing
	}
	type plain PublicDescriptor
	var result plain
	if json.Unmarshal(raw, &result) != nil || !CanonicalPairingPublic(result.PairingPublicKey) {
		return errPairing
	}
	*p = PublicDescriptor(result)
	return nil
}

func (p *Pairing) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 2*MaxProfileBytes)
	if err != nil || len(object) != 2 {
		return errPairing
	}
	if _, ok := object["private_key"].(string); !ok {
		return errPairing
	}
	if _, ok := object["server"].(map[string]any); !ok {
		return errPairing
	}
	type plain Pairing
	var result plain
	if json.Unmarshal(raw, &result) != nil {
		return errPairing
	}
	if _, err := pairingPrivate(result.PrivateKey); err != nil {
		return errPairing
	}
	*p = Pairing(result)
	return nil
}

// Reject duplicate members at every depth before a typed decoder can silently
// discard unknown private material. Bounds include strings and nested arrays.
func pairingObject(raw []byte, limit int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return nil, errPairing
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var decode func(int) (any, error)
	decode = func(depth int) (any, error) {
		if depth > 24 {
			return nil, errPairing
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, errPairing
		}
		delim, structured := token.(json.Delim)
		if !structured {
			return token, nil
		}
		switch delim {
		case '{':
			value := map[string]any{}
			for decoder.More() {
				key, err := decoder.Token()
				text, ok := key.(string)
				if err != nil || !ok || len(value) > 4096 {
					return nil, errPairing
				}
				if _, exists := value[text]; exists {
					return nil, errPairing
				}
				entry, err := decode(depth + 1)
				if err != nil {
					return nil, err
				}
				value[text] = entry
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
				return nil, errPairing
			}
			return value, nil
		case '[':
			value := []any{}
			for decoder.More() {
				if len(value) > 4096 {
					return nil, errPairing
				}
				entry, err := decode(depth + 1)
				if err != nil {
					return nil, err
				}
				value = append(value, entry)
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
				return nil, errPairing
			}
			return value, nil
		default:
			return nil, errPairing
		}
	}
	value, err := decode(0)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errPairing
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errPairing
	}
	return object, nil
}

func CompileProfile(p Profile, tag, detour string) (map[string]any, error) {
	encoded, err := CompileEndpoint(p.Config, p.Username, p.Password, tag, detour)
	if err != nil {
		return nil, errPairing
	}
	object, err := pairingObject([]byte(encoded), 2*MaxProfileBytes)
	if err != nil {
		return nil, errPairing
	}
	return object, nil
}

func pairingPrivate(value string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errPairing
	}
	defer clear(raw)
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, errPairing
	}
	return private, nil
}

func CanonicalPairingPublic(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value || raw[31]&128 != 0 {
		return false
	}
	for i := 31; i > 0; i-- {
		limit := byte(255)
		if i == 31 {
			limit = 127
		}
		if raw[i] < limit {
			return true
		}
	}
	return raw[0] < 237
}

func PairingAgreement(privateValue, otherValue string) ([]byte, error) {
	private, err := pairingPrivate(privateValue)
	if err != nil || !CanonicalPairingPublic(otherValue) {
		return nil, errPairing
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(otherValue)
	if err != nil || bytes.Equal(private.PublicKey().Bytes(), raw) {
		return nil, errPairing
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, errPairing
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, errPairing
	}
	return shared, nil
}

func canonicalProviderName(value string, limit int) (string, error) {
	if !utf8.ValidString(value) || len(value) > limit {
		return "", errPairing
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", errPairing
		}
	}
	return strings.ToLower(strings.TrimSpace(value)), nil
}

func validateProviderIdentity(identity ProviderIdentity) error {
	name, err := canonicalProviderName(identity.CommonName, 1024)
	if err != nil || name != identity.CommonName {
		return errPairing
	}
	username, err := canonicalProviderName(identity.Username, 4096)
	if err != nil || username != identity.Username {
		return errPairing
	}
	if (identity.PublicKeySHA256 == "") != (identity.CommonName == "") {
		return errPairing
	}
	if identity.PublicKeySHA256 != "" {
		raw, err := hex.DecodeString(identity.PublicKeySHA256)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != identity.PublicKeySHA256 {
			return errPairing
		}
	}
	if identity.PublicKeySHA256 == "" && identity.Username == "" {
		return errPairing
	}
	return nil
}

func inlineStrings(value any) (string, error) {
	values, ok := value.([]any)
	if !ok || len(values) != 1 {
		return "", errPairing
	}
	text, ok := values[0].(string)
	if !ok || text == "" {
		return "", errPairing
	}
	return text, nil
}

func publicCertificateBundle(value any) ([]any, error) {
	text, err := inlineStrings(value)
	if err != nil {
		return nil, err
	}
	remaining := []byte(text)
	var canonical bytes.Buffer
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errPairing
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errPairing
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errPairing
		}
		if err := pem.Encode(&canonical, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return nil, errPairing
		}
		remaining = rest
		count++
		if count > 64 {
			return nil, errPairing
		}
	}
	if count == 0 {
		return nil, errPairing
	}
	return []any{canonical.String()}, nil
}

// DescribePeer exports only the canonical transport policy and provider public
// identity. Even malformed PEM cannot hide a private key in a public CA field.
func DescribePeer(profile Profile, authPrivate string) (PublicDescriptor, error) {
	private, err := pairingPrivate(authPrivate)
	if err != nil {
		return PublicDescriptor{}, err
	}
	endpoint, err := CompileProfile(profile, "exit", "")
	if err != nil {
		return PublicDescriptor{}, err
	}
	if _, err := Remotes(endpoint); err != nil {
		return PublicDescriptor{}, err
	}
	tlsPolicy, ok := endpoint["tls"].(map[string]any)
	if !ok {
		return PublicDescriptor{}, errPairing
	}
	identity := ProviderIdentity{}
	identity.Username, err = canonicalProviderName(profile.Username, 4096)
	if err != nil {
		return PublicDescriptor{}, err
	}
	if raw, exists := tlsPolicy["client_certificate"]; exists {
		certificate, err := inlineStrings(raw)
		if err != nil {
			return PublicDescriptor{}, err
		}
		key, err := inlineStrings(tlsPolicy["client_key"])
		if err != nil {
			return PublicDescriptor{}, err
		}
		pair, err := tls.X509KeyPair([]byte(certificate), []byte(key))
		if err != nil || len(pair.Certificate) == 0 {
			return PublicDescriptor{}, errPairing
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return PublicDescriptor{}, errPairing
		}
		publicDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return PublicDescriptor{}, errPairing
		}
		digest := sha256.Sum256(publicDER)
		identity.PublicKeySHA256 = hex.EncodeToString(digest[:])
		identity.CommonName, err = canonicalProviderName(leaf.Subject.CommonName, 1024)
		if err != nil {
			return PublicDescriptor{}, err
		}
	}
	if validateProviderIdentity(identity) != nil {
		return PublicDescriptor{}, errPairing
	}
	delete(endpoint, "username")
	delete(endpoint, "password")
	delete(endpoint, "tag")
	delete(tlsPolicy, "client_certificate")
	delete(tlsPolicy, "client_key")
	if raw, exists := tlsPolicy["certificate"]; exists {
		tlsPolicy["certificate"], err = publicCertificateBundle(raw)
		if err != nil {
			return PublicDescriptor{}, err
		}
	}
	if raw, exists := tlsPolicy["peer_fingerprint"]; exists {
		value, ok := raw.([]any)
		if !ok || len(value) != 1 {
			return PublicDescriptor{}, errPairing
		}
		text, ok := value[0].(string)
		if !ok {
			return PublicDescriptor{}, errPairing
		}
		canonical := strings.ToLower(strings.ReplaceAll(text, ":", ""))
		decoded, err := hex.DecodeString(canonical)
		if err != nil || len(decoded) != 32 {
			return PublicDescriptor{}, errPairing
		}
		tlsPolicy["peer_fingerprint"] = []any{canonical}
	}
	if wrap, exists := tlsPolicy["control_wrap"].(map[string]any); exists {
		delete(wrap, "key")
	}
	if _, exists := endpoint["mtu"]; !exists {
		endpoint["mtu"] = float64(1500)
	}
	return PublicDescriptor{PairingPublicKey: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), Transport: endpoint, ProviderIdentity: identity}, nil
}

// SameRemoteHost preserves the legacy single-response-endpoint contract and
// the current Start Layer mapping. Multi-host relay captures instead require
// ResponseProbes and an owned connected-remote receipt.
func SameRemoteHost(endpoint map[string]any) (string, error) {
	remotes, err := Remotes(endpoint)
	if err != nil || len(remotes) == 0 {
		return "", errPairing
	}
	for _, remote := range remotes {
		if remote.Host != remotes[0].Host {
			return "", errPairing
		}
	}
	return remotes[0].Host, nil
}

func ValidatePublicPair(local, server PublicDescriptor) error {
	if !CanonicalPairingPublic(local.PairingPublicKey) || !CanonicalPairingPublic(server.PairingPublicKey) || local.PairingPublicKey == server.PairingPublicKey || validateProviderIdentity(local.ProviderIdentity) != nil || validateProviderIdentity(server.ProviderIdentity) != nil {
		return errPairing
	}
	l, s := local.ProviderIdentity, server.ProviderIdentity
	if (l.PublicKeySHA256 == "") != (s.PublicKeySHA256 == "") || (l.Username == "") != (s.Username == "") {
		return errPairing
	}
	if l.PublicKeySHA256 != "" && (l.PublicKeySHA256 == s.PublicKeySHA256 || l.CommonName == s.CommonName) || l.Username != "" && l.Username == s.Username {
		return errPairing
	}
	if !reflect.DeepEqual(local.Transport, server.Transport) {
		return errPairing
	}
	return nil
}

func ValidatePairing(profile Profile, pairing Pairing) (PublicDescriptor, error) {
	local, err := DescribePeer(profile, pairing.PrivateKey)
	if err != nil {
		return PublicDescriptor{}, err
	}
	if err := ValidatePublicPair(local, pairing.Server); err != nil {
		return PublicDescriptor{}, err
	}
	shared, err := PairingAgreement(pairing.PrivateKey, pairing.Server.PairingPublicKey)
	if err != nil {
		return PublicDescriptor{}, err
	}
	clear(shared)
	return local, nil
}

// ValidatePairingJSON is a string-only native editor boundary. Parse the exact
// input before a Java/Swift object decoder can discard duplicate or unknown
// private fields. It returns no descriptor, provider name, credential or graph.
func ValidatePairingJSON(profileJSON, pairingJSON string) error {
	var profile Profile
	var pairing Pairing
	if json.Unmarshal([]byte(profileJSON), &profile) != nil || json.Unmarshal([]byte(pairingJSON), &pairing) != nil {
		return errPairing
	}
	_, err := ValidatePairing(profile, pairing)
	return err
}

// ValidatePrivateNodeJSON checks the complete raw import before a native host's
// typed decoder can discard duplicate members. It deliberately does not claim
// schema or runtime validity: the existing typed import and policy validators
// must run afterward. The bound matches the native private bundle loader.
func ValidatePrivateNodeJSON(raw string) error {
	if _, err := pairingObject([]byte(raw), 64<<20); err != nil {
		return errors.New("private node import requires one bounded unambiguous UTF-8 JSON object")
	}
	return nil
}

// ProviderSessionsOverlap is intentionally separate from pairing-auth keys.
// Aliasing the same provider certificate/CN/username under another pair must
// not bypass simultaneous-session exclusion in the relay manager.
func ProviderSessionsOverlap(left, right ProviderIdentity) bool {
	return left.PublicKeySHA256 != "" && left.PublicKeySHA256 == right.PublicKeySHA256 || left.CommonName != "" && left.CommonName == right.CommonName || left.Username != "" && left.Username == right.Username
}
