package multihoprelay

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"

	"router-vpn/internal/applexray"
)

// The descriptions are public native transport parameters. The private key
// belongs only to Exit.Transport for Owner; no opposite private key or PSK is
// copied into this object, a capability catalog or a client profile.
type ExternalPacketPair struct {
	Owner  string         `json:"owner"`
	Local  map[string]any `json:"local"`
	Server map[string]any `json:"server"`
}

func (pair *ExternalPacketPair) UnmarshalJSON(raw []byte) error {
	bad := errors.New("packet pairing requires exact role and two public transport descriptions")
	if len(raw) > 32<<10 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 3 {
		return bad
	}
	owner, ok := object["owner"].(string)
	if !ok || owner != "client" && owner != "server" {
		return bad
	}
	_, ok = object["local"].(map[string]any)
	if !ok {
		return bad
	}
	_, ok = object["server"].(map[string]any)
	if !ok {
		return bad
	}
	type wirePair ExternalPacketPair
	var decoded wirePair
	if json.Unmarshal(raw, &decoded) != nil {
		return bad
	}
	*pair = ExternalPacketPair(decoded)
	return nil
}

func ExternalPacketMode(mode string) bool { return mode == "wireguard" || mode == "amneziawg" }

func externalPacketTransport(protocol string, external map[string]any) (map[string]any, error) {
	bad := errors.New("external packet transport requires its exact inline peer configuration")
	if !ExternalPacketMode(protocol) || external["protocol"] != protocol {
		return nil, bad
	}
	for key := range external {
		switch key {
		case "protocol", "expected_public_ip", "response_probe", "start_layer", "server_peer":
		default:
			if key != protocol {
				return nil, bad
			}
		}
	}
	block, ok := external[protocol].(map[string]any)
	if !ok {
		return nil, bad
	}
	for key := range block {
		switch key {
		case "private_key", "addresses", "peer_public_key", "preshared_key", "endpoint", "allowed_ips", "dns", "mtu", "persistent_keepalive_interval":
		case "parameters":
			if protocol != "amneziawg" {
				return nil, bad
			}
		default:
			return nil, bad
		}
	}
	host, portText, err := net.SplitHostPort(stringValue(block["endpoint"]))
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText || !externalPublicIP(host) {
		return nil, bad
	}
	peer := map[string]any{"address": host, "port": port, "public_key": block["peer_public_key"], "allowed_ips": block["allowed_ips"]}
	if value, exists := block["preshared_key"]; exists && value != "" {
		peer["pre_shared_key"] = value
	}
	if value, exists := block["persistent_keepalive_interval"]; exists {
		peer["persistent_keepalive_interval"] = value
	}
	mtu := any(1280)
	if value, exists := block["mtu"]; exists && value != float64(0) && value != 0 {
		mtu = value
	}
	transport := map[string]any{"type": "wireguard", "tag": "exit", "private_key": block["private_key"], "address": block["addresses"], "mtu": mtu, "peers": []any{peer}}
	if protocol == "amneziawg" {
		transport["type"], transport["amnezia"] = "routervpn-amneziawg", block["parameters"]
	}
	if raw, exists := block["dns"]; exists {
		data, _ := json.Marshal(raw)
		var servers []string
		if json.Unmarshal(data, &servers) != nil || len(servers) > 32 {
			return nil, bad
		}
		for _, value := range servers {
			if address, err := netip.ParseAddr(value); err != nil || address.Zone() != "" || address.Is4In6() {
				return nil, bad
			}
		}
	}
	return validateTransport(Exit{Mode: protocol, Transport: transport, External: &ExternalExit{}})
}

func packetPublicDescription(transport map[string]any, mode string) (map[string]any, error) {
	validated, err := validateTransport(Exit{Mode: mode, Transport: transport, External: &ExternalExit{}})
	if err != nil {
		return nil, err
	}
	identity, err := clientIdentity(validated)
	if err != nil {
		return nil, err
	}
	delete(validated, "private_key")
	delete(validated, "tag")
	validated["client_public_key"] = identity
	peer := validated["peers"].([]any)[0].(map[string]any)
	delete(peer, "pre_shared_key")
	if _, present := peer["persistent_keepalive_interval"]; !present {
		peer["persistent_keepalive_interval"] = float64(0)
	}
	return validated, nil
}

func externalPacketSelection(protocol string, external, local map[string]any) (*ExternalPacketPair, error) {
	bad := errors.New("packet Server/Compare requires its separately provisioned public server peer")
	raw, ok := external["server_peer"].(map[string]any)
	if !ok || len(raw) < 3 || len(raw) > 4 {
		return nil, bad
	}
	for key := range raw {
		switch key {
		case "public_key", "addresses", "mtu", "persistent_keepalive_interval":
		default:
			return nil, bad
		}
	}
	public, ok := raw["public_key"].(string)
	if !ok || !canonicalPacketPublic(public) {
		return nil, bad
	}
	localPublic, err := packetPublicDescription(local, protocol)
	if err != nil {
		return nil, err
	}
	serverPublic, _ := copyMap(localPublic)
	serverPublic["client_public_key"], serverPublic["address"], serverPublic["mtu"] = public, raw["addresses"], raw["mtu"]
	peer := serverPublic["peers"].([]any)[0].(map[string]any)
	peer["persistent_keepalive_interval"] = float64(0)
	if value, exists := raw["persistent_keepalive_interval"]; exists {
		peer["persistent_keepalive_interval"] = value
	}
	serverPublic, err = copyMap(serverPublic)
	if err != nil {
		return nil, err
	}
	pair := &ExternalPacketPair{Owner: "client", Local: localPublic, Server: serverPublic}
	if err := validatePacketDescriptions(pair, protocol); err != nil {
		return nil, err
	}
	shared, err := packetAgreement(local, public)
	if err != nil {
		return nil, err
	}
	clear(shared)
	return pair, nil
}

// ValidateExternalServerPeer also runs during Local-only idle import. Merely
// including an invalid or secret-bearing server descriptor must never defer its
// rejection until a later Server connection.
func ValidateExternalServerPeer(protocol string, external map[string]any) error {
	if _, exists := external["server_peer"]; !exists {
		return nil
	}
	local, err := ExternalTransport(protocol, external)
	if err != nil || !ExternalPacketMode(protocol) {
		return errors.New("server peer belongs only to a captured WG/AWG external node")
	}
	_, err = externalPacketSelection(protocol, external, local)
	return err
}

func canonicalPacketPublic(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value || raw[31]&128 != 0 {
		return false
	}
	// X25519 masks the top bit and reduces field encodings. Reject aliases of
	// the same public u-coordinate before comparing independent peer owners.
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

func packetAgreement(transport map[string]any, other string) ([]byte, error) {
	bad := errors.New("packet agreement requires distinct canonical X25519 peer identities")
	raw, err := base64.StdEncoding.Strict().DecodeString(stringValue(transport["private_key"]))
	if err != nil || len(raw) != 32 || !canonicalPacketPublic(other) {
		return nil, bad
	}
	private, err := ecdh.X25519().NewPrivateKey(raw)
	clear(raw)
	if err != nil || base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) == other {
		return nil, bad
	}
	publicBytes, _ := base64.StdEncoding.Strict().DecodeString(other)
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, bad
	}
	secret, err := private.ECDH(public)
	if err != nil {
		return nil, bad
	}
	return secret, nil
}

func packetPublicAddresses(value any) (map[bool]bool, map[netip.Addr]bool, error) {
	bad := errors.New("packet peers require distinct canonical assigned addresses in matching IP families")
	values, ok := value.([]any)
	if !ok || len(values) < 1 || len(values) > 2 {
		return nil, nil, bad
	}
	families, addresses := map[bool]bool{}, map[netip.Addr]bool{}
	for _, raw := range values {
		text, ok := raw.(string)
		p, err := netip.ParsePrefix(text)
		if !ok || err != nil || p.String() != text || p.Addr().Is4In6() || !p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() || families[p.Addr().Is4()] {
			return nil, nil, bad
		}
		families[p.Addr().Is4()], addresses[p.Addr()] = true, true
	}
	return families, addresses, nil
}

func validatePacketDescriptions(pair *ExternalPacketPair, mode string) error {
	bad := errors.New("packet public pairing descriptions are incomplete, ambiguous or share a client identity")
	if pair == nil || pair.Owner != "client" && pair.Owner != "server" || !ExternalPacketMode(mode) {
		return bad
	}
	local, err := copyMap(pair.Local)
	if err != nil {
		return bad
	}
	server, err := copyMap(pair.Server)
	if err != nil {
		return bad
	}
	publics := []string{}
	var families []map[bool]bool
	var addresses []map[netip.Addr]bool
	for _, value := range []map[string]any{local, server} {
		public := stringValue(value["client_public_key"])
		if !canonicalPacketPublic(public) {
			return bad
		}
		publics = append(publics, public)
		for field := range value {
			switch field {
			case "type", "client_public_key", "address", "mtu", "peers":
			case "amnezia":
				if mode != "amneziawg" {
					return bad
				}
			default:
				return bad
			}
		}
		wantType := "wireguard"
		if mode == "amneziawg" {
			wantType = "routervpn-amneziawg"
		}
		peers, ok := value["peers"].([]any)
		if value["type"] != wantType || !ok || len(peers) != 1 {
			return bad
		}
		peer, ok := peers[0].(map[string]any)
		if !ok || !externalPublicIP(stringValue(peer["address"])) || !validPort(peer["port"]) || !canonicalPacketPublic(stringValue(peer["public_key"])) {
			return bad
		}
		if _, exists := peer["pre_shared_key"]; exists {
			return bad
		}
		if validatePacketPeer(value, peer) != nil {
			return bad
		}
		if mode == "amneziawg" && validateAmnezia(value, peer) != nil {
			return bad
		}
		f, a, err := packetPublicAddresses(value["address"])
		if err != nil {
			return bad
		}
		families, addresses = append(families, f), append(addresses, a)
		delete(value, "client_public_key")
		delete(value, "address")
		delete(value, "mtu")
		delete(peers[0].(map[string]any), "persistent_keepalive_interval")
	}
	if publics[0] == publics[1] || !reflect.DeepEqual(local, server) || !reflect.DeepEqual(families[0], families[1]) {
		return bad
	}
	for address := range addresses[0] {
		if addresses[1][address] {
			return bad
		}
	}
	return nil
}

func validateExternalPacket(exit Exit) (map[string]any, error) {
	bad := errors.New("external packet relay lost its exact owner, remote identity or server proof")
	if exit.External == nil || exit.NodeID != "" || !externalPublicIP(exit.External.ExpectedPublicIP) || validatePacketDescriptions(exit.External.Packet, exit.Mode) != nil {
		return nil, bad
	}
	transport, err := validateTransport(exit)
	if err != nil {
		return nil, err
	}
	public, err := packetPublicDescription(transport, exit.Mode)
	if err != nil {
		return nil, err
	}
	owned, other := exit.External.Packet.Local, exit.External.Packet.Server
	if exit.External.Packet.Owner == "server" {
		owned, other = other, owned
	}
	if !reflect.DeepEqual(public, owned) {
		return nil, bad
	}
	secret, err := packetAgreement(transport, stringValue(other["client_public_key"]))
	if err != nil {
		return nil, err
	}
	clear(secret)
	peer := transport["peers"].([]any)[0].(map[string]any)
	host := stringValue(peer["address"])
	if !externalPublicIP(host) || exit.External.ResponseProbe.Validate(host) != nil {
		return nil, bad
	}
	if exit.StartLayer != nil {
		if _, _, err := WrapStartLayer(transport, exit.Mode, exit.StartLayer, ExitStartLayerTag, ""); err != nil {
			return nil, err
		}
	}
	return transport, nil
}

func externalPacketAuthKey(exit Exit, fingerprint string) ([]byte, error) {
	pair := exit.External.Packet
	other := pair.Server
	if pair.Owner == "server" {
		other = pair.Local
	}
	shared, err := packetAgreement(exit.Transport, stringValue(other["client_public_key"]))
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	var layerSecret any
	if exit.StartLayer != nil {
		layerSecret = exit.StartLayer.Transport["password"]
	}
	raw, _ := json.Marshal([]any{"routervpn-external-packet-salt-v3", fingerprint, layerSecret})
	salt := sha256.Sum256(raw)
	clear(raw)
	return packetHKDF(shared, salt[:], "routervpn-external-packet-lease-v3"), nil
}

// RFC 5869 extract and its first SHA-256 expansion block. The lease needs
// exactly 32 bytes. Keep the declared Go 1.23 module compatible (crypto/hkdf
// was introduced later), and cover this bounded form with the RFC test vector.
func packetHKDF(secret, salt []byte, info string) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(info))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

// PairExternalPacket is the administrator boundary. The server profile is a
// separate private protocol block; the client descriptor contains no server
// key. Only the public local description survives in the resulting registry.
func PairExternalPacket(id, protocol string, external, serverProfile map[string]any, layer *StartLayer) (Exit, error) {
	client, err := ExternalSelection(id, protocol, external, layer)
	if err != nil || !ExternalPacketMode(protocol) {
		return Exit{}, errors.New("packet pairing requires its exact client capture")
	}
	if len(serverProfile) != 2 || serverProfile["protocol"] != protocol || serverProfile[protocol] == nil {
		return Exit{}, errors.New("server peer profile must contain only protocol and its private peer block")
	}
	server, err := ExternalTransport(protocol, serverProfile)
	if err != nil {
		return Exit{}, err
	}
	client.Transport, client.External.Packet.Owner = server, "server"
	if _, err := externalTransport(client); err != nil {
		return Exit{}, err
	}
	return client, nil
}

func ExternalPacketIdentities(exit Exit) (string, string, error) {
	if !ExternalPacketMode(exit.Mode) {
		return "", "", errors.New("external transport is not a packet pairing")
	}
	if _, err := validateExternalPacket(exit); err != nil {
		return "", "", err
	}
	return stringValue(exit.External.Packet.Local["client_public_key"]), stringValue(exit.External.Packet.Server["client_public_key"]), nil
}

// ExternalPacketServerDescriptor is the offline public export for an operator's
// separately created server credential. Its output is safe to import alongside
// the Local private configuration; the eventual pairing proves both identities.
func ExternalPacketServerDescriptor(serverProfile map[string]any) (map[string]any, error) {
	protocol, ok := serverProfile["protocol"].(string)
	if !ok || !ExternalPacketMode(protocol) || len(serverProfile) != 2 {
		return nil, errors.New("server peer descriptor requires exactly one private WG/AWG profile")
	}
	transport, err := ExternalTransport(protocol, serverProfile)
	if err != nil {
		return nil, err
	}
	public, err := packetPublicDescription(transport, protocol)
	if err != nil {
		return nil, err
	}
	if _, _, err := packetPublicAddresses(public["address"]); err != nil {
		return nil, err
	}
	peer := public["peers"].([]any)[0].(map[string]any)
	if !canonicalPacketPublic(stringValue(peer["public_key"])) {
		return nil, errors.New("server peer descriptor requires a canonical remote identity")
	}
	descriptor := map[string]any{"public_key": public["client_public_key"], "addresses": public["address"], "mtu": public["mtu"]}
	if keepalive, ok := peer["persistent_keepalive_interval"]; ok && keepalive != float64(0) {
		descriptor["persistent_keepalive_interval"] = keepalive
	}
	return descriptor, nil
}
