package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"router-vpn/internal/mobilepq"
)

const PQType = "routervpn-pq"

// PQEndpointConfig keeps the base WG/AWG fields visible to native MTU and graph
// policy. PQ is mandatory for this endpoint; it never becomes an ordinary peer
// when its protocol factory, handshake, rekey or cleanup fails.
type PQEndpointConfig struct {
	AmneziaEndpointConfig
	Mode   string          `json:"mode"`
	NodeID string          `json:"node_id"`
	PQ     mobilepq.Config `json:"pq"`
}

type PQRuntime struct {
	Mode       string
	BaseJSON   string
	PeerPublic []byte
	PQ         mobilepq.Config
}

func IsPQMode(mode string) bool { return mode == "wg-pq" || mode == "awg2-pq" }

// CompilePQProfile consumes the generated private profile assets as data. It
// never executes TOML/env directives or opens their paths. The PQ transport IP
// comes from the captured WG/AWG peer, not a second hostname lookup.
func CompilePQProfile(mode, encodedFiles, nodeID string) (string, error) {
	bad := errors.New("invalid generated native PQ profile")
	if !IsPQMode(mode) || !proofID.MatchString(nodeID) {
		return "", bad
	}
	var encoded map[string]string
	if exactJSON([]byte(encodedFiles), &encoded, 12*1024*1024) != nil || len(encoded) > 32 {
		return "", bad
	}
	files := map[string][]byte{}
	defer func() {
		for _, data := range files {
			for i := range data {
				data[i] = 0
			}
		}
	}()
	total := 0
	for name, value := range encoded {
		if !exactID.MatchString(name) || strings.HasPrefix(name, ".") {
			return "", bad
		}
		data, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(data) > 2*1024*1024 {
			return "", bad
		}
		files[name] = data
		total += len(data)
		if total > 8*1024*1024 {
			return "", bad
		}
	}
	asset := "wg.conf"
	if mode == "awg2-pq" {
		asset = "awg.conf"
	}
	raw := string(files[asset])
	var profile wireGuardProfile
	var err error
	if mode == "wg-pq" {
		profile, err = parseWireGuardProfile(raw, nodeID)
	} else {
		var compiled string
		compiled, err = CompileAmneziaProfile(raw, nodeID)
		if err == nil {
			err = json.Unmarshal([]byte(compiled), &profile)
		}
	}
	if err != nil {
		return "", err
	}
	return compilePQAssets(mode, nodeID, profile, files)
}

func compilePQAssets(mode, nodeID string, profile wireGuardProfile, files map[string][]byte) (string, error) {
	bad := errors.New("generated PQ assets do not belong to the selected peer")
	// Normalize the existing validated endpoint once; no private source fields
	// are inferred or substituted by the native host.
	base, err := json.Marshal(profile.Endpoint)
	if err != nil {
		return "", bad
	}
	var endpoint AmneziaEndpointConfig
	if err = json.Unmarshal(base, &endpoint); err != nil || len(endpoint.Peers) != 1 {
		return "", bad
	}
	peer := endpoint.Peers[0]
	env, err := parsePQEnvironment(string(files["rosenpass.env"]))
	if err != nil {
		return "", err
	}
	tool := "wg"
	if mode == "awg2-pq" {
		tool = "awg"
	}
	if env["ROSENPASS_TOOL"] != tool || env["ROSENPASS_INTERFACE"] != tool || env["ROSENPASS_WG_PEER"] != peer.PublicKey || env["ROSENPASS_KEY_OUT"] != "rosenpass.psk" {
		return "", bad
	}
	port, err := wireGuardNumber(env["ROSENPASS_PORT"], 1, 65535)
	if err != nil {
		return "", bad
	}
	if err = validatePQDocument(string(files["rosenpass.toml"]), port); err != nil {
		return "", err
	}
	endpoint.Type, endpoint.Tag = PQType, "proxy"
	options := PQEndpointConfig{AmneziaEndpointConfig: endpoint, Mode: mode, NodeID: nodeID,
		PQ: mobilepq.Config{Endpoint: net.JoinHostPort(peer.Address, strconv.Itoa(port)), Version: 2,
			Secret: files["rosenpass-client-secret"], Public: files["rosenpass-client-public"], Peer: files["rosenpass-server-public"]}}
	serialized, err := json.Marshal(options)
	if err != nil {
		return "", bad
	}
	checked, err := PQRuntimeConfig(string(serialized))
	if err != nil {
		return "", err
	}
	checked.PQ.Erase()
	if err = json.Unmarshal(serialized, &profile.Endpoint); err != nil {
		return "", bad
	}
	return nativeExitConfig(profile)
}

// PQRuntimeConfig revalidates hand-written native JSON before creating any
// protocol, transport, peer or interface. A WG profile remains native WG; AWG
// retains all eleven generated obfuscation parameters.
func PQRuntimeConfig(raw string) (PQRuntime, error) {
	fail := errors.New("invalid native PQ endpoint ownership")
	var object map[string]any
	if exactJSON([]byte(raw), &object, 12*1024*1024) != nil {
		return PQRuntime{}, fail
	}
	var config PQEndpointConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || !IsPQMode(config.Mode) || !proofID.MatchString(config.NodeID) || config.Type != "" && config.Type != PQType || config.System || config.ListenPort != 0 || len(config.Peers) != 1 || config.Tag != "" && !exactID.MatchString(config.Tag) || config.Detour != "" && !exactID.MatchString(config.Detour) {
		return PQRuntime{}, fail
	}
	if err := config.PQ.Validate(); err != nil {
		return PQRuntime{}, err
	}
	peer := config.Peers[0]
	endpoint, _, err := net.SplitHostPort(config.PQ.Endpoint)
	if err != nil || endpoint != peer.Address {
		return PQRuntime{}, fail
	}
	base := config.AmneziaEndpointConfig
	if config.Mode == "wg-pq" {
		if len(base.Parameters) != 0 {
			return PQRuntime{}, fail
		}
		base.Type = "wireguard"
		profile := nativePQBaseProfile(base)
		if _, err = parseWireGuardProfile(profile, config.NodeID); err != nil {
			return PQRuntime{}, err
		}
	} else {
		base.Type = AmneziaType
		encoded, _ := json.Marshal(base)
		if _, err = AmneziaRuntimeConfig(string(encoded)); err != nil {
			return PQRuntime{}, err
		}
	}
	public, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKey)
	if err != nil || len(public) != 32 {
		return PQRuntime{}, fail
	}
	// These options are passed to the existing pinned endpoint constructor.
	encoded, err := json.Marshal(base)
	if err != nil {
		return PQRuntime{}, fail
	}
	var clean map[string]any
	_ = json.Unmarshal(encoded, &clean)
	delete(clean, "type")
	delete(clean, "tag")
	if config.Mode == "wg-pq" {
		delete(clean, "amnezia")
	}
	encoded, err = json.Marshal(clean)
	if err != nil {
		return PQRuntime{}, fail
	}
	return PQRuntime{Mode: config.Mode, BaseJSON: string(encoded), PeerPublic: public, PQ: config.PQ}, nil
}

func nativePQBaseProfile(c AmneziaEndpointConfig) string {
	p := c.Peers[0]
	text := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=%s\nMTU=%d\n[Peer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s\nPersistentKeepalive=%d\n", c.PrivateKey, strings.Join(c.Address, ","), c.MTU, p.PublicKey, net.JoinHostPort(p.Address, strconv.Itoa(p.Port)), strings.Join(p.AllowedIPs, ","), p.Keepalive)
	if p.PreSharedKey != "" {
		text += "PresharedKey=" + p.PreSharedKey + "\n"
	}
	return text
}

func parsePQEnvironment(text string) (map[string]string, error) {
	bad := errors.New("invalid generated PQ peer metadata")
	if len(text) == 0 || len(text) > 16384 || !utf8.ValidString(text) {
		return nil, bad
	}
	expected := map[string]bool{"ROSENPASS_TOOL": true, "ROSENPASS_INTERFACE": true, "ROSENPASS_WG_PEER": true, "ROSENPASS_KEY_OUT": true, "ROSENPASS_PORT": true}
	result := map[string]string{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || !expected[key] || result[key] != "" || value == "" || strings.ContainsAny(value, "\x00\r\n\"'`$;\\") {
			return nil, bad
		}
		result[key] = value
	}
	if len(result) != len(expected) {
		return nil, bad
	}
	return result, nil
}

func validatePQDocument(text string, port int) error {
	bad := errors.New("unowned directive in generated PQ document")
	if len(text) == 0 || len(text) > 16384 || !utf8.ValidString(text) {
		return bad
	}
	root, peer := map[string]string{}, map[string]string{}
	current := root
	peers := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[peers]]" {
			peers++
			if peers != 1 {
				return bad
			}
			current = peer
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || current[key] != "" || key == "" || value == "" {
			return bad
		}
		if key == "listen" && peers == 0 {
			if strings.ReplaceAll(value, " ", "") != "[]" {
				return bad
			}
			current[key] = "[]"
			continue
		}
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' || strings.ContainsAny(value[1:len(value)-1], "\"\\\x00\r\n") {
			return bad
		}
		current[key] = value[1 : len(value)-1]
	}
	if peers != 1 || len(root) != 4 || len(peer) != 3 || root["public_key"] != "rosenpass-client-public" || root["secret_key"] != "rosenpass-client-secret" || root["listen"] != "[]" || root["verbosity"] != "Quiet" || peer["public_key"] != "rosenpass-server-public" || peer["key_out"] != "rosenpass.psk" {
		return bad
	}
	host, portText, err := net.SplitHostPort(peer["endpoint"])
	if err != nil || host == "" || strings.ContainsAny(host, "/\\ \t\x00") {
		return bad
	}
	got, err := wireGuardNumber(portText, 1, 65535)
	if err != nil || got != port {
		return bad
	}
	return nil
}
