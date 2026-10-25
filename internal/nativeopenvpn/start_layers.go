package nativeopenvpn

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const MaxStartLayersBytes = 128 << 10

var errStartLayers = errors.New("OpenVPN Start Layers require the exact captured private provision for every original remote host")

// StartLayer is a private provision for one original OpenVPN provider host.
// It deliberately has no executable user-supplied detour or routing policy.
type StartLayer struct {
	Mode      string         `json:"mode"`
	API       string         `json:"api"`
	Transport map[string]any `json:"transport"`
}

// StartLayers is keyed by canonical original public hosts, never by the private
// service address. Multiple independent providers may use the same private IP.
type StartLayers map[string]StartLayer

func validStartLayerMode(mode string) bool {
	return mode == "aes-256-gcm" || mode == "aes-256-gcm+xor-whitening"
}

func startLayerIdent(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

func (layer *StartLayer) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 16<<10)
	if err != nil || len(object) != 3 {
		return errStartLayers
	}
	mode, modeOK := object["mode"].(string)
	api, apiOK := object["api"].(string)
	transport, transportOK := object["transport"].(map[string]any)
	if !modeOK || !apiOK || !transportOK {
		return errStartLayers
	}
	result := StartLayer{Mode: mode, API: api, Transport: transport}
	host, ok := transport["server"].(string)
	if !ok || result.Validate(host, mode) != nil {
		return errStartLayers
	}
	*layer = result
	return nil
}

// Validate rejects an outer transport from another provider even when both
// providers happen to expose the same private service address.
func (layer StartLayer) Validate(host, selectedMode string) error {
	if !remotePublicHost(host) || !validStartLayerMode(selectedMode) || layer.Mode != selectedMode || len(layer.API) > 2048 || strings.TrimSpace(layer.API) != layer.API {
		return errStartLayers
	}
	api, err := url.Parse(layer.API)
	if err != nil || api == nil || api.Scheme != "http" && api.Scheme != "https" || api.User != nil || api.RawQuery != "" || api.ForceQuery || api.Fragment != "" || api.RawPath != "" || api.Opaque != "" || api.Path != "" && api.Path != "/" {
		return errStartLayers
	}
	address, addressErr := netip.ParseAddr(api.Hostname())
	port, portErr := strconv.Atoi(api.Port())
	if addressErr != nil || portErr != nil || api.Port() != strconv.Itoa(port) || port < 1 || port > 65535 || address.Is4In6() || address.Zone() != "" || !address.IsPrivate() || address.String() != api.Hostname() {
		return errStartLayers
	}
	outer := layer.Transport
	if len(outer) != 6 || outer["type"] != "shadowsocks" || outer["method"] != "2022-blake3-aes-256-gcm" || outer["server"] != host {
		return errStartLayers
	}
	tag, tagOK := outer["tag"].(string)
	outerPort, outerPortOK := outer["server_port"].(float64)
	password, passwordOK := outer["password"].(string)
	if !tagOK || !startLayerIdent(tag) || !outerPortOK || outerPort != float64(int(outerPort)) || outerPort < 1 || outerPort > 65535 || !passwordOK || len(password) == 0 || len(password) > 4096 {
		return errStartLayers
	}
	for _, part := range strings.Split(password, ":") {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return errStartLayers
		}
	}
	return nil
}

func (layers *StartLayers) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, MaxStartLayersBytes)
	if err != nil || len(object) < 2 || len(object) > 16 {
		return errStartLayers
	}
	result := StartLayers{}
	mode := ""
	for host, value := range object {
		encoded, err := json.Marshal(value)
		var layer StartLayer
		if err != nil || json.Unmarshal(encoded, &layer) != nil {
			return errStartLayers
		}
		if mode == "" {
			mode = layer.Mode
		}
		if layer.Validate(host, mode) != nil {
			return errStartLayers
		}
		result[host] = layer
	}
	*layers = result
	return nil
}

// Mode is only a selection helper. Call Validate before compiling, signing or
// returning egress policy; an invalid typed map must never gain authority here.
func (layers StartLayers) Mode() string {
	mode := ""
	for _, layer := range layers {
		if !validStartLayerMode(layer.Mode) || mode != "" && mode != layer.Mode {
			return ""
		}
		mode = layer.Mode
	}
	return mode
}

// DatagramOverhead bounds the larger authenticated SS2022 request/response
// envelope for every allowed host. XOR preserves ciphertext length. The outer
// IPv4/IPv6 UDP header is accounted by the enclosing OpenVPN path budget.
func (layers StartLayers) DatagramOverhead() (int, error) {
	mode := layers.Mode()
	if len(layers) < 2 || len(layers) > 16 || !validStartLayerMode(mode) {
		return 0, errStartLayers
	}
	maximum := 0
	for host, layer := range layers {
		if layer.Validate(host, mode) != nil {
			return 0, errStartLayers
		}
		api, _ := url.Parse(layer.API)
		addressBytes := 7
		if strings.Contains(api.Hostname(), ":") {
			addressBytes = 19
		}
		keys := len(strings.Split(layer.Transport["password"].(string), ":"))
		overhead := max(43+addressBytes+16*(keys-1), 51+addressBytes)
		maximum = max(maximum, overhead)
	}
	return maximum, nil
}

// ValidatePairingKeys prevents a provisioned outer key from disclosing either
// role's private X25519 identity to the other owner. Compare public identities
// so alternate private-byte encodings with the same clamped identity cannot
// bypass separation. These keys are never returned or included in errors.
func (layers StartLayers) ValidatePairingKeys(publicKeys ...string) error {
	for _, public := range publicKeys {
		if !CanonicalPairingPublic(public) {
			return errStartLayers
		}
	}
	for host, layer := range layers {
		if layer.Validate(host, layers.Mode()) != nil {
			return errStartLayers
		}
		for _, part := range strings.Split(layer.Transport["password"].(string), ":") {
			key, err := base64.StdEncoding.Strict().DecodeString(part)
			if err != nil {
				return errStartLayers
			}
			private, err := ecdh.X25519().NewPrivateKey(key)
			clear(key)
			if err != nil {
				return errStartLayers
			}
			public := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
			for _, paired := range publicKeys {
				if public == paired {
					return errStartLayers
				}
			}
		}
	}
	return nil
}

func (layers StartLayers) Validate(endpoint map[string]any, probes ResponseProbes, selectedMode string) error {
	if len(layers) < 2 || len(layers) > 16 || len(layers) != len(probes) || probes.Validate(endpoint) != nil || !validStartLayerMode(selectedMode) {
		return errStartLayers
	}
	encoded, err := json.Marshal(layers)
	if err != nil || len(encoded) > MaxStartLayersBytes {
		return errStartLayers
	}
	for host := range probes {
		layer, exists := layers[host]
		if !exists || layer.Validate(host, selectedMode) != nil {
			return errStartLayers
		}
	}
	return nil
}

func decodeStartLayers(profileJSON, responseProbesJSON, layersJSON, selectedMode string) (map[string]any, StartLayers, error) {
	if len(layersJSON) == 0 || len(layersJSON) > MaxStartLayersBytes || len(responseProbesJSON) > 40<<10 || len(profileJSON) > 8*MaxProfileBytes {
		return nil, nil, errStartLayers
	}
	var profile Profile
	var probes ResponseProbes
	var layers StartLayers
	if json.Unmarshal([]byte(profileJSON), &profile) != nil || json.Unmarshal([]byte(responseProbesJSON), &probes) != nil || json.Unmarshal([]byte(layersJSON), &layers) != nil {
		return nil, nil, errStartLayers
	}
	endpoint, err := CompileProfile(profile, "exit", "")
	if err != nil || layers.Validate(endpoint, probes, selectedMode) != nil {
		return nil, nil, errStartLayers
	}
	return endpoint, layers, nil
}

func ValidateStartLayers(profileJSON, responseProbesJSON, layersJSON, selectedMode string) error {
	_, _, err := decodeStartLayers(profileJSON, responseProbesJSON, layersJSON, selectedMode)
	return err
}

// LayerEgress is the physical outer endpoint, not the inner OpenVPN service
// port. A caller with a preceding Router transport uses that entry's egress
// instead; this helper never decides which process owns the physical path.
type LayerEgress struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

func StartLayerEgress(profileJSON, responseProbesJSON, layersJSON, selectedMode string) ([]LayerEgress, error) {
	endpoint, layers, err := decodeStartLayers(profileJSON, responseProbesJSON, layersJSON, selectedMode)
	if err != nil {
		return nil, err
	}
	remotes, err := Remotes(endpoint)
	if err != nil {
		return nil, errStartLayers
	}
	seen := map[LayerEgress]bool{}
	result := make([]LayerEgress, 0, len(remotes))
	for _, remote := range remotes {
		port := int(layers[remote.Host].Transport["server_port"].(float64))
		if selectedMode == "aes-256-gcm+xor-whitening" {
			port = 8389
		}
		egress := LayerEgress{Host: remote.Host, Port: port, Network: remote.Network}
		if !seen[egress] {
			result = append(result, egress)
			seen[egress] = true
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Network < result[j].Network
	})
	return result, nil
}
