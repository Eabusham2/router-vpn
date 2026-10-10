package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"router-vpn/internal/applexray"
	"router-vpn/internal/awgpolicy"
	"strings"
)

const EntryStartLayerTag = "routervpn-entry-start-layer"

type EntryStartLayer struct {
	Mode    string            `json:"mode"`
	Profile map[string]string `json:"profile"`
}

// NewWithEntryStartLayer builds the normal frozen Local/Server/Auto controller,
// then encloses only its entry in the captured node's authenticated AES path.
// It never starts an engine or mutates the caller's profile. Both execution
// candidates, their node proofs and DNS continue to traverse that exact entry.
func NewWithEntryStartLayer(config, metadata, start string) (*Controller, error) {
	if start == "" {
		return New(config, metadata)
	}
	var request EntryStartLayer
	if exactJSON([]byte(start), &request, 16384) != nil || request.Profile == nil {
		return nil, errors.New("invalid captured entry Start Layer")
	}
	if request.Mode != "aes-256-gcm" && request.Mode != "aes-256-gcm+xor-whitening" {
		return nil, errors.New("entry Start Layer requires authenticated AES; standalone XOR is not encryption")
	}
	profile, err := json.Marshal(request.Profile)
	if err != nil {
		return nil, err
	}
	encoded, err := CompileProxyEntry(string(profile), "shadowsocks")
	if err != nil {
		return nil, errors.New("entry Start Layer requires its exact self-contained AES profile")
	}
	var outer map[string]any
	if exactJSON([]byte(encoded), &outer, 4<<20) != nil || len(outer) != 6 || outer["method"] != NativeStartLayerMethod {
		return nil, errors.New("entry Start Layer cannot discard extra transport policy")
	}
	password, ok := outer["password"].(string)
	if !ok || len(password) > 4096 {
		return nil, errors.New("invalid entry AES credential")
	}
	for _, part := range strings.Split(password, ":") {
		key, e := base64.StdEncoding.Strict().DecodeString(part)
		if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != part {
			return nil, errors.New("entry AES requires exact 256-bit keys")
		}
	}
	controller, err := New(config, metadata)
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(controller.config), &graph, 4<<20) != nil {
		return nil, errors.New("invalid planned entry graph")
	}
	var entry map[string]any
	for _, list := range []string{"endpoints", "outbounds"} {
		values, _ := graph[list].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid native transport")
			}
			if value["tag"] == EntryStartLayerTag {
				return nil, errors.New("entry Start Layer tag already has an owner")
			}
			if value["tag"] == controller.meta.EntryTag {
				if entry != nil {
					return nil, errors.New("entry Start Layer has ambiguous ownership")
				}
				entry = value
			}
		}
	}
	if entry == nil || entry["detour"] != nil {
		return nil, errors.New("entry already has another physical transport")
	}
	host, err := entryStartHost(entry, controller.meta.EntryMode)
	if err != nil {
		return nil, err
	}
	server, ok := outer["server"].(string)
	left, e1 := netip.ParseAddr(host)
	right, e2 := netip.ParseAddr(server)
	if !ok || e1 != nil || e2 != nil || left != right || !wireGuardServerIP(host) || !wireGuardServerIP(server) {
		return nil, errors.New("entry AES and native transport must belong to the same captured server")
	}
	api, err := privateAPI(controller.meta.EntryAPI)
	if err != nil {
		return nil, err
	}
	if !wireGuardServerIP(api.Hostname()) {
		return nil, errors.New("entry service has no valid private literal address")
	}
	if err = rewriteEntryStartHost(entry, controller.meta.EntryMode, api.Hostname()); err != nil {
		return nil, err
	}
	entry["detour"] = EntryStartLayerTag
	outer["tag"] = EntryStartLayerTag
	if request.Mode == "aes-256-gcm+xor-whitening" {
		outer["type"] = "routervpn-aes-xor"
		outer["server_port"] = 8389
	}
	graph["outbounds"] = append(graph["outbounds"].([]any), outer)
	result, err := json.Marshal(graph)
	if err != nil || len(result) > 4<<20 {
		return nil, errors.New("entry Start Layer graph exceeds its bound")
	}
	controller.config = string(result)
	return controller, nil
}

func entryStartHost(entry map[string]any, mode string) (string, error) {
	bad := errors.New("entry Start Layer lost its exact native transport")
	if awgpolicy.WireGuardFamily(mode) {
		peers, ok := entry["peers"].([]any)
		if !ok || len(peers) != 1 {
			return "", bad
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return "", bad
		}
		if _, ok = exactStartPort(peer["port"]); !ok {
			return "", bad
		}
		host, ok := peer["address"].(string)
		if !ok {
			return "", bad
		}
		return host, nil
	}
	if XrayEntryMode(mode) {
		raw, ok := entry["config_json"].(string)
		if !ok {
			return "", bad
		}
		plan, err := applexray.Prepare(mode, []byte(raw))
		if err != nil {
			return "", bad
		}
		return plan.ServerHost, nil
	}
	if mode == "shadowsocks" || mode == "hysteria2" {
		if err := validateProxyEntry(entry, mode); err != nil {
			return "", bad
		}
		host, ok := entry["server"].(string)
		if !ok {
			return "", bad
		}
		return host, nil
	}
	return "", bad
}

func rewriteEntryStartHost(entry map[string]any, mode, host string) error {
	if awgpolicy.WireGuardFamily(mode) {
		entry["peers"].([]any)[0].(map[string]any)["address"] = host
		if mode != "wg" {
			raw, _ := json.Marshal(entry)
			if _, err := AmneziaRuntimeConfig(string(raw)); err != nil {
				return err
			}
		}
		return nil
	}
	if XrayEntryMode(mode) {
		var raw map[string]any
		if exactJSON([]byte(entry["config_json"].(string)), &raw, 4<<20) != nil {
			return errors.New("invalid original Xray entry")
		}
		raw["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = host
		encoded, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if _, err = applexray.Prepare(mode, encoded); err != nil {
			return err
		}
		entry["config_json"] = string(encoded)
		return nil
	}
	entry["server"] = host
	return validateProxyEntry(entry, mode)
}
