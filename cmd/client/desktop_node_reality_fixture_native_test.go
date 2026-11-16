//go:build (linux || darwin) && routervpn_controller_privileged

package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
)

func pairedREALITYMode(mode string) bool {
	return mode == "reality-vision" || mode == "reality-pq-vision" || mode == "reality-xhttp"
}

type pairedREALITYPeer struct {
	Address, Base, AES netip.AddrPort
	Files              string
}

// This receipt describes the separately retained reference process, not a
// successful native tunnel. The enclosing installed-host case still requires
// its original policy, selected DNS, node proof and joined native retirement.
func pairedREALITYRead(raw []byte, physical netip.Addr, layer string, original *pairedREALITYPeer) (*pairedREALITYPeer, error) {
	var v struct {
		Schema         int    `json:"schema"`
		Address        string `json:"address"`
		Base           string `json:"base_address"`
		AES            string `json:"aes_address"`
		Files          string `json:"protocol_files"`
		RawTCP         int64  `json:"raw_tcp"`
		RawUDP         int64  `json:"raw_udp"`
		PlainTCP       int64  `json:"plain_tcp"`
		PlainUDP       int64  `json:"plain_udp"`
		ProtocolRawTCP int64  `json:"protocol_raw_tcp"`
		ProtocolRawUDP int64  `json:"protocol_raw_udp"`
		ProtocolTCP    int64  `json:"protocol_tcp"`
		ProtocolUDP    int64  `json:"protocol_udp"`
		TLSHTTP        int64  `json:"protocol_tls_http"`
		WebSocket      int64  `json:"protocol_websocket"`
		Mux            int64  `json:"protocol_mux"`
		UDPBranch      string `json:"udp_branch_address"`
		PhysicalClient string `json:"physical_client_address"`
		RelaySource    string `json:"relay_source_address"`
		Parameters     string `json:"parameters_sha256"`
		RejectedUDP    int64  `json:"rejected_udp"`
	}
	bad := errors.New("REALITY peer changed its original TCP lower, private source or reference owner")
	if json.Unmarshal(raw, &v) != nil || v.Schema != 1 || !physical.IsValid() || v.Files == "" ||
		v.RawTCP < 0 || v.RawUDP != 0 || v.PlainTCP < 0 || v.PlainUDP < 0 ||
		v.ProtocolRawTCP < 0 || v.ProtocolRawUDP != 0 || v.ProtocolTCP < 0 || v.ProtocolUDP < 0 ||
		v.TLSHTTP != 0 || v.WebSocket != 0 || v.Mux != 0 || v.UDPBranch != "" ||
		v.PhysicalClient != "" || v.RelaySource != "" || v.Parameters != "" || v.RejectedUDP != 0 {
		return nil, bad
	}
	address, aerr := netip.ParseAddrPort(v.Address)
	base, berr := netip.ParseAddrPort(v.Base)
	if aerr != nil || berr != nil || address.Addr() != physical || base.Addr() != physical || address.Port() == 0 || base.Port() == 0 {
		return nil, bad
	}
	capture := &pairedREALITYPeer{Address: address, Base: base, Files: v.Files}
	if layer == "" {
		if v.AES != "" || address != base || v.ProtocolRawTCP < v.RawTCP || v.ProtocolTCP < v.PlainTCP || v.ProtocolUDP < v.PlainUDP {
			return nil, bad
		}
	} else {
		aes, err := netip.ParseAddrPort(v.AES)
		white := layer == common.StartLayerAES256GCMXOR
		if err != nil || aes.Addr() != physical || aes.Port() == 0 || aes == base || address == base || v.PlainUDP != 0 ||
			layer != common.StartLayerAES256GCM && !white || white && (address.Port() != 8389 || aes == address) || !white && aes != address {
			return nil, bad
		}
		capture.AES = aes
	}
	if original != nil && *capture != *original {
		return nil, bad
	}
	return capture, nil
}

func pairedREALITYWrongKeyAction(action string) bool {
	switch action {
	case "wrong-key", "wrong-user", "wrong-server-name", "wrong-short-id", "wrong-pq-key", "wrong-path", "wrong-layer-key", "wrong-whitening":
		return true
	}
	return false
}

// Positives preserve both private assets byte-for-byte. A negative mutates only
// its named credential or transport field after the real shared parser proves
// the complete original VLESS, REALITY and Vision/PQ/XHTTP configuration.
func pairedREALITYAssets(files string, endpoint netip.AddrPort, mode, action string) (map[string][]byte, error) {
	bad := errors.New("REALITY lost its complete captured private Xray source")
	var encoded map[string]string
	if !pairedREALITYMode(mode) || !endpoint.IsValid() || endpoint.Port() == 0 || json.Unmarshal([]byte(files), &encoded) != nil || len(encoded) != 2 || encoded["sing-box.json"] == "" || encoded["xray.json"] == "" {
		return nil, bad
	}
	assets := make(map[string][]byte, 2)
	for name, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) == 0 || len(raw) > 32<<10 || base64.StdEncoding.EncodeToString(raw) != value {
			return nil, bad
		}
		assets[name] = raw
	}
	plan, err := applexray.Prepare(mode, assets["xray.json"])
	if err != nil || plan.Server != endpoint || plan.ListenerPort != 1090 {
		return nil, bad
	}
	wrapper, err := applexray.Object(assets["sing-box.json"])
	if err != nil || len(wrapper) != 3 {
		return nil, bad
	}
	ins, iok := wrapper["inbounds"].([]any)
	outs, ook := wrapper["outbounds"].([]any)
	route, rok := wrapper["route"].(map[string]any)
	if !iok || !ook || !rok || len(ins) != 1 || len(outs) != 1 || len(route) != 2 || route["final"] != "proxy" {
		return nil, bad
	}
	in, iok := ins[0].(map[string]any)
	out, ook := outs[0].(map[string]any)
	rules, rok := route["rules"].([]any)
	if !iok || !ook || !rok || len(rules) != 0 || len(in) != 4 || in["type"] != "tun" || in["tag"] != "tun-in" || in["auto_route"] != true || in["strict_route"] != true ||
		len(out) != 5 || out["type"] != "socks" || out["tag"] != "proxy" || out["server"] != "127.0.0.1" || out["server_port"] != json.Number("1090") || out["version"] != "5" {
		return nil, bad
	}
	if !pairedREALITYWrongKeyAction(action) || action == "wrong-layer-key" || action == "wrong-whitening" {
		return assets, nil
	}
	graph, err := applexray.Object(assets["xray.json"])
	if err != nil {
		return nil, err
	}
	value := graph["outbounds"].([]any)[0].(map[string]any)
	user := value["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	stream := value["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	switch action {
	case "wrong-key":
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		reality["password"] = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	case "wrong-user":
		old := user["id"].(string)
		first := "0"
		if old[0] == '0' {
			first = "1"
		}
		user["id"] = first + old[1:]
	case "wrong-server-name":
		reality["serverName"] = "wrong-reality.example.com"
	case "wrong-short-id":
		old := reality["shortId"].(string)
		if len(old) != 16 {
			return nil, bad
		}
		first := "0"
		if old[0] == '0' {
			first = "1"
		}
		reality["shortId"] = first + old[1:]
	case "wrong-pq-key":
		if mode == "reality-vision" {
			return nil, bad
		}
		var seed [64]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		key, err := mlkem.NewDecapsulationKey768(seed[:])
		clear(seed[:])
		if err != nil {
			return nil, err
		}
		user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(key.EncapsulationKey().Bytes())
	case "wrong-path":
		if mode != "reality-xhttp" {
			return nil, bad
		}
		stream["xhttpSettings"].(map[string]any)["path"] = "/unowned-reality-control"
	default:
		return nil, bad
	}
	assets["xray.json"], err = json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	if _, err := applexray.Prepare(mode, assets["xray.json"]); err != nil {
		return nil, bad
	}
	return assets, nil
}
