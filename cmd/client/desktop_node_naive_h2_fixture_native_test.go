//go:build (linux || darwin) && routervpn_controller_privileged

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"

	"router-vpn/internal/common"
)

// These observations come from the separate native reference process. The
// native host tests still require the real installed Box, physical policy,
// selected DNS, private proof and joined retirement before writing a receipt.
type pairedNaiveH2Peer struct {
	Address, Base, AES netip.AddrPort
	Files              string
}

func pairedNaiveH2Read(raw []byte, physical netip.Addr, layer string, original *pairedNaiveH2Peer) (*pairedNaiveH2Peer, error) {
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
	bad := errors.New("Naive H2 peer changed its captured TLS/H2, TCP-only lower or original source")
	if json.Unmarshal(raw, &v) != nil || v.Schema != 1 || !physical.IsValid() || v.Files == "" ||
		v.RawTCP < 0 || v.RawUDP != 0 || v.PlainTCP < 0 || v.PlainUDP < 0 ||
		v.ProtocolRawTCP < 0 || v.ProtocolRawUDP != 0 || v.ProtocolTCP < 0 || v.ProtocolUDP < 0 ||
		v.TLSHTTP < 0 || v.WebSocket != 0 || v.Mux != 0 || v.UDPBranch != "" ||
		v.PhysicalClient != "" || v.RelaySource != "" || v.Parameters != "" || v.RejectedUDP != 0 {
		return nil, bad
	}
	address, aerr := netip.ParseAddrPort(v.Address)
	base, berr := netip.ParseAddrPort(v.Base)
	if aerr != nil || berr != nil || address.Addr() != physical || base.Addr() != physical || address.Port() == 0 || base.Port() == 0 {
		return nil, bad
	}
	capture := &pairedNaiveH2Peer{Address: address, Base: base, Files: v.Files}
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

func pairedNaiveH2WrongKeyAction(action string) bool {
	switch action {
	case "wrong-key", "wrong-user", "wrong-trust", "wrong-server-name", "wrong-layer-key", "wrong-whitening":
		return true
	}
	return false
}

// Positive installation preserves both private source byte strings exactly.
// A negative changes only its named authentication, trust or SNI field. Outer
// AES/whitening faults remain independently captured by the Start Layer peer.
func pairedNaiveH2Assets(files string, endpoint netip.AddrPort, action string) (map[string][]byte, error) {
	bad := errors.New("Naive H2 lost its original endpoint, authenticated H2/UoT-v2 graph or private CA")
	var encoded map[string]string
	if !endpoint.IsValid() || endpoint.Port() == 0 || json.Unmarshal([]byte(files), &encoded) != nil || len(encoded) != 2 || encoded["sing-box.json"] == "" || encoded["cert.pem"] == "" {
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
	var graph struct {
		Inbounds []struct {
			Type string `json:"type"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type     string `json:"type"`
			Tag      string `json:"tag"`
			Server   string `json:"server"`
			Port     int    `json:"server_port"`
			Username string `json:"username"`
			Password string `json:"password"`
			QUIC     bool   `json:"quic"`
			UDP      struct {
				Enabled bool `json:"enabled"`
				Version int  `json:"version"`
			} `json:"udp_over_tcp"`
			TLS struct {
				Enabled         bool   `json:"enabled"`
				Insecure        bool   `json:"insecure"`
				ServerName      string `json:"server_name"`
				CertificatePath string `json:"certificate_path"`
			} `json:"tls"`
		} `json:"outbounds"`
		Route struct {
			Final string `json:"final"`
		} `json:"route"`
	}
	if json.Unmarshal(assets["sing-box.json"], &graph) != nil || len(graph.Inbounds) != 1 || graph.Inbounds[0].Type != "tun" || len(graph.Outbounds) != 1 || graph.Route.Final != "proxy" {
		return nil, bad
	}
	out := graph.Outbounds[0]
	if out.Type != "naive" || out.Tag != "proxy" || out.Server != endpoint.Addr().String() || out.Port != int(endpoint.Port()) ||
		out.Username == "" || out.Password == "" || out.Username == out.Password || out.QUIC || !out.UDP.Enabled || out.UDP.Version != 2 ||
		!out.TLS.Enabled || out.TLS.Insecure || out.TLS.ServerName != "captured-naive.test" || out.TLS.CertificatePath != "cert.pem" {
		return nil, bad
	}
	block, rest := pem.Decode(assets["cert.pem"])
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, bad
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.VerifyHostname(out.TLS.ServerName) != nil {
		return nil, bad
	}
	if action == "wrong-trust" {
		// A syntactically valid CA with the same selected name but a different
		// private key must fail the real TLS peer; SNI remains unchanged.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		assets["cert.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	if action == "wrong-key" || action == "wrong-user" || action == "wrong-server-name" {
		var changed map[string]any
		if json.Unmarshal(assets["sing-box.json"], &changed) != nil {
			return nil, bad
		}
		value := changed["outbounds"].([]any)[0].(map[string]any)
		switch action {
		case "wrong-key":
			value["password"] = out.Password + "-wrong"
		case "wrong-user":
			value["username"] = out.Username + "-wrong"
		case "wrong-server-name":
			value["tls"].(map[string]any)["server_name"] = "wrong-naive.test"
		}
		assets["sing-box.json"], err = json.Marshal(changed)
		if err != nil {
			return nil, err
		}
	}
	return assets, nil
}
