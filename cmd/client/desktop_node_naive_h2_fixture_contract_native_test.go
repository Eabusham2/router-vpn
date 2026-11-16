//go:build (linux || darwin) && routervpn_controller_privileged

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/netip"
	"testing"
	"time"
)

// These are source/fixture contracts. Only the separate installed host phase
// may claim real TLS/H2, PF/nft, TUN, DNS, MTU or retirement execution.
func TestDesktopUnixNaiveH2PrivateFixtureRefusesSubstitution(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "captured-naive.test"}, DNSNames: []string{"captured-naive.test"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	endpoint := netip.MustParseAddrPort("192.0.2.17:24443")
	for _, fault := range []string{"original", "quic", "uot-disabled", "uot-version", "endpoint", "port", "username", "password", "trust-disabled", "trust-insecure", "sni", "certificate-path", "missing-ca", "extra-source", "extra-outbound", "foreign-final"} {
		t.Run(fault, func(t *testing.T) {
			out := map[string]any{"type": "naive", "tag": "proxy", "server": endpoint.Addr().String(), "server_port": endpoint.Port(), "username": "captured-user", "password": "captured-private-password", "quic": false, "udp_over_tcp": map[string]any{"enabled": true, "version": 2}, "tls": map[string]any{"enabled": true, "server_name": "captured-naive.test", "certificate_path": "cert.pem"}}
			graph := map[string]any{"inbounds": []any{map[string]any{"type": "tun"}}, "outbounds": []any{out}, "route": map[string]any{"final": "proxy"}}
			switch fault {
			case "quic":
				out["quic"] = true
			case "uot-disabled":
				out["udp_over_tcp"].(map[string]any)["enabled"] = false
			case "uot-version":
				out["udp_over_tcp"].(map[string]any)["version"] = 1
			case "endpoint":
				out["server"] = "192.0.2.18"
			case "port":
				out["server_port"] = 24444
			case "username":
				out["username"] = ""
			case "password":
				out["password"] = ""
			case "trust-disabled":
				out["tls"].(map[string]any)["enabled"] = false
			case "trust-insecure":
				out["tls"].(map[string]any)["insecure"] = true
			case "sni":
				out["tls"].(map[string]any)["server_name"] = "another.test"
			case "certificate-path":
				out["tls"].(map[string]any)["certificate_path"] = "foreign.pem"
			case "extra-outbound":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct"})
			case "foreign-final":
				graph["route"].(map[string]any)["final"] = "direct"
			}
			raw, _ := json.Marshal(graph)
			files := map[string]string{"sing-box.json": base64.StdEncoding.EncodeToString(raw), "cert.pem": base64.StdEncoding.EncodeToString(cert)}
			if fault == "missing-ca" {
				delete(files, "cert.pem")
			}
			if fault == "extra-source" {
				files["foreign.pem"] = files["cert.pem"]
			}
			encoded, _ := json.Marshal(files)
			assets, err := pairedNaiveH2Assets(string(encoded), endpoint, "connect")
			if (err == nil) != (fault == "original") {
				t.Fatal("Naive H2 private source substitution verdict changed", fault, err)
			}
			if fault == "original" && (!bytes.Equal(assets["sing-box.json"], raw) || !bytes.Equal(assets["cert.pem"], cert)) {
				t.Fatal("positive Naive H2 installation reserialized private original bytes")
			}
		})
	}
}

func TestDesktopUnixNaiveH2PeerReceiptRefusesForeignLower(t *testing.T) {
	for _, fault := range []string{"original", "raw-udp", "protocol-udp-lower", "foreign-address", "foreign-base", "outer-source", "borrowed-source", "websocket", "mux"} {
		t.Run(fault, func(t *testing.T) {
			v := map[string]any{"schema": 1, "address": "192.0.2.17:24443", "base_address": "192.0.2.17:24443", "protocol_files": "captured-original-files"}
			original := &pairedNaiveH2Peer{Address: netip.MustParseAddrPort("192.0.2.17:24443"), Base: netip.MustParseAddrPort("192.0.2.17:24443"), Files: "captured-original-files"}
			switch fault {
			case "raw-udp":
				v["raw_udp"] = 1
			case "protocol-udp-lower":
				v["protocol_raw_udp"] = 1
			case "foreign-address":
				v["address"] = "192.0.2.18:24443"
			case "foreign-base":
				v["base_address"] = "192.0.2.17:24444"
			case "outer-source":
				v["aes_address"] = "192.0.2.17:24445"
			case "borrowed-source":
				v["protocol_files"] = "borrowed-files"
			case "websocket":
				v["protocol_websocket"] = 1
			case "mux":
				v["protocol_mux"] = 1
			}
			raw, _ := json.Marshal(v)
			_, err := pairedNaiveH2Read(raw, netip.MustParseAddr("192.0.2.17"), "", original)
			if (err == nil) != (fault == "original") {
				t.Fatal("Naive H2 peer receipt substitution verdict changed", fault, err)
			}
		})
	}
}
