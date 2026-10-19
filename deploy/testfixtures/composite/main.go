//go:build go1.24

// Command composite emits public two-node profile assets for the shipping
// Java/Swift compiler harnesses. It never starts a runtime or opens a socket.
package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"router-vpn/internal/nativecomposite"
)

func encoded(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	exit := len(os.Args) == 2 && os.Args[1] == "--exits"
	if len(os.Args) > 1 && !exit {
		return fmt.Errorf("usage: composite [--exits]")
	}
	seed, pqSeed := make([]byte, 32), make([]byte, 64)
	id, host, api, name := "entry", "192.0.2.11", "http://10.77.0.1:8787", "entry.example.test"
	if exit {
		seed[1], pqSeed[0] = 7, 9
		id, host, api, name = "exit", "198.51.100.22", "http://10.88.0.1:8787", "exit.example.test"
	}
	key, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return err
	}
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	proof := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
	nodeID := hex.EncodeToString(proof[:])
	pq, err := mlkem.NewDecapsulationKey768(pqSeed)
	if err != nil {
		return err
	}
	certificateKey := ed25519.NewKeyFromSeed(seed)
	spec := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, spec, spec, certificateKey.Public(), certificateKey)
	if err != nil {
		return err
	}
	cert := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	secret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(id[:1], 32)))
	aes := map[string]any{
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280, "address": []string{"172.29.94.1/30", "fd29:94::1/126"}}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": host, "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": secret}},
		"route":     map[string]any{"final": "proxy"},
	}
	profiles := map[string]map[string]string{"shadowsocks": {"sing-box.json": encoded(aes)}}
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		helperPort, helperName := 1090, "xray.json"
		user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
		if exit {
			user["id"] = "22222222-2222-4222-8222-222222222222"
		}
		if mode == "max" {
			user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
		}
		helper := map[string]any{"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 1090, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": 24443, "users": []any{user}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": name, "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "0123456789abcdef"}}}}}
		if mode == "ss-v2ray" {
			helperPort, helperName = 1092, "sslocal.json"
			helper = map[string]any{"server": host, "server_port": 10443, "method": "2022-blake3-aes-256-gcm", "password": secret, "local_address": "127.0.0.1", "local_port": helperPort, "mode": "tcp_only", "plugin": "v2ray-plugin", "plugin_opts": "tls;host=" + name + ";path=/shadowsocks"}
		}
		graph := map[string]any{
			"inbounds":  []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280, "address": []string{"172.29.94.1/30", "fd29:94::1/126"}}},
			"outbounds": []any{map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": helperPort, "version": "5"}, map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": host, "server_port": 8443, "password": id + "-hysteria-secret", "obfs": map[string]any{"type": "salamander", "password": id + "-mask"}, "tls": map[string]any{"enabled": true, "server_name": name, "certificate_path": "cert.pem"}}},
			"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "home-dns", "server": "10.77.0.1", "server_port": 53, "detour": "tcp-stack"}}, "final": "home-dns"},
			"route":     map[string]any{"final": "tcp-stack", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"}, map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"}}},
		}
		assets := map[string]string{"sing-box.json": encoded(graph), helperName: encoded(helper), "cert.pem": cert}
		if mode != "ss-v2ray" {
			assets["stack.json"] = encoded(map[string]any{"name": "Dual Transport", "transport": "both", "post_quantum": mode == "max", "shared_layers": []string{"single TUN interface"}, "tcp_stack": []string{"VLESS", "REALITY", "XTLS Vision"}, "udp_stack": []string{"Hysteria2", "QUIC", "TLS 1.3"}})
		}
		profiles[mode] = assets
		// Fail the generator itself if its raw assets no longer match the actual
		// compiler, including every supported same-node encryption option.
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			metadata, _ := json.Marshal(map[string]any{"node_id": nodeID, "node_kind": "router-vpn", "router_api": api, "start_layer": layer})
			source, _ := json.Marshal(assets)
			start := ""
			if layer != "" {
				raw, _ := json.Marshal(profiles["shadowsocks"])
				start = string(raw)
			}
			if _, err := nativecomposite.Compile(mode, string(source), string(metadata), start); err != nil {
				return err
			}
		}
	}
	dns := "10.77.0.1"
	if exit {
		dns = "10.88.0.1"
	}
	profile := map[string]any{"id": id, "name": id + " fixture", "node_kind": "router-vpn", "node_proof_id": nodeID, "endpoint": host, "router_api": api, "api_token": id + "-fixture-token", "adguard_ipv4": dns, "start_layer": "off"}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"selectedRouterID": id, "nodeProofId": nodeID, "routerProfiles": []any{profile}, "profiles": profiles})
}
