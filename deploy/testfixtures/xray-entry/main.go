//go:build go1.24

// Command xray-entry emits public, deterministic test fixtures. It does not
// start an engine, open a socket or read any user configuration.
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"router-vpn/internal/mobilemultihop"
)

func encode(v any) (string, error) {
	b, e := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(b), e
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	key, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		return err
	}
	pq, err := mlkem.NewDecapsulationKey768(make([]byte, 64))
	if err != nil {
		return err
	}
	entries := map[string]json.RawMessage{}
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		user := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision", "encryption": "none"}
		stream := map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": "entry.example.test", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "0123456789abcdef"}}
		if mode != "reality-vision" {
			user["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
		}
		if mode == "reality-xhttp" {
			delete(user, "flow")
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{"path": "/entry-authenticated", "mode": "auto"}
			stream["finalmask"] = map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}}
		}
		raw := map[string]any{"inbounds": []any{map[string]any{"protocol": "socks", "listen": "127.0.0.1", "port": 1090, "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "vless", "tag": "proxy", "settings": map[string]any{"vnext": []any{map[string]any{"address": "192.0.2.11", "port": 443, "users": []any{user}}}}, "streamSettings": stream}}}
		wrapper := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1090, "version": "5"}}, "route": map[string]any{"final": "proxy"}}
		original, e := encode(raw)
		if e != nil {
			return e
		}
		outer, e := encode(wrapper)
		if e != nil {
			return e
		}
		profile, e := json.Marshal(map[string]string{"sing-box.json": outer, "xray.json": original})
		if e != nil {
			return e
		}
		result, e := mobilemultihop.CompileProxyEntry(string(profile), mode)
		if e != nil {
			return e
		}
		entries[mode] = json.RawMessage(result)
	}
	return json.NewEncoder(os.Stdout).Encode(entries)
}
