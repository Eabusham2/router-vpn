// Command pq-exit emits deterministic, public configuration-test fixtures.
// Key sizes are structural policy fixtures, not valid cryptographic peer assets;
// no protocol handle, socket, or user configuration is used by this command.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"router-vpn/internal/mobilemultihop"
	"strings"
)

func run() error {
	if len(os.Args) != 1 {
		return fmt.Errorf("pq-exit accepts no arguments")
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + key(2)))
	node := hex.EncodeToString(hash[:])
	results := map[string]any{}
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		tool, asset := "wg", "wg.conf"
		raw := "[Interface]\nAddress=10.88.0.2/32,fd88:88::2/128\nPrivateKey=" + key(3) + "\nDNS=10.77.0.1\nMTU=1400\n[Peer]\nPublicKey=" + key(2) + "\nPresharedKey=" + key(4) + "\nEndpoint=198.51.100.2:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
		if mode == "awg2-pq" {
			tool, asset = "awg", "awg.conf"
			raw = strings.Replace(raw, "[Peer]", "Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]", 1)
		}
		files := map[string][]byte{asset: []byte(raw), "rosenpass-client-secret": bytes.Repeat([]byte{7}, 64), "rosenpass-client-public": bytes.Repeat([]byte{8}, 128), "rosenpass-server-public": bytes.Repeat([]byte{9}, 128), "rosenpass.env": []byte("ROSENPASS_TOOL=" + tool + "\nROSENPASS_INTERFACE=" + tool + "\nROSENPASS_WG_PEER=" + key(2) + "\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"), "rosenpass.toml": []byte("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"fixture.example.test:51822\"\nkey_out = \"rosenpass.psk\"\n")}
		data, err := json.Marshal(files)
		if err != nil {
			return err
		}
		config, err := mobilemultihop.CompilePQProfile(mode, string(data), node)
		if err != nil {
			return err
		}
		results[mode] = map[string]any{"node": node, "config": json.RawMessage(config)}
	}
	return json.NewEncoder(os.Stdout).Encode(results)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
