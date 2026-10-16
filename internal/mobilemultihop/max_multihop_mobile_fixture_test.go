package mobilemultihop

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Export raw generated assets, not precomputed answers, for both actual host
// compilers. The keys are structural fixtures; native traffic has separate keys.
func TestExportMAXMultihopMobileProfiles(t *testing.T) {
	result := map[string]any{}
	key := func(c byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{c}, 32)) }
	for _, role := range []string{"entry", "exit"} {
		profiles := map[string]any{}
		pub, priv, psk, host, service, pqByte := byte('a'), byte('j'), byte('h'), "192.0.2.44", "10.77.0.1", byte(1)
		if role == "exit" {
			pub, priv, psk, host, service, pqByte = 'b', 'k', 'i', "198.51.100.44", "10.88.0.1", 4
		}
		nodeHash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + key(pub)))
		node := hex.EncodeToString(nodeHash[:])
		for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
			files, policy := maxFixture(t, mode)
			changes := strings.NewReplacer(key('a'), key(priv), key('b'), key(pub), key('c'), key(psk), "192.0.2.44", host, "10.77.0.2", strings.TrimSuffix(service, "1")+"2", "10.77.0.1", service, "10.78.0.1", service)
			for name, encoded := range files {
				if strings.HasPrefix(name, "rosenpass-") || name == "rosenpass.toml" {
					continue
				}
				raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				files[name] = base64.StdEncoding.EncodeToString([]byte(changes.Replace(string(raw))))
			}
			files["rosenpass-client-secret"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{pqByte}, 64))
			files["rosenpass-client-public"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{pqByte + 1}, 128))
			files["rosenpass-server-public"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{pqByte + 2}, 128))
			var metadata map[string]any
			if err := json.Unmarshal([]byte(policy), &metadata); err != nil {
				t.Fatal(err)
			}
			metadata["node_id"], metadata["endpoint"], metadata["router_api"] = node, host, "http://"+service+":8787"
			for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				metadata["start_layer"] = layer
				raw, _ := json.Marshal(metadata)
				graph, err := CompileMAXProfile(mode, pqEncoded(files), string(raw))
				if err != nil {
					t.Fatal(role, mode, layer, err)
				}
				temporary, err := MAXMultihopBase(graph, mode, node, layer)
				if err != nil {
					t.Fatal("actual complete-profile base", role, mode, layer, err)
				}
				if !strings.Contains(temporary, `"type":"routervpn-pq"`) {
					t.Fatal("base protocol was not preserved")
				}
			}
			metadata["start_layer"] = "off"
			profiles[mode] = map[string]any{"files": files, "policy": metadata}
		}
		result[role] = profiles
	}
	if path := os.Getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES"); path != "" {
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
