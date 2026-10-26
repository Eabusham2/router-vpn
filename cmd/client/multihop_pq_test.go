package main

import (
	"bytes"
	"strings"
	"testing"
)

// These bounded synthetic bytes exercise captured-source validation only. The
// separate native traffic gate generates real pinned-Rust KEM keys and performs
// the actual negotiation; structural acceptance is not cryptographic proof.
func nativeMultihopPQAssets(t *testing.T, mode string, packet map[string][]byte, peer string) map[string][]byte {
	t.Helper()
	tool := "wg"
	if mode == "awg2-pq" {
		tool = "awg"
	}
	assets := map[string][]byte{}
	for name, raw := range packet {
		assets[name] = []byte(strings.ReplaceAll(string(raw), testWGKey('p'), testWGKey('v')))
	}
	assets["rosenpass-client-secret"] = bytes.Repeat([]byte{1}, 64)
	assets["rosenpass-client-public"] = bytes.Repeat([]byte{2}, 128)
	assets["rosenpass-server-public"] = bytes.Repeat([]byte{3}, 128)
	assets["rosenpass.env"] = []byte("ROSENPASS_TOOL=" + tool + "\nROSENPASS_INTERFACE=" + tool + "\nROSENPASS_WG_PEER=" + peer + "\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n")
	assets["rosenpass.toml"] = []byte("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"captured-router.example:51822\"\nkey_out = \"rosenpass.psk\"\n")
	return assets
}
