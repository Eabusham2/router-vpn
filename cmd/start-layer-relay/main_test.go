package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeKeyConfig(t *testing.T, method, password string, second bool) string {
	t.Helper()
	outbounds := []map[string]any{
		{
			"type":        "shadowsocks",
			"tag":         "proxy",
			"server":      "198.51.100.7",
			"server_port": 8388,
			"method":      method,
			"password":    password,
		},
		{"type": "direct", "tag": "direct"},
	}
	if second {
		outbounds = append(outbounds, map[string]any{
			"type":        "shadowsocks",
			"tag":         "second",
			"server":      "198.51.100.8",
			"server_port": 8388,
			"method":      method,
			"password":    password,
		})
	}
	doc := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"dns":       map[string]any{"servers": []any{}},
		"route":     map[string]any{"rules": []any{}},
		"outbounds": outbounds,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestDeriveKeyUsesOnlyAES256GCMShadowsocks2022(t *testing.T) {
	path := writeKeyConfig(t, "2022-blake3-aes-256-gcm", "0123456789abcdef0123456789abcdef", false)
	first, err := deriveKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same private SS2022 secret produced different whitening keys")
	}
	if first == ([32]byte{}) {
		t.Fatal("derived whitening key is all zero")
	}
}

func TestDeriveKeyRejectsNonAESOrAmbiguousConfig(t *testing.T) {
	wrong := writeKeyConfig(t, "2022-blake3-chacha20-poly1305", "0123456789abcdef0123456789abcdef", false)
	if _, err := deriveKey(wrong); err == nil {
		t.Fatal("non-AES Shadowsocks method was accepted for AES start layer")
	}
	ambiguous := writeKeyConfig(t, "2022-blake3-aes-256-gcm", "0123456789abcdef0123456789abcdef", true)
	if _, err := deriveKey(ambiguous); err == nil {
		t.Fatal("ambiguous multi-Shadowsocks key config was accepted")
	}
}

func TestDeriveKeyRejectsUnsafePrivateFile(t *testing.T) {
	path := writeKeyConfig(t, "2022-blake3-aes-256-gcm", "0123456789abcdef0123456789abcdef", false)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := deriveKey(path); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("weak private-file permissions were not rejected: %v", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	link := filepath.Join(filepath.Dir(path), "key-link.json")
	if err := os.Symlink(path, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable on this Windows runner: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := deriveKey(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink key config was not rejected: %v", err)
	}
}

func TestXORWhiteningRoundTrip(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	plain := []byte("already authenticated AES-GCM ciphertext placeholder")
	var encoded bytes.Buffer
	writer := &xorWriter{w: &encoded, key: key}
	if _, err := writer.Write(plain[:17]); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain[17:]); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded.Bytes(), plain) {
		t.Fatal("XOR whitening did not change the byte stream")
	}
	reader := &xorReader{r: bytes.NewReader(encoded.Bytes()), key: key}
	decoded := make([]byte, len(plain))
	if _, err := reader.Read(decoded[:11]); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(decoded[11:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("round trip mismatch: got %q want %q", decoded, plain)
	}
}
