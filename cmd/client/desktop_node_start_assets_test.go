package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopNodeStartAssetsMAXKeepsEmbeddedOwner(t *testing.T) {
	for _, mode := range []string{"max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				profile, _ := desktopNodeFixture(t, "198.51.100.8")
				profile.StartLayer = layer
				files := nativeEntryMAXAssets(t, profile, mode)
				before := encodeDesktopNodeAssets(files)
				root := t.TempDir()
				other := filepath.Join(root, "generated", profile.ID, "shadowsocks")
				if err := os.MkdirAll(other, 0700); err != nil {
					t.Fatal(err)
				}
				unrelated := []byte("another selected mode has no valid Start Layer here\n")
				if err := os.WriteFile(filepath.Join(other, "sing-box.json"), unrelated, 0600); err != nil {
					t.Fatal(err)
				}
				start, err := readDesktopNodeStartAssets(root, profile, mode)
				if err != nil || start != nil {
					t.Fatal("MAX borrowed a separate Start Layer owner", err)
				}
				compiled, endpoint, err := compileDesktopNode(context.Background(), profile, mode, files, start, nil)
				if err != nil || endpoint != profile.Endpoint || encodeDesktopNodeAssets(files) != before {
					t.Fatal("captured MAX lost its complete original source", err)
				}
				var graph map[string]any
				if err := json.Unmarshal([]byte(compiled.Config()), &graph); err != nil {
					t.Fatal(err)
				}
				var aes map[string]any
				for _, raw := range graph["outbounds"].([]any) {
					out := raw.(map[string]any)
					if out["tag"] == mobilemultihop.MAXStartLayerTag {
						aes = out
					}
				}
				if layer == "off" {
					if aes != nil {
						t.Fatal("MAX Off created an unrequested Start Layer")
					}
				} else {
					kind, port := "shadowsocks", float64(8388)
					if layer == "aes-256-gcm+xor-whitening" {
						kind, port = "routervpn-aes-xor", 8389
					}
					if aes == nil || aes["type"] != kind || aes["server"] != endpoint || aes["server_port"] != port ||
						aes["method"] != mobilemultihop.NativeStartLayerMethod || aes["password"] != testWGKey('s') {
						t.Fatal("MAX changed its captured Start Layer transport or original chain credential")
					}
				}
				after, err := os.ReadFile(filepath.Join(other, "sing-box.json"))
				if err != nil || !bytes.Equal(after, unrelated) {
					t.Fatal("MAX changed another mode's private source", err)
				}
			})
		}
	}
}

func TestDesktopNodeStartAssetsSeparateOwnerStillRequired(t *testing.T) {
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	root := t.TempDir()
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		profile.StartLayer = layer
		if _, err := readDesktopNodeStartAssets(root, profile, "wg"); err == nil {
			t.Fatal("ordinary base accepted a missing selected Start Layer source")
		}
	}
	profile.StartLayer = "aes-256-gcm+xor-whitening"
	directory := filepath.Join(root, "generated", profile.ID, "shadowsocks")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	aes := desktopOwnedNodePreparationAES(t, profile.Endpoint)
	if err := os.WriteFile(filepath.Join(directory, "sing-box.json"), aes["sing-box.json"], 0600); err != nil {
		t.Fatal(err)
	}
	start, err := readDesktopNodeStartAssets(root, profile, "wg")
	if err != nil || !bytes.Equal(start["sing-box.json"], aes["sing-box.json"]) {
		t.Fatal("ordinary base lost its exact selected Start Layer source", err)
	}
	if _, _, err := compileDesktopNode(context.Background(), profile, "wg", files, start, nil); err != nil {
		t.Fatal("ordinary captured Start Layer no longer compiles", err)
	}
	if self, err := readDesktopNodeStartAssets(root, profile, "shadowsocks"); err != nil || self != nil {
		t.Fatal("Shadowsocks borrowed a duplicate Start Layer owner", err)
	}
}
