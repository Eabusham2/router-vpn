package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const testServerPublicKey = "KfD3x0SHtHE3yKqC7kLQ1LxJgq2o7jYy6h8e0W9Zx1A="

func writeTestWGIdentity(t *testing.T, root, profileID string) string {
	t.Helper()
	dir := filepath.Join(root, "generated", profileID, "wg")
	if err := os.MkdirAll(dir, 0o700); err != nil { t.Fatal(err) }
	wg := fmt.Sprintf("[Interface]\nPrivateKey = ignored\nAddress = 10.77.0.2/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\n", testServerPublicKey)
	if err := os.WriteFile(filepath.Join(dir, "wg.conf"), []byte(wg), 0o600); err != nil { t.Fatal(err) }
	digest := sha256.Sum256([]byte(nodeProofDomain + testServerPublicKey))
	return hex.EncodeToString(digest[:])
}

func TestNodeProofIDFromWGConfig(t *testing.T) {
	wg := []byte("[Interface]\nPrivateKey=x\n[Peer]\nPublicKey = " + testServerPublicKey + "\n")
	got, err := nodeProofIDFromWGConfig(wg)
	if err != nil { t.Fatal(err) }
	digest := sha256.Sum256([]byte(nodeProofDomain + testServerPublicKey))
	want := hex.EncodeToString(digest[:])
	if got != want { t.Fatalf("derived node proof mismatch: got %s want %s", got, want) }
}

func TestValidateSelectedNodeProofRequiresExactIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := common.RouterProfile{ID: "router-test"}
	expected := writeTestWGIdentity(t, root, profile.ID)

	good := []byte(fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, expected, desktopNodeProofKind))
	if err := validateSelectedNodeProof(profile, good); err != nil { t.Fatalf("valid proof rejected: %v", err) }

	for name, body := range map[string][]byte{
		"ok-only": []byte(`{"ok":true}`),
		"wrong-node": []byte(fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, strings.Repeat("0",64), desktopNodeProofKind)),
		"wrong-kind": []byte(fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":"other"}`, expected)),
		"not-ok": []byte(fmt.Sprintf(`{"ok":false,"node_id":%q,"proof":%q}`, expected, desktopNodeProofKind)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSelectedNodeProof(profile, body); err == nil { t.Fatal("invalid path proof accepted") }
		})
	}
}

func TestExpectedNodeProofCrossChecksPersistedIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := common.RouterProfile{ID: "router-test"}
	expected := writeTestWGIdentity(t, root, profile.ID)
	profile.NodeProofID = expected
	if got, err := expectedNodeProofID(profile); err != nil || got != expected { t.Fatalf("matching persisted proof rejected: got=%q err=%v", got, err) }
	profile.NodeProofID = strings.Repeat("0", 64)
	if _, err := expectedNodeProofID(profile); err == nil { t.Fatal("persisted proof mismatch accepted") }
}
