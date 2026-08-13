package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleGeneratorEmbedsStableNodeProof(t *testing.T) {
	root := filepath.Join("..", "..")
	bundle, err := os.ReadFile(filepath.Join(root, "server", "scripts", "create-bundle-json.py"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(bundle)
	for _, marker := range []string{
		"ensure-node-proof.py",
		"'node_proof_id':node_proof_id",
		"'nodeProofId':node_proof_id",
		"re.fullmatch(r'[0-9a-f]{64}',node_proof_id)",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("bundle generator lost node proof marker %q", marker)
		}
	}
}

func TestNodeProofDerivesOnlyFromWireGuardServerPublicIdentity(t *testing.T) {
	root := filepath.Join("..", "..")
	helper, err := os.ReadFile(filepath.Join(root, "server", "scripts", "ensure-node-proof.py"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(helper)
	for _, marker := range []string{
		"router-vpn-node-proof-v1\\n",
		"WireGuard server public key",
		"config[\"node_id\"] = node_id",
		"os.chmod(AGENT_CONFIG, 0o600)",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("node proof helper lost marker %q", marker)
		}
	}
	for _, forbidden := range []string{"PrivateKey", "private_key", "WG_SERVER_PRIV"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("node proof helper must not derive from server private key: found %q", forbidden)
		}
	}
}
