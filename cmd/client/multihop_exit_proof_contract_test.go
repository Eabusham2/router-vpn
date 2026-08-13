package main

import (
	"os"
	"strings"
	"testing"
)

// Multihop must prove the exact selected exit node, not merely accept a private
// Router VPN health response containing {"ok":true}. The same immutable node
// identity binding used by normal desktop connects must protect the exit proof.
func TestMultihopExitProofBindsExactSelectedNode(t *testing.T) {
	body, err := os.ReadFile("multihop.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "validateSelectedNodeProof(exit, body)") {
		t.Fatal("multihop exit proof is not bound to the exact selected exit node identity")
	}
	if strings.Contains(source, `payload["ok"] == true`) {
		t.Fatal("multihop exit proof still accepts generic ok=true without exact exit identity")
	}
}
