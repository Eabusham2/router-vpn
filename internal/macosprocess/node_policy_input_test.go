package macosprocess

import (
	"reflect"
	"strings"
	"testing"
)

func TestNodePolicyInputRetainsCapturedMTUAndManifest(t *testing.T) {
	for _, mtu := range []int{0, 1280, 1420, 9000} {
		raw, err := MarshalNodePolicyInput(mtu)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseNodePolicyInput(raw)
		if err != nil || parsed != (NodePolicyInput{1, mtu}) {
			t.Fatal("changed original MTU", err)
		}
	}
	manifest, err := (Scope{Family: NodeFamily}).inputManifest()
	want := []scopeInput{{"node-source.json", 40 << 20}, {"node-policy.json", NodePolicyInputLimit}, {"sing-box.json", 4 << 20}}
	if err != nil || !reflect.DeepEqual(manifest, want) || NodeFamily.protocolSchema() != 2 {
		t.Fatal("paired-node private manifest changed", err)
	}
	manifest[0].name = "capture.json"
	again, _ := (Scope{Family: NodeFamily}).inputManifest()
	if !reflect.DeepEqual(again, want) {
		t.Fatal("caller replaced original manifest")
	}
}

func TestNodePolicyInputRefusesIncompleteOrSubstitutedCapture(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"schema":1}`, `{"restored_mtu":0}`, `{"schema":2,"restored_mtu":0}`,
		`{"schema":1,"restored_mtu":null}`, `{"schema":1,"restored_mtu":0,"extra":1}`,
		`{"schema":1,"restored_mtu":0,"restored_mtu":1420}`, `{"schema":1,"schema":1,"restored_mtu":0}`,
		`{"schema":1,"restored_mtu":0.0}`, `{"schema":1,"restored_mtu":-1}`,
		`{"schema":1,"restored_mtu":1279}`, `{"schema":1,"restored_mtu":9001}`,
		`{"schema":1,"restored_mtu":"1420"}`, `{"schema":1,"restored_mtu":1420} {}`,
		`{"restored_mtu":1420,"schema":1}`, strings.Repeat(" ", NodePolicyInputLimit+1),
	} {
		if parsed, err := ParseNodePolicyInput([]byte(raw)); err == nil || parsed != (NodePolicyInput{}) {
			t.Fatal("malformed or noncanonical derivation input was accepted")
		}
	}
}
