package mobilemultihop

import (
	"errors"
	"reflect"
)

// The optional identity inventory belongs to the same ordered source as its
// selected transports. Callers which supply it must capture every original
// standard-WG asset map, including a matching split-route source when present.
// An AWG server key can differ from this durable Router identity. This parser
// validates the original WG peer; it never replaces the selected transport or
// opens a second native endpoint. The complete original bytes stay in the
// chain source and therefore its launch, source digest and projection seal.
func validateNodeChainIdentity(source string, node *NodeProfile) error {
	bad := errors.New("ordered node lost its original standard WireGuard identity source")
	if node == nil {
		return bad
	}
	files, err := nodeProfileAssets(source)
	if err != nil {
		return bad
	}
	defer clearNodeChainIdentityAssets(files)
	raw, err := NativeBaseSourceForEndpoint("wg", files, predecessorText(node.profile, "endpoint"))
	if err != nil {
		return bad
	}
	if _, err := parseWireGuardProfile(string(raw), predecessorText(node.profile, "node_proof_id")); err != nil {
		return bad
	}
	if node.mode == "wg" {
		selected, err := nodeProfileAssets(node.inputs.Files)
		if err != nil {
			return bad
		}
		defer clearNodeChainIdentityAssets(selected)
		if !reflect.DeepEqual(files, selected) {
			return bad
		}
	}
	return nil
}

func clearNodeChainIdentityAssets(files map[string][]byte) {
	for _, raw := range files {
		clear(raw)
	}
}
