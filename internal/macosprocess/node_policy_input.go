package macosprocess

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const NodePolicyInputLimit = 1024

// NodePolicyInput is captured derivation input, never proof or native authority.
// The inherited input manifest binds its bytes. The child must independently
// recompile the original NodeProfile and compare its derived source and graph.
type NodePolicyInput struct {
	Schema      int `json:"schema"`
	RestoredMTU int `json:"restored_mtu"`
}

func (p NodePolicyInput) valid() bool {
	return p.Schema == 1 && (p.RestoredMTU == 0 || p.RestoredMTU >= 1280 && p.RestoredMTU <= 9000)
}

func MarshalNodePolicyInput(restoredMTU int) ([]byte, error) {
	p := NodePolicyInput{Schema: 1, RestoredMTU: restoredMTU}
	if !p.valid() {
		return nil, errors.New("paired-node derivation input has an invalid restored MTU")
	}
	return json.Marshal(p)
}

func ParseNodePolicyInput(raw []byte) (NodePolicyInput, error) {
	bad := errors.New("paired-node derivation input is not its complete canonical capture")
	var p NodePolicyInput
	if len(raw) == 0 || len(raw) > NodePolicyInputLimit {
		return p, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !p.valid() {
		return NodePolicyInput{}, bad
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return NodePolicyInput{}, bad
	}
	canonical, err := json.Marshal(p)
	// Canonical comparison also rejects omitted, duplicate and null fields,
	// reordered keys, alternate integer spellings and surrounding documents.
	if err != nil || !bytes.Equal(raw, canonical) {
		return NodePolicyInput{}, bad
	}
	return p, nil
}
