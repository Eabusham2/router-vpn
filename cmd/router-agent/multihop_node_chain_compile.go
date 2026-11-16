package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// compileServerNodeChainSource uses the same data-only compiler as the native
// worker. Both pipes belong to the private administrator command; a public
// descriptor or authenticated client lease cannot install this source.
func compileServerNodeChainSource(input io.Reader, output io.Writer) error {
	bad := errors.New("invalid private ordered server pairing source")
	const inputLimit = mobilemultihop.NodeChainInputLimit + 4096
	raw, err := io.ReadAll(io.LimitReader(input, inputLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > inputLimit {
		return bad
	}
	defer clear(raw)
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 2 {
		return bad
	}
	node, ok := object["entry_node_id"].(string)
	if !ok {
		return bad
	}
	source, ok := object["source"].(map[string]any)
	if !ok {
		return bad
	}
	body, err := json.Marshal(source)
	if err != nil || len(body) > mobilemultihop.NodeChainInputLimit {
		return bad
	}
	defer clear(body)
	policy, err := parsePrivateNodeChainServerSource(body)
	if err != nil || policy.Descriptor().EntryNodeID != node {
		return bad
	}
	return writeServerNodeChainSource(output, policy)
}

func compileServerNodeChainPlan(input io.Reader, output io.Writer) error {
	bad := errors.New("invalid private ordered server bundle plan")
	raw, err := io.ReadAll(io.LimitReader(input, mobilemultihop.NodeChainInputLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > mobilemultihop.NodeChainInputLimit {
		return bad
	}
	defer clear(raw)
	connect, err := privateNodeChainCONNECTInput(raw)
	if err != nil {
		return bad
	}
	var policy *mobilemultihop.NodeChainServerPolicy
	if privateNodeChainOpenVPNInput(raw) {
		policy, err = mobilemultihop.NewNodeChainOpenVPNServerPlan(string(raw))
	} else if privateNodeChainSOCKSInput(raw) {
		policy, err = mobilemultihop.NewNodeChainSOCKSServerPlan(string(raw))
	} else if connect {
		policy, err = mobilemultihop.NewNodeChainCONNECTServerPlan(string(raw))
	} else {
		policy, err = mobilemultihop.NewNodeChainServerPlan(string(raw))
	}
	if err != nil {
		return bad
	}
	return writeServerNodeChainSource(output, policy)
}

// Schema selects a distinct typed compiler; it grants no source or transport
// authority itself. A rejected SOCKS or CONNECT source never falls back to the paired
// or imported-SS compiler. The installed reader uses this same dispatch.
func parsePrivateNodeChainServerSource(raw []byte) (*mobilemultihop.NodeChainServerPolicy, error) {
	connect, err := privateNodeChainCONNECTInput(raw)
	if err != nil {
		return nil, err
	}
	if privateNodeChainOpenVPNInput(raw) {
		return mobilemultihop.NewNodeChainOpenVPNServerPolicy(string(raw))
	}
	if privateNodeChainSOCKSInput(raw) {
		return mobilemultihop.NewNodeChainSOCKSServerPolicy(string(raw))
	}
	if connect {
		return mobilemultihop.NewNodeChainCONNECTServerPolicy(string(raw))
	}
	return mobilemultihop.NewNodeChainServerPolicy(string(raw))
}

func privateNodeChainSOCKSInput(raw []byte) bool {
	var header struct {
		Schema json.RawMessage `json:"schema"`
	}
	return len(raw) > 0 && len(raw) <= mobilemultihop.NodeChainInputLimit && json.Unmarshal(raw, &header) == nil && string(header.Schema) == "3"
}

func privateNodeChainCONNECTInput(raw []byte) (bool, error) {
	var header struct {
		Schema json.RawMessage `json:"schema"`
	}
	if len(raw) == 0 || len(raw) > mobilemultihop.NodeChainInputLimit || json.Unmarshal(raw, &header) != nil {
		return false, errors.New("invalid private ordered server pairing source")
	}
	// Only select here. The original typed compiler still rejects duplicate,
	// unknown and malformed fields under the full ordered-source byte bound.
	return string(header.Schema) == "4", nil
}

func writeServerNodeChainSource(output io.Writer, policy *mobilemultihop.NodeChainServerPolicy) error {
	bad := errors.New("invalid private ordered server pairing source")
	if policy == nil {
		return bad
	}
	result := struct {
		SourceJSON string                            `json:"source_json"`
		Reference  multihoprelay.NodeChainDescriptor `json:"reference"`
	}{SourceJSON: policy.Source(), Reference: policy.Descriptor()}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > 2*mobilemultihop.NodeChainInputLimit+4096 {
		return bad
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	n, err := output.Write(encoded)
	if err == nil && n != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}

func privateNodeChainOpenVPNInput(raw []byte) bool {
	var header struct {
		Schema json.RawMessage `json:"schema"`
	}
	return len(raw) > 0 && len(raw) <= mobilemultihop.NodeChainInputLimit && json.Unmarshal(raw, &header) == nil && string(header.Schema) == "5"
}
