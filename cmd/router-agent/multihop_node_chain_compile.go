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
	policy, err := mobilemultihop.NewNodeChainServerPolicy(string(body))
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
	policy, err := mobilemultihop.NewNodeChainServerPlan(string(raw))
	if err != nil {
		return bad
	}
	return writeServerNodeChainSource(output, policy)
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
