package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

func compileServerNodeChainPrefix(input io.Reader, output io.Writer, plan bool) error {
	bad := errors.New("invalid private ordered prefix pairing source")
	raw, err := io.ReadAll(io.LimitReader(input, mobilemultihop.NodeChainInputLimit+4097))
	if err != nil || len(raw) == 0 || len(raw) > mobilemultihop.NodeChainInputLimit+4096 {
		return bad
	}
	defer clear(raw)
	var policy *mobilemultihop.NodeChainServerPrefixPolicy
	if plan {
		policy, err = mobilemultihop.NewNodeChainServerPrefixPlan(string(raw))
	} else {
		object, e := applexray.Object(raw)
		if e != nil || len(object) != 2 {
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
		body, e := json.Marshal(source)
		if e != nil || len(body) > mobilemultihop.NodeChainInputLimit {
			return bad
		}
		defer clear(body)
		policy, err = mobilemultihop.NewNodeChainServerPrefixPolicy(string(body))
		if err != nil {
			return bad
		}
		descriptor, e := policy.Descriptor()
		if e != nil || descriptor.EntryNodeID != node {
			return bad
		}
	}
	if err != nil || policy == nil {
		return bad
	}
	descriptor, err := policy.Descriptor()
	if err != nil {
		return bad
	}
	result := struct {
		SourceJSON string                                  `json:"source_json"`
		Reference  multihoprelay.NodeChainPrefixDescriptor `json:"reference"`
	}{policy.Source(), descriptor}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > 2*mobilemultihop.NodeChainInputLimit+4096 {
		return bad
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	count, err := output.Write(encoded)
	if err == nil && count != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}

func compileServerNodeChainPrefixCatalog(input io.Reader, output io.Writer) error {
	bad := errors.New("invalid private ordered prefix catalog")
	raw, err := io.ReadAll(io.LimitReader(input, mobilemultihop.NodeChainInputLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > mobilemultihop.NodeChainInputLimit {
		return bad
	}
	defer clear(raw)
	catalog, err := mobilemultihop.NewNodeChainServerPrefixCatalog(string(raw))
	if err != nil || catalog == nil {
		return bad
	}
	result := struct {
		SourceJSON string                                        `json:"source_json"`
		Reference  multihoprelay.NodeChainPrefixCatalogReference `json:"reference"`
	}{catalog.Source(), catalog.Reference()}
	if result.Reference.Validate() != nil {
		return bad
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > 2*mobilemultihop.NodeChainInputLimit+4096 {
		return bad
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	count, err := output.Write(encoded)
	if err == nil && count != len(encoded) {
		return io.ErrShortWrite
	}
	return err
}
