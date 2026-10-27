package main

import (
	"encoding/json"
	"errors"
	"io"

	"router-vpn/internal/applexray"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/multihoprelay"
)

// compileServerTorSource shares the worker's data-only policy compiler. The
// input and output are operator-private pipes; no source, bridge or resolver is
// accepted through a lease or copied into a public capability response.
func compileServerTorSource(input io.Reader, output io.Writer) error {
	bad := errors.New("invalid private server Tor pairing source")
	raw, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 {
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
	if err != nil {
		return bad
	}
	defer clear(body)
	policy, err := mobiletor.NewServerTorPolicy(string(body), node)
	if err != nil {
		return bad
	}
	result := struct {
		SourceJSON string                      `json:"source_json"`
		Reference  multihoprelay.TorExitSource `json:"reference"`
	}{SourceJSON: policy.Source(), Reference: multihoprelay.TorExitSource{
		ID: policy.ID(), Mode: policy.Mode(), SourceSHA256: policy.SourceSHA256(), DNSPolicySHA256: policy.DNSPolicySHA256(),
	}}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 256<<10 {
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
