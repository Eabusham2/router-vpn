package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func decodeTorBridgeImportRequest(body io.Reader) (torBridgeImportRequest, error) {
	var request torBridgeImportRequest
	data, err := io.ReadAll(body)
	if err != nil {
		return request, err
	}
	err = json.Unmarshal(data, &request)
	return request, err
}

// Updates reuse the Connect source contract. The bridge editor supplies only
// public revision tokens; graph choices and credentials come from the exact
// current stored sources under the owning mutation transaction.
func (q *torBridgeImportRequest) UnmarshalJSON(data []byte) error {
	fields, err := externalConnectJSONObject(data)
	if err != nil {
		return err
	}
	expected := map[string]json.RawMessage{}
	for name, raw := range fields {
		for _, canonical := range []string{"expected_selected_node_id", "expected_profile_tokens"} {
			if name != canonical && strings.EqualFold(name, canonical) {
				return errors.New("Tor update source field must use its canonical JSON name")
			}
			if name == canonical {
				expected[name] = raw
			}
		}
	}
	// This invokes the same unique-object/null/partial/type/token validation
	// as the shipping Connect API, without accepting its path-edit fields.
	expectationJSON, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	var capture externalProfileConnectRequest
	if err = json.Unmarshal(expectationJSON, &capture); err != nil {
		return err
	}
	type wire torBridgeImportRequest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&decoded); err != nil {
		return err
	}
	decoded.ExpectedSelectedNodeID = capture.ExpectedSelectedNodeID
	decoded.ExpectedProfileTokens = capture.ExpectedProfileTokens
	*q = torBridgeImportRequest(decoded)
	return nil
}

func (q torBridgeImportRequest) expectedProfiles() externalProfileConnectRequest {
	return externalProfileConnectRequest{ProfileID: strings.TrimSpace(q.ID), ExpectedSelectedNodeID: q.ExpectedSelectedNodeID, ExpectedProfileTokens: q.ExpectedProfileTokens}
}
