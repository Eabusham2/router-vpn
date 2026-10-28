package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// This caller nonce correlates an observer with the HTTP action that it owns.
// It grants no connection, proof or cancellation authority. Server-generated
// round IDs and captured native ownership remain independent of this value.
func validComparisonRequestID(id string) bool {
	if id == "" {
		return true // Existing internal and HTTP callers may omit correlation.
	}
	if len(id) != 32 {
		return false
	}
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == id
}

func validateComparisonRequestJSON(fields map[string]json.RawMessage) error {
	const canonical = "comparison_request_id"
	for name := range fields {
		if name != canonical && strings.EqualFold(name, canonical) {
			return errors.New("comparison request identity must use its canonical JSON field")
		}
	}
	if raw, exists := fields[canonical]; exists {
		var id string
		if json.Unmarshal(raw, &id) != nil || id == "" || !validComparisonRequestID(id) {
			return errors.New("comparison request identity must be 32 lowercase hexadecimal characters")
		}
	}
	return nil
}

func (q *speedLabRequest) UnmarshalJSON(data []byte) error {
	fields, err := externalConnectJSONObject(data)
	if err != nil {
		return err
	}
	if err := validateComparisonRequestJSON(fields); err != nil {
		return err
	}
	type wire speedLabRequest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*q = speedLabRequest(decoded)
	return nil
}
