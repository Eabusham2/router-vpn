package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type connectionProfileRefRequestWire connectionProfileRefRequest

func (q *connectionProfileRefRequest) UnmarshalJSON(data []byte) error {
	if q == nil {
		return errors.New("connection profile reference request target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if key != "id" {
			return fmt.Errorf("connection profile reference request contains unsupported field %q", key)
		}
	}
	var decoded connectionProfileRefRequestWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.ID = strings.TrimSpace(decoded.ID)
	if !validProfileID(decoded.ID) {
		return errors.New("connection profile reference request requires a valid id")
	}
	*q = connectionProfileRefRequest(decoded)
	return nil
}
