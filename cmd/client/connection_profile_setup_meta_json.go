package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type connectionProfileSetupMetaWire connectionProfileSetupMeta
type connectionProfileSetupMetaStoreWire connectionProfileSetupMetaStore
type connectionProfileSetupRequestWire connectionProfileSetupRequest

func (q *connectionProfileSetupRequest) UnmarshalJSON(data []byte) error {
	var decoded connectionProfileSetupRequestWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if value, present := fields["multihop_entry_mode"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return errors.New("requested multihop entry transport cannot be null")
	}
	*q = connectionProfileSetupRequest(decoded)
	return nil
}

func (m *connectionProfileSetupMeta) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("connection profile setup metadata target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if key != "multihop_entry_mode" && key != "multihop_exit_mode" && key != "multihop_execution" {
			return fmt.Errorf("connection profile setup metadata contains unsupported field %q", key)
		}
	}
	if value, present := raw["multihop_entry_mode"]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return errors.New("captured multihop entry transport cannot be null")
	}
	var decoded connectionProfileSetupMetaWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	mode, err := normalizeConnectionProfileExitMode(decoded.MultihopExitMode)
	if err != nil {
		return err
	}
	decoded.MultihopExitMode = mode
	decoded.MultihopEntryMode, err = normalizeConnectionProfileSetupEntryMode(decoded.MultihopEntryMode)
	if err != nil {
		return err
	}
	if _, present := raw["multihop_execution"]; present {
		execution, err := routeExecution(multihopConnectRequest{Execution: decoded.MultihopExecution})
		if err != nil {
			return err
		}
		decoded.MultihopExecution = string(execution)
	}
	*m = connectionProfileSetupMeta(decoded)
	return nil
}

func (s *connectionProfileSetupMetaStore) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("connection profile setup metadata store target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if key != "version" && key != "entries" {
			return fmt.Errorf("connection profile setup metadata store contains unsupported field %q", key)
		}
	}
	var decoded connectionProfileSetupMetaStoreWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = connectionProfileSetupMetaStore(decoded)
	return nil
}
