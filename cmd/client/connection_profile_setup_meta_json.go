package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

type connectionProfileSetupMetaWire connectionProfileSetupMeta
type connectionProfileSetupMetaStoreWire connectionProfileSetupMetaStore

func (m *connectionProfileSetupMeta) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("connection profile setup metadata target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if key != "multihop_exit_mode" {
			return fmt.Errorf("connection profile setup metadata contains unsupported field %q", key)
		}
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
