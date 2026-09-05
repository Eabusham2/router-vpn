package main

import (
	"encoding/json"
	"fmt"
)

type connectionProfileStoreWire connectionProfileStore

var connectionProfileStoreKeys = map[string]struct{}{
	"version": {},
	"profiles": {},
}

// UnmarshalJSON keeps durable connection-profile state fail-closed. Legacy
// stores may omit version (loadConnectionProfileStore treats that as v1), but
// no schema generation ever owned additional top-level fields, so silently
// ignoring one could canonize corrupt or foreign state during a v4 migration.
func (s *connectionProfileStore) UnmarshalJSON(data []byte) error {
	if s == nil {
		return fmt.Errorf("connection profile store target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if _, ok := connectionProfileStoreKeys[key]; !ok {
			return fmt.Errorf("connection profile store contains unsupported field %q", key)
		}
	}
	var decoded connectionProfileStoreWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = connectionProfileStore(decoded)
	return nil
}
