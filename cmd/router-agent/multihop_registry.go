package main

import (
	"encoding/json"
	"errors"
	"router-vpn/internal/multihoprelay"
)

// Startup and offline validation must read the same bounded private registry.
// Keeping the reader shared prevents a successful pairing that cannot restart.
func readRelayRegistry(path string) (multihoprelay.Config, error) {
	var config multihoprelay.Config
	raw, err := readPrivilegedState(path, multihoprelay.MaxRegistryBytes)
	if err != nil {
		return config, err
	}
	defer clear(raw)
	if json.Unmarshal(raw, &config) != nil {
		return config, errors.New("invalid private multihop registry")
	}
	return config, nil
}
