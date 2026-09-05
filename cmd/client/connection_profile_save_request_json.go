package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var connectionProfileSaveLogicalModeIDs = map[string]struct{}{
	"base-raw": {}, "base-pq": {}, "awg-strong": {}, "shadowsocks": {},
	"reality-vision": {}, "hysteria2": {}, "reality-pq-vision": {}, "ss-v2ray": {},
	"naive-h2": {}, "naive-h3": {}, "split": {}, "reality-xhttp": {}, "max": {},
	"max-quic": {}, "max-tls": {}, "all": {},
}

var connectionProfileSaveRequestKeys = map[string]struct{}{
	"id": {}, "name": {}, "mode": {}, "custom_layers": {},
}

func normalizeConnectionProfileSaveMode(mode string, layers []string) (string, error) {
	mode, err := normalizeConnectionProfileMode(mode)
	if err != nil {
		return "", err
	}
	switch mode {
	case "smart-auto", "auto":
		return mode, nil
	case "custom":
		if len(layers) == 0 {
			return "", errors.New("CUSTOM connection profile requires at least one validated layer")
		}
		return mode, nil
	case "external":
		// Kept only for backward-compatible direct callers. The selected-node
		// write path remains authoritative and forces external mode only for an
		// actually linked external node.
		if len(layers) != 0 {
			return "", errors.New("external connection profile cannot contain CUSTOM layers")
		}
		return mode, nil
	}
	if strings.HasPrefix(mode, "custom:") {
		if len(layers) == 0 {
			return "", errors.New("saved CUSTOM preset requires its validated layer set")
		}
		return mode, nil
	}
	if _, ok := connectionProfileSaveLogicalModeIDs[mode]; ok {
		return mode, nil
	}
	return "", fmt.Errorf("new connection profile mode %q is not a current logical mode", mode)
}

type connectionProfileSaveRequestWire connectionProfileSaveRequest

// UnmarshalJSON is the shared semantic boundary for both the raw CRUD and the
// setup-aware desktop endpoints. Persisted compatibility may still read known
// historic runtime IDs, but new writes must use the current logical surface.
func (q *connectionProfileSaveRequest) UnmarshalJSON(data []byte) error {
	if q == nil {
		return errors.New("connection profile save request target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if _, ok := connectionProfileSaveRequestKeys[key]; !ok {
			return fmt.Errorf("connection profile save request contains unsupported field %q", key)
		}
	}
	var decoded connectionProfileSaveRequestWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	layers, err := normalizeConnectionProfileLayers(decoded.CustomLayers)
	if err != nil {
		return err
	}
	mode, err := normalizeConnectionProfileSaveMode(decoded.Mode, layers)
	if err != nil {
		return err
	}
	decoded.Mode = mode
	decoded.CustomLayers = layers
	*q = connectionProfileSaveRequest(decoded)
	return nil
}
