package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// This list is the persisted compatibility surface, not a second UI catalog.
// It includes the current logical mode IDs plus all known runtime/strategy IDs
// from modes.json so older connection-profile stores can migrate without
// becoming un-loadable. Tests lock it to both canonical JSON catalogs.
var connectionProfilePersistedModeIDs = map[string]struct{}{
	"base-raw": {}, "base-pq": {}, "awg-strong": {}, "shadowsocks": {},
	"reality-vision": {}, "hysteria2": {}, "reality-pq-vision": {}, "ss-v2ray": {},
	"naive-h2": {}, "naive-h3": {}, "split": {}, "reality-xhttp": {}, "max": {},
	"max-quic": {}, "max-tls": {}, "all": {},
	"wg": {}, "awg2-fast": {}, "wg-pq": {}, "awg2-strong": {}, "awg2-pq": {},
	"max-quic-wg": {}, "max-quic-awg": {}, "max-tls-wg": {}, "max-tls-awg": {},
	"smart-auto": {}, "custom": {},
}

var connectionProfileRecordKeys = map[string]struct{}{
	"id": {}, "name": {}, "node_id": {}, "mode": {}, "preferences": {},
	"created_at": {}, "updated_at": {},
}

func normalizePersistedConnectionProfileMode(mode string, prefs *connectionProfilePreferences) (string, error) {
	mode, err := normalizeConnectionProfileMode(mode)
	if err != nil {
		return "", err
	}
	// Since schema v1, Router VPN records carry a non-secret preferences
	// snapshot while external-node records intentionally omit it. Keep that
	// representation bound to the persisted mode so a hand-edited/corrupt store
	// cannot cross-wire an external node into a Router mode (or vice versa).
	if prefs == nil && mode != "external" {
		return "", errors.New("external connection profile must use external mode")
	}
	if prefs != nil && mode == "external" {
		return "", errors.New("Router VPN connection profile cannot use external mode")
	}
	switch mode {
	case "smart-auto", "auto":
		return mode, nil
	case "external":
		return mode, nil
	case "custom":
		if len(prefs.CustomLayers) == 0 {
			return "", errors.New("CUSTOM connection profile requires at least one validated layer")
		}
		return mode, nil
	}
	if strings.HasPrefix(mode, "custom:") {
		if len(prefs.CustomLayers) == 0 {
			return "", errors.New("saved CUSTOM preset requires its validated layer set")
		}
		return mode, nil
	}
	if _, ok := connectionProfilePersistedModeIDs[mode]; ok {
		return mode, nil
	}
	return "", fmt.Errorf("connection profile mode %q is not a current logical or compatible runtime mode", mode)
}

// validateConnectionProfileModeForSave keeps a Router VPN profile on the live
// logical-mode surface before persistence. Raw runtime IDs are accepted only by
// the persisted compatibility validator above for migration of older stores.
func (a *app) validateConnectionProfileModeForSave(mode string, customLayers []string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "smart-auto", "auto":
		return nil
	case "custom":
		if len(customLayers) == 0 {
			return errors.New("CUSTOM connection profile requires at least one validated layer")
		}
		return nil
	}
	if strings.HasPrefix(mode, "custom:") {
		if len(customLayers) == 0 {
			return errors.New("saved CUSTOM preset requires its validated layer set")
		}
		return nil
	}
	if _, ok := a.logicalModeByID(mode); ok {
		return nil
	}
	return fmt.Errorf("connection profile mode %q is not a current logical mode", mode)
}

type connectionProfileRecordWire connectionProfileRecord

func (p *connectionProfileRecord) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("connection profile record target is nil")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for key := range raw {
		if _, ok := connectionProfileRecordKeys[key]; !ok {
			return fmt.Errorf("connection profile record contains unsupported field %q", key)
		}
	}
	var decoded connectionProfileRecordWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	record := connectionProfileRecord(decoded)
	mode, err := normalizePersistedConnectionProfileMode(record.Mode, record.Prefs)
	if err != nil {
		return err
	}
	record.Mode = mode
	*p = record
	return nil
}

func (p connectionProfileRecord) MarshalJSON() ([]byte, error) {
	mode, err := normalizePersistedConnectionProfileMode(p.Mode, p.Prefs)
	if err != nil {
		return nil, err
	}
	p.Mode = mode
	return json.Marshal(connectionProfileRecordWire(p))
}
