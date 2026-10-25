package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// A live result belongs to the system TUN. Restoring it must not rewrite an
// entry endpoint's MTU, DNS, credentials, or the previously proved graph.
func restoreDesktopNodeTUNMTU(config []byte, mtu int) ([]byte, error) {
	if mtu < 1280 || mtu > 9000 {
		return nil, errors.New("captured native restore MTU is outside the TUN bounds")
	}
	var graph map[string]json.RawMessage
	if json.Unmarshal(config, &graph) != nil || graph == nil {
		return nil, errors.New("native restore graph is invalid")
	}
	var inbounds []map[string]json.RawMessage
	if json.Unmarshal(graph["inbounds"], &inbounds) != nil {
		return nil, errors.New("native restore graph has no system TUN")
	}
	count := 0
	for _, inbound := range inbounds {
		var kind string
		if json.Unmarshal(inbound["type"], &kind) != nil {
			return nil, errors.New("native restore inbound has no exact type")
		}
		if kind != "tun" {
			continue
		}
		count++
		var original int
		if json.Unmarshal(inbound["mtu"], &original) != nil || original < 1280 || original > 9000 {
			return nil, errors.New("native restore TUN has no valid original MTU")
		}
		inbound["mtu"], _ = json.Marshal(mtu)
	}
	if count != 1 {
		return nil, errors.New("native restore requires exactly one captured system TUN")
	}
	graph["inbounds"], _ = json.Marshal(inbounds)
	return json.Marshal(graph)
}

func captureDesktopNodeRestoreMTU(launch *desktopNodeLaunch) (int, error) {
	record, err := readDesktopNodeMTU(launch)
	if err != nil || record.Active || record.Failure != "" {
		return 0, errors.New("native MTU is still changing or its exact readback is unavailable")
	}
	return record.MTU, nil
}

func capturedDesktopNodeRestoreGraph(launch *desktopNodeLaunch, config, metadata []byte) ([]byte, []byte, error) {
	original := sha256.Sum256(config)
	if launch == nil || launch.configSHA256 == "" || hex.EncodeToString(original[:]) != launch.configSHA256 {
		return nil, nil, errors.New("native restore graph differs from the captured process")
	}
	mtu, err := captureDesktopNodeRestoreMTU(launch)
	if err != nil {
		return nil, nil, err
	}
	restored, err := restoreDesktopNodeTUNMTU(config, mtu)
	if err != nil {
		return nil, nil, err
	}
	var receipt map[string]json.RawMessage
	if json.Unmarshal(metadata, &receipt) != nil || receipt == nil {
		clear(restored)
		return nil, nil, errors.New("native restore capture metadata is invalid")
	}
	var prior string
	if json.Unmarshal(receipt["config_sha256"], &prior) != nil || prior != launch.configSHA256 {
		clear(restored)
		return nil, nil, errors.New("native restore metadata belongs to another graph")
	}
	digest := sha256.Sum256(restored)
	receipt["config_sha256"], _ = json.Marshal(hex.EncodeToString(digest[:]))
	restoredMetadata, err := json.Marshal(receipt)
	if err != nil {
		clear(restored)
		return nil, nil, err
	}
	return restored, restoredMetadata, nil
}
