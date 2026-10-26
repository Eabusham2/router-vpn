package main

import (
	"errors"
	"strings"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// Complete MAX owns a mandatory PQ-keyed packet endpoint inside its captured
// middle and outer transports. Keep that ownership distinct from the raw
// composite mode named "max" and from raw-packet MTU arithmetic.
func nativeMultihopExitMode(mode string) bool {
	return mobilemultihop.NodeMultihopExitMode(mode) || mobilemultihop.MAXMode(mode)
}

func nativeMultihopPacketExitMode(mode string) bool {
	return mobilemultihop.NodeMultihopPacketExitMode(mode) || mobilemultihop.MAXMode(mode)
}

func nativeMultihopPQExitMode(mode string) bool {
	return mobilemultihop.IsPQMode(mode) || mobilemultihop.MAXMode(mode)
}

// Validate the entire captured Local exit before the authenticated Server
// lease replaces it. Only these exact child owners may be removed; the entry
// closure, proof lanes, interface and selected DNS retain their captured owners.
func nativeMAXExitOwners(graph map[string]any, selection multihopSelection) (map[string]bool, error) {
	bad := errors.New("complete MAX Server execution lost its captured exit chain")
	if !mobilemultihop.MAXMode(selection.ExitMode) {
		return nil, bad
	}
	names := multihoprelay.MAXTags{Root: "proxy", Middle: mobilemultihop.MAXExitPrefix + "ss", Outer: mobilemultihop.MAXExitPrefix + "outer", Start: mobilemultihop.MAXExitPrefix + "start"}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok {
		return nil, bad
	}
	var base map[string]any
	for _, raw := range endpoints {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		if value["tag"] == names.Root {
			if base != nil {
				return nil, bad
			}
			base = value
		}
	}
	outputs, ok := graph["outbounds"].([]any)
	if !ok || base == nil {
		return nil, bad
	}
	var children []any
	owned := map[string]bool{}
	for _, raw := range outputs {
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		tag, _ := value["tag"].(string)
		if strings.HasPrefix(tag, mobilemultihop.MAXExitPrefix) {
			if owned[tag] {
				return nil, bad
			}
			owned[tag] = true
			children = append(children, value)
		}
	}
	if multihoprelay.ValidateMAXChain(base, children, selection.ExitMode, selection.Exit.NodeProofID, selection.Exit.StartLayer, names, "entry-wg") != nil {
		return nil, bad
	}
	return owned, nil
}
