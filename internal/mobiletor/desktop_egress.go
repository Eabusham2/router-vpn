package mobiletor

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/mobilemultihop"
)

// The projection is private runtime metadata, never a saved profile setting.
// Existing pure compiler callers may omit it; shipping desktop launch wrappers
// require it for Router predecessors before granting physical firewall access.
// Reconstruction checks the complete graph instead of trusting host metadata.
func validateDesktopPhysicalEgress(profile map[string]any, predecessor *DesktopPredecessor) error {
	value, exists := profile["desktop_physical_egress"]
	if !exists {
		return nil
	}
	bad := errors.New("desktop Tor physical egress differs from its captured Router graph")
	if predecessor == nil {
		return bad
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return bad
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var actual []mobilemultihop.PhysicalEgress
	if decoder.Decode(&actual) != nil || len(actual) < 1 || len(actual) > 16 {
		return bad
	}
	expected, err := mobilemultihop.NodePhysicalEgress(predecessor.mode, predecessor.profile, predecessor.config)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return bad
	}
	return nil
}
