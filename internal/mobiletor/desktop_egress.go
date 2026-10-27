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
	var expected []mobilemultihop.PhysicalEgress
	if predecessor != nil && predecessor.IsExternal() {
		raw, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		_, plan, _, err := desktopBridgeProfile(string(raw))
		if err != nil {
			return err
		}
		expected, err = predecessor.PhysicalEgress(plan)
		if err != nil {
			return err
		}
	}
	value, exists := profile["desktop_physical_egress"]
	if !exists {
		return nil
	}
	bad := errors.New("desktop Tor physical egress differs from its captured predecessor graph")
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
	if predecessor.IsRouter() {
		expected, err = mobilemultihop.NodePhysicalEgress(predecessor.mode, predecessor.profile, predecessor.config)
	}
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return bad
	}
	return nil
}

// PhysicalEgress retains only sockets of the captured lower graph. PT relays,
// proof services and selected DNS are carried inside it, never direct physical
// exceptions. Snowflake requires actual UDP; TCP-only or dynamic SOCKS relay
// predecessors cannot silently claim that fixed-tuple authority.
func (p *DesktopPredecessor) PhysicalEgress(plan Plan) ([]mobilemultihop.PhysicalEgress, error) {
	if p.IsRouter() {
		return mobilemultihop.NodePhysicalEgress(p.mode, p.profile, p.config)
	}
	if !p.IsExternal() {
		return nil, errors.New("Tor physical projection has no typed predecessor owner")
	}
	networks := []string{"tcp"}
	for _, bridge := range plan.Bridges {
		if bridge.Transport == "snowflake" {
			networks = append(networks, "udp")
			break
		}
	}
	return p.external.policy.DirectPhysicalEgress(networks)
}
