package mobiletor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// DesktopDirectPhysicalEgress reconstructs only fixed obfs4 sockets from the
// complete captured bridge lines. A Plan is exported data, so its convenience
// fields cannot grant authority independently of those lines. Distinct relay
// credentials may share a socket tuple; the source retains every bridge while
// the firewall receives each exact TCP tuple once, in first-source order.
func DesktopDirectPhysicalEgress(plan Plan) ([]mobilemultihop.PhysicalEgress, error) {
	bad := errors.New("Direct strict Tor requires one to eight captured literal obfs4 bridges")
	if len(plan.Bridges) < 1 || len(plan.Bridges) > 8 {
		return nil, bad
	}
	lines := make([]string, len(plan.Bridges))
	for i, bridge := range plan.Bridges {
		lines[i] = bridge.Line
	}
	verified, err := NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: lines})
	if err != nil || !reflect.DeepEqual(plan, verified) {
		return nil, bad
	}
	result := make([]mobilemultihop.PhysicalEgress, 0, len(verified.Bridges))
	seen := map[string]bool{}
	for _, bridge := range verified.Bridges {
		if bridge.Transport != "obfs4" {
			return nil, bad
		}
		host, portText, splitErr := net.SplitHostPort(bridge.Target)
		address, addressErr := netip.ParseAddr(host)
		port, portErr := strconv.Atoi(portText)
		if splitErr != nil || addressErr != nil || portErr != nil || port < 1 || port > 65535 ||
			address.String() != host || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() {
			return nil, bad
		}
		if address.Is4() {
			value := address.As4()
			if value[0] == 0 || value[0] >= 224 {
				return nil, bad
			}
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if !seen[key] {
			seen[key] = true
			result = append(result, mobilemultihop.PhysicalEgress{Host: host, Port: port, Network: "tcp"})
		}
	}
	return result, nil
}

// The projection is private runtime metadata, never a saved profile setting.
// An ordinary strict predecessor must supply it at compilation, as well as at
// the shipping wrapper. An Off policy and existing Router pure-compiler callers
// may omit it; every shipping fixed-bridge/predecessor wrapper requires it.
// Reconstruction checks the complete graph instead of trusting host metadata.
func validateDesktopPhysicalEgress(profile map[string]any, predecessor *DesktopPredecessor) error {
	var expected []mobilemultihop.PhysicalEgress
	required := false
	if predecessor == nil || predecessor.IsExternal() {
		raw, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		_, plan, _, err := desktopBridgeProfile(string(raw))
		if err != nil {
			return err
		}
		kill, err := desktopBridgeKillPolicy(profile, plan)
		if err != nil {
			return err
		}
		if predecessor == nil {
			expected, err = DesktopDirectPhysicalEgress(plan)
			// Existing single-bridge pure compiler callers may omit runtime
			// metadata. New strict multi-bridge graphs must retain it; shipping
			// launch validators require it for every fixed bridge selection.
			required = kill != "off" && len(plan.Bridges) > 1
		} else {
			required = kill != "off"
			expected, err = predecessor.PhysicalEgress(plan)
			if err != nil {
				return err
			}
		}
	}
	value, exists := profile["desktop_physical_egress"]
	if !exists {
		if required {
			return errors.New("strict Tor path requires its exact captured physical egress projection")
		}
		return nil
	}
	bad := errors.New("desktop Tor physical egress differs from its captured source graph")
	if predecessor == nil && len(expected) == 0 {
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
	if predecessor != nil && predecessor.IsRouter() {
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
