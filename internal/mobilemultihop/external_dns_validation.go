package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// ValidateExternalDNS validates saved DNS settings with the runtime parser.
// An absent Home entry is deferred only for this idle operation. Supplying an
// entry requires the exact selected node, and connection always requires the
// complete native graph and live DNS, private-entry and public-exit proofs.
func ValidateExternalDNS(profileJSON, entryJSON string) error {
	var profile, entry map[string]any
	if exactJSON([]byte(profileJSON), &profile, 4<<20) != nil || profile == nil || profile["node_kind"] != "external" {
		return errors.New("external DNS validation requires one captured external profile")
	}
	id, err := externalProfileIdentity(profile)
	ext, ok := profile["external"].(map[string]any)
	protocol, _ := ext["protocol"].(string)
	if err != nil || !ok || !externalOrdinaryProtocol(protocol) {
		return errors.New("external DNS validation requires the selected ordinary protocol")
	}
	selection := externalPolicyCapture{Schema: 1, ExitID: id, Protocol: protocol, Profile: profile}
	udp := externalUDP(protocol)
	if entryJSON != "" {
		if exactJSON([]byte(entryJSON), &entry, 4<<20) != nil || entry == nil {
			return errors.New("external DNS validation requires the complete captured entry")
		}
		entryID, err := externalProfileIdentity(entry)
		mode, modeErr := externalOptionalString(profile, "multihop_entry_mode")
		if err != nil || modeErr != nil || !exactID.MatchString(mode) || entryID == id || profile["multihop_enabled"] != true ||
			profile["multihop_entry_id"] != entryID || profile["multihop_exit_id"] != id || profile["multihop_exit_mode"] != protocol {
			return errors.New("external DNS entry does not belong to the exact saved node selection")
		}
		switch entry["node_kind"] {
		case nil, "", "router-vpn":
		case "external":
			external, ok := entry["external"].(map[string]any)
			entryProtocol, _ := external["protocol"].(string)
			if !ok || !externalOrdinaryProtocol(entryProtocol) || mode != entryProtocol {
				return errors.New("external DNS entry has no exact supported captured protocol")
			}
			udp = udp && externalUDP(entryProtocol)
		default:
			return errors.New("external DNS entry has no supported node kind")
		}
		selection.Entry, selection.EntryTag = entry, "external-entry"
	}
	if protocol == "openvpn" {
		// Match runtime policy: the owned IP stack carries DNS datagrams even
		// when its authenticated outer connection uses a TCP predecessor.
		udp = true
	}
	if raw, present := profile["dns_bootstrap"]; present {
		encoded, err := json.Marshal(raw)
		if err != nil || exactJSON(encoded, &selection.DNSBootstrap, 8192) != nil || selection.DNSBootstrap == nil || selection.DNSBootstrap.Server == nil || selection.DNSBootstrap.Query == nil {
			return errors.New("external DNS validation requires the exact owned hostname bootstrap")
		}
	}
	ipv6, _, err := externalDevicePolicy(profile, entry)
	if err != nil {
		return err
	}
	_, _, err = externalDNSSelection(selection, ipv6, udp, true)
	return err
}
