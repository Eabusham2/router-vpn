package mobiletor

import (
	"encoding/json"
	"errors"
)

// SelectDesktopBridgeDNS validates the saved resolver against the same parser
// used by the native Tor graph. A private Home resolver belongs to the exact
// captured Router entry. Idle intent grants neither a route nor live DNS proof.
func SelectDesktopBridgeDNS(source, entryJSON string, idle bool) (DesktopBridgeDNS, error) {
	profile, _, _, err := desktopBridgeProfile(source)
	if err != nil {
		return DesktopBridgeDNS{}, err
	}
	if (profile["multihop_enabled"] == true) != (entryJSON != "") {
		return DesktopBridgeDNS{}, errors.New("Tor DNS requires the exact saved entry selection")
	}
	var entry map[string]any
	if entryJSON != "" {
		entry, err = profileObject(entryJSON, 4<<20)
		if err != nil {
			return DesktopBridgeDNS{}, err
		}
		if entry["node_kind"] == "external" {
			// Idle DNS editing binds an ordinary source identity without
			// manufacturing a Router proof. Connect separately captures and
			// recompiles the full native graph before proving this provider.
			var protocol string
			entry, protocol, _, err = desktopExternalPredecessorProfile(entryJSON)
			if err != nil || profile["multihop_entry_mode"] != protocol {
				return DesktopBridgeDNS{}, errors.New("Tor DNS requires its exact ordinary predecessor protocol and public identity")
			}
		} else {
			if _, err = NewPredecessorProof(entryJSON); err != nil {
				return DesktopBridgeDNS{}, err
			}
		}
		if profile["multihop_entry_id"] != entry["id"] || profile["multihop_exit_id"] != profile["id"] || entry["id"] == profile["id"] ||
			!profileIdentifier.MatchString(profileString(profile, "multihop_entry_mode")) ||
			(profileString(profile, "multihop_execution") != "" && profileString(profile, "multihop_execution") != "local") {
			return DesktopBridgeDNS{}, errors.New("Tor DNS belongs to another captured entry, exit or execution selection")
		}
	}
	selected, _, err := torSelectedDNS(profile, entry, idle)
	if err != nil {
		return DesktopBridgeDNS{}, err
	}
	return desktopBridgeDNSMetadata(profile, selected)
}

func desktopBridgeDNSMetadata(profile, selected map[string]any) (DesktopBridgeDNS, error) {
	encoded, err := json.Marshal(selected)
	if err != nil {
		return DesktopBridgeDNS{}, err
	}
	numbers, err := profileObject(string(encoded), 16<<10)
	if err != nil {
		return DesktopBridgeDNS{}, err
	}
	port, err := profileInteger(numbers, "server_port", 0)
	if err != nil || port < 1 || port > 65535 {
		return DesktopBridgeDNS{}, errors.New("desktop Tor selected resolver lost its exact port")
	}
	dns := DesktopBridgeDNS{Mode: profileString(profile, "dns_mode"), Transport: profileString(selected, "type"), Address: profileString(selected, "server"), Port: port, Path: profileString(selected, "path")}
	if tls, ok := selected["tls"].(map[string]any); ok {
		dns.ServerName = profileString(tls, "server_name")
	}
	return dns, nil
}
