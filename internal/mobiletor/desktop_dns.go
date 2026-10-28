package mobiletor

import (
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
	if profileString(profile, "multihop_execution") == "server" {
		normalizeDesktopServerDNSMode(profile)
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
			if profileString(profile, "multihop_execution") == "server" {
				return DesktopBridgeDNS{}, errors.New("Tor Server DNS requires its private Router entry")
			}
			// Idle DNS editing binds an ordinary source identity without
			// manufacturing a Router proof. Connect separately captures and
			// recompiles the full native graph before proving this provider.
			var protocol string
			entry, protocol, _, err = externalPredecessorProfile(entryJSON)
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
			(profileString(profile, "multihop_execution") != "" && profileString(profile, "multihop_execution") != "local" && profileString(profile, "multihop_execution") != "server") {
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
	return selectedDNSMetadata(profile, selected)
}
