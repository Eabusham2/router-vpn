package mobilemultihop

import "errors"

// ValidateExternalTransport validates an idle imported node's exact native
// transport, credentials and device/MTU settings without choosing DNS or
// granting runtime readiness. A Home-default draft may be saved before the
// user links its Router entry. Connection still requires NewExternalPolicy,
// the selected DNS owner and the live native proofs.
func ValidateExternalTransport(config, capture string) error {
	var selection externalPolicyCapture
	if exactJSON([]byte(capture), &selection, 8<<20) != nil || selection.Schema != 1 ||
		selection.Entry != nil || selection.EntryTag != "" || selection.PredecessorConfig != "" || selection.Execution != nil ||
		!exactID.MatchString(selection.ExitID) || !externalOrdinaryProtocol(selection.Protocol) || !externalPublicIP(selection.ExpectedPublicIP) {
		return errors.New("external transport validation requires one captured idle node")
	}
	profileID, err := externalProfileIdentity(selection.Profile)
	ext, ok := selection.Profile["external"].(map[string]any)
	if err != nil || selection.Profile["node_kind"] != "external" || profileID != selection.ExitID || !ok ||
		ext["protocol"] != selection.Protocol || ext["expected_public_ip"] != selection.ExpectedPublicIP {
		return errors.New("external transport validation cannot change its saved protocol or node identity")
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return errors.New("external transport validation requires its bounded native graph")
	}
	tun, exit, entry, _, err := externalOwnedGraph(graph, selection.Protocol, "", "", false)
	if err != nil {
		return err
	}
	if err = externalCapturedTransport(exit, selection.Profile); err != nil {
		return err
	}
	if _, _, err = externalDevicePolicy(selection.Profile); err != nil {
		return err
	}
	if _, _, _, err = externalMTUPolicy(tun, exit, entry, selection.Profile, nil); err != nil {
		return err
	}
	_, err = externalApplyStartLayer(graph, exit, selection)
	return err
}
