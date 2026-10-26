package mobilemultihop

import "errors"

// ValidateNodePredecessor validates a complete captured Router node without
// inventing an external exit. Desktop Tor reuses this same family/key/DNS,
// Start Layer, performance and dependency validation before retaining a graph.
// This function performs no I/O and never reports a running or proved path.
func ValidateNodePredecessor(mode, profileJSON, configJSON string) error {
	if !NodeProfileMode(mode) || configJSON == "" {
		return errors.New("desktop predecessor requires one exact supported Router mode and complete graph")
	}
	var entry map[string]any
	if exactJSON([]byte(profileJSON), &entry, 256<<10) != nil || entry == nil {
		return errors.New("desktop predecessor requires the captured private Router profile")
	}
	predecessor, err := newExternalPredecessor(externalPolicyCapture{
		EntryTag: externalEntryTag, Entry: entry,
		Profile: map[string]any{"multihop_entry_mode": mode}, PredecessorConfig: configJSON,
	})
	if err != nil {
		return err
	}
	// The external-exit compositor replaces dns.final. Desktop Tor retains
	// this complete graph for the predecessor's bootstrap, so its original
	// final resolver must also name an owner from that validated graph.
	dns, ok := predecessor.graph["dns"].(map[string]any)
	if !ok || predecessor.resolvers[predecessorText(dns, "final")] == nil {
		return errors.New("desktop predecessor lost its captured final resolver")
	}
	return nil
}
