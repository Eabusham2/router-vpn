package mobilemultihop

import "encoding/json"

// NodeChainExternalFinalFromEntry binds the original selected mobile entry and
// external source. The imported member's standalone transport projection uses
// Rescue DNS; its original selection retains the user's final resolver.
func NodeChainExternalFinalFromEntry(entryInput, importedInput string) (string, error) {
	entry, err := ParseNodeLaunchInput(entryInput)
	if err != nil || entry.mode != "wg" {
		return "", nodeChainError
	}
	member, err := parseNodeChainImportedMember(importedInput)
	if err != nil || member.hostname != nil {
		return "", nodeChainError
	}
	var record nodeChainImportedInput
	if err := json.Unmarshal([]byte(importedInput), &record); err != nil {
		return "", err
	}
	s := member.selection
	s.Entry, s.EntryTag, s.PredecessorConfig = entry.profile, externalEntryTag, entry.Config()
	s.Profile = predecessorCopy(s.Profile)
	s.Profile["multihop_entry_mode"], s.Profile["multihop_entry_id"] = entry.mode, entry.profile["id"]
	s.Profile["multihop_exit_id"], s.Profile["multihop_enabled"], s.Profile["multihop_execution"] = s.ExitID, true, "local"
	capture, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return NodeChainExternalFinalInput(record.Config, string(capture))
}
