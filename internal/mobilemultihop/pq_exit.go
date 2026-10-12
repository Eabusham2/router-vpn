package mobilemultihop

import (
	"encoding/json"
	"errors"
)

func validatePQExit(value map[string]any, mode, nodeID, entryTag string) error {
	if !IsPQMode(mode) || value["type"] != PQType || value["mode"] != mode || value["node_id"] != nodeID || !proofID.MatchString(nodeID) || !exactID.MatchString(entryTag) || value["detour"] != entryTag {
		return errors.New("PQ exit does not belong to the captured mode, node and entry")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	config, err := PQRuntimeConfig(string(raw))
	if err != nil {
		return err
	}
	config.PQ.Erase()
	return nil
}
