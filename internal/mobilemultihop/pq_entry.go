package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// validatePQEntry is used before a Start Layer introduces its owned detour.
// The packet endpoint and the independent Rosenpass handshake are one captured
// node policy. No native handle, socket, lease or OS interface is created here.
func validatePQEntry(value map[string]any, mode, nodeID string) error {
	if !IsPQMode(mode) || value["type"] != PQType || value["mode"] != mode ||
		value["node_id"] != nodeID || !proofID.MatchString(nodeID) || value["detour"] != nil {
		return errors.New("PQ entry does not belong to the captured mode and node")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	runtime, err := PQRuntimeConfig(string(raw))
	if err != nil {
		return err
	}
	runtime.PQ.Erase()
	return nil
}
