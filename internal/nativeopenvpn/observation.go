package nativeopenvpn

import "encoding/json"

// PacketObservation is a readback from one authenticated userspace endpoint.
// Its containing native owner must also retain the endpoint, packet reader,
// source and caller. A saved profile cannot supply this observation.
type PacketObservation struct {
	Remote RemoteReceipt `json:"remote"`
	MTU    uint32        `json:"entry_mtu"`
}

func (state PacketObservation) Validate() error {
	if state.Remote.Validate() != nil || state.MTU < 1280 || state.MTU > 65535 {
		return errRemote
	}
	return nil
}

func (state *PacketObservation) UnmarshalJSON(raw []byte) error {
	object, err := pairingObject(raw, 3072)
	if err != nil || len(object) != 2 {
		return errRemote
	}
	if _, ok := object["remote"].(map[string]any); !ok {
		return errRemote
	}
	if _, ok := object["entry_mtu"].(float64); !ok {
		return errRemote
	}
	type plain PacketObservation
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || PacketObservation(decoded).Validate() != nil {
		return errRemote
	}
	*state = PacketObservation(decoded)
	return nil
}
