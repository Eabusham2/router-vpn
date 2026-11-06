package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

func BuildResolvedServerStateFrame(capture string, sequence uint32, raw []byte) ([]byte, error) {
	var state ResolvedServerState
	if !resolvedDigest(capture, 32) || sequence == 0 || sequence > MaxResolvedRequests || len(raw) > MaxResolvedServerState || json.Unmarshal(raw, &state) != nil {
		return nil, errors.New("server-state frame omitted original request")
	}
	canonical, err := state.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("server-state frame changed canonical observation")
	}
	return json.Marshal(ResolvedFrame{1, capture, sequence, ResolvedPolicySHA256(raw), 0, 1, bytes.Clone(raw)})
}
func DecodeResolvedServerStateFrame(raw []byte, capture string, sequence uint32, policy ResolvedPolicy, name string, index int32) (ResolvedServerState, error) {
	var frame ResolvedFrame
	bad := errors.New("server-state frame changed original request or observation")
	if len(raw) == 0 || len(raw) > 12<<10 || !resolvedDigest(capture, 32) || sequence == 0 || sequence > MaxResolvedRequests || json.Unmarshal(raw, &frame) != nil {
		return ResolvedServerState{}, bad
	}
	canonical, err := json.Marshal(frame)
	if err != nil || !bytes.Equal(raw, canonical) || frame.Schema != 1 || frame.CaptureSHA256 != capture || frame.Sequence != sequence || frame.Part != 0 || frame.Parts != 1 || ResolvedPolicySHA256(frame.Data) != frame.SHA256 {
		return ResolvedServerState{}, bad
	}
	return DecodeResolvedServerState(frame.Data, policy, name, index)
}
