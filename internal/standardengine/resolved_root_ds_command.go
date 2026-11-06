package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Root decision frames retain the explicit original local-only outcome; its embedded
// policy hash binds it to the complete policy already held by the same helper.
func BuildResolvedRootDSFrames(capture string, sequence uint32, raw []byte) ([][]byte, error) {
	var anchor ResolvedRootDSDecision
	if !resolvedDigest(capture, 32) || sequence == 0 || sequence > MaxResolvedRequests || len(raw) == 0 || len(raw) > MaxResolvedRootDS || json.Unmarshal(raw, &anchor) != nil {
		return nil, errors.New("resolved anchor frame omitted bounded original identity")
	}
	canonical, err := anchor.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("resolved anchor frame is not canonical")
	}
	parts := (len(raw) + resolvedChunkSize - 1) / resolvedChunkSize
	frames := make([][]byte, 0, parts)
	for i := 0; i < parts; i++ {
		frame, err := json.Marshal(ResolvedFrame{1, capture, sequence, ResolvedPolicySHA256(raw), uint32(i), uint32(parts), raw[i*resolvedChunkSize : min((i+1)*resolvedChunkSize, len(raw))]})
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}
func DecodeResolvedRootDSFrames(frames [][]byte, capture string, sequence uint32, policy ResolvedPolicy, name string, index int32) (ResolvedRootDSDecision, error) {
	var zero ResolvedRootDSDecision
	bad := errors.New("resolved anchor frames changed original request or loaded-store observation")
	if !resolvedDigest(capture, 32) || sequence == 0 || sequence > MaxResolvedRequests || len(frames) == 0 || len(frames) > 9 {
		return zero, bad
	}
	var raw []byte
	digest := ""
	for i, body := range frames {
		var frame ResolvedFrame
		if len(body) == 0 || len(body) > 12<<10 || json.Unmarshal(body, &frame) != nil {
			return zero, bad
		}
		canonical, err := json.Marshal(frame)
		if err != nil || !bytes.Equal(body, canonical) || frame.Schema != 1 || frame.CaptureSHA256 != capture || frame.Sequence != sequence || frame.Part != uint32(i) || frame.Parts != uint32(len(frames)) || !resolvedDigest(frame.SHA256, 32) || len(frame.Data) == 0 || len(frame.Data) > resolvedChunkSize || i < len(frames)-1 && len(frame.Data) != resolvedChunkSize {
			return zero, bad
		}
		if i == 0 {
			digest = frame.SHA256
		} else if digest != frame.SHA256 {
			return zero, bad
		}
		raw = append(raw, frame.Data...)
	}
	if ResolvedPolicySHA256(raw) != digest {
		return zero, bad
	}
	return DecodeResolvedRootDS(raw, policy, name, index)
}
