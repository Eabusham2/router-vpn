package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

// MaxResolvedRequests covers at most 32 original address/alias-proof cohorts
// for each of 7 searched names, 2 address families and 5 attempts. Each cohort
// has at most 257 scopes, 256 validator queries with 4 live policy guards each,
// and three complete trust observations: capture, joined-cohort recheck, and
// final chain adoption (256 DS/DNSKEY suffix results plus 2 policy reads each).
// Two cohort observations and 11 greeting/preflight/retirement frames bring the
// bound below 1<<30. The original two-minute deadline never renews; no frame
// history or extra query authority is created by this finite sequence budget.
const resolvedCompleteRequestBudget uint64 = 32*7*2*5*(257*(256*4+3*(256+2))+2) + 11
const MaxResolvedRequests uint32 = 1 << 30

// The fixed resolver helper receives these bytes through the existing sealed
// capture descriptor and authenticates their digest with its original parent.
type ResolvedCapture struct {
	Schema     int    `json:"schema"`
	Session    string `json:"session"`
	DeadlineNS int64  `json:"deadline_ns"`
	Name       string `json:"name"`
}

func (c ResolvedCapture) Canonical() ([]byte, error) {
	if c.Schema != 1 || !resolvedDigest(c.Session, 16) || c.DeadlineNS <= 0 || !ResolvedName(c.Name, false) {
		return nil, errors.New("resolved helper requires exact original bounded capture")
	}
	return json.Marshal(c)
}
func DecodeResolvedCapture(raw []byte, expected string) (ResolvedCapture, error) {
	var c ResolvedCapture
	if len(raw) == 0 || len(raw) > 2048 || !resolvedDigest(expected, 32) || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("resolved helper capture malformed")
	}
	canonical, err := c.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || ResolvedPolicySHA256(raw) != expected {
		return ResolvedCapture{}, errors.New("resolved helper capture differs from original parent")
	}
	return c, nil
}

type ResolvedRequest struct {
	Schema        int    `json:"schema"`
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint32 `json:"sequence"`
	Action        string `json:"action"`
	Name          string `json:"name,omitempty"`
	Index         int32  `json:"index,omitempty"`
	Type          uint16 `json:"type,omitempty"`
}

func (r ResolvedRequest) Canonical() ([]byte, error) {
	valid := r.Schema == 1 && resolvedDigest(r.CaptureSHA256, 32) && r.Sequence > 0 && r.Sequence <= MaxResolvedRequests
	switch r.Action {
	case "observe":
		valid = valid && (r.Name == "" || ResolvedName(r.Name, false)) && r.Index == 0 && r.Type == 0
	case "close":
		valid = valid && r.Name == "" && r.Index == 0 && r.Type == 0
	case "server-state":
		valid = valid && ResolvedName(r.Name, false) && r.Index >= 0 && r.Type == 0
	case "anchor":
		valid = valid && ResolvedName(r.Name, true) && r.Index >= 0 && (r.Type == 43 || r.Type == 48)
	default:
		valid = false
	}
	if !valid {
		return nil, errors.New("resolved request escaped fixed read-only protocol")
	}
	return json.Marshal(r)
}
func DecodeResolvedRequest(raw []byte, capture string, sequence uint32) (ResolvedRequest, error) {
	var r ResolvedRequest
	if len(raw) == 0 || len(raw) > 512 || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("resolved request frame malformed")
	}
	canonical, err := r.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || r.CaptureSHA256 != capture || r.Sequence != sequence {
		return ResolvedRequest{}, errors.New("resolved request changed original capture or sequence")
	}
	return r, nil
}

type ResolvedObservation struct {
	Schema        int             `json:"schema"`
	CaptureSHA256 string          `json:"capture_sha256"`
	Sequence      uint32          `json:"sequence"`
	Policy        json.RawMessage `json:"policy"`
	Local         json.RawMessage `json:"local"`
}

// Frames are smaller than the existing 16KiB authenticated process channel.
// They preserve the full policy, never truncate its DNS/search/link inventory.
type ResolvedFrame struct {
	Schema        int    `json:"schema"`
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint32 `json:"sequence"`
	SHA256        string `json:"sha256"`
	Part          uint32 `json:"part"`
	Parts         uint32 `json:"parts"`
	Data          []byte `json:"data"`
}

const resolvedChunkSize = 8 << 10
const maxResolvedObservation = MaxResolvedPolicy + (20 << 10)

func BuildResolvedFrames(capture string, sequence uint32, name, policy, local string) ([][]byte, error) {
	if !resolvedDigest(capture, 32) || sequence > MaxResolvedRequests {
		return nil, errors.New("resolved response lost original capture")
	}
	if _, err := DecodeResolvedPolicy([]byte(policy), ResolvedPolicySHA256([]byte(policy))); err != nil {
		return nil, err
	}
	if _, err := DecodeResolvedLocal([]byte(local), ResolvedPolicySHA256([]byte(policy)), name); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(ResolvedObservation{1, capture, sequence, json.RawMessage(policy), json.RawMessage(local)})
	if err != nil || len(raw) > maxResolvedObservation {
		return nil, errors.New("resolved observation exceeds bounded frame inventory")
	}
	parts := (len(raw) + resolvedChunkSize - 1) / resolvedChunkSize
	frames := make([][]byte, 0, parts)
	digest := ResolvedPolicySHA256(raw)
	for i := 0; i < parts; i++ {
		end := min((i+1)*resolvedChunkSize, len(raw))
		frame, err := json.Marshal(ResolvedFrame{1, capture, sequence, digest, uint32(i), uint32(parts), raw[i*resolvedChunkSize : end]})
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func DecodeResolvedFrames(frames [][]byte, capture string, sequence uint32, name string) (ResolvedObservation, error) {
	bad := errors.New("resolved frames lost original whole observation")
	var result ResolvedObservation
	if !resolvedDigest(capture, 32) || sequence > MaxResolvedRequests || len(frames) == 0 || len(frames) > (maxResolvedObservation+resolvedChunkSize-1)/resolvedChunkSize {
		return result, bad
	}
	var raw []byte
	var digest string
	for i, body := range frames {
		var f ResolvedFrame
		if len(body) == 0 || len(body) > 12<<10 || json.Unmarshal(body, &f) != nil {
			return result, bad
		}
		canonical, err := json.Marshal(f)
		if err != nil || !bytes.Equal(body, canonical) || f.Schema != 1 || f.CaptureSHA256 != capture || f.Sequence != sequence || f.Part != uint32(i) || f.Parts != uint32(len(frames)) || len(f.Data) == 0 || len(f.Data) > resolvedChunkSize || i < len(frames)-1 && len(f.Data) != resolvedChunkSize || !resolvedDigest(f.SHA256, 32) {
			return result, bad
		}
		if i == 0 {
			digest = f.SHA256
		} else if digest != f.SHA256 {
			return result, bad
		}
		raw = append(raw, f.Data...)
	}
	if len(raw) > maxResolvedObservation || ResolvedPolicySHA256(raw) != digest || json.Unmarshal(raw, &result) != nil {
		return ResolvedObservation{}, bad
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(raw, canonical) || result.Schema != 1 || result.CaptureSHA256 != capture || result.Sequence != sequence {
		return ResolvedObservation{}, bad
	}
	if _, err = DecodeResolvedPolicy(result.Policy, ResolvedPolicySHA256(result.Policy)); err != nil {
		return ResolvedObservation{}, err
	}
	if _, err = DecodeResolvedLocal(result.Local, ResolvedPolicySHA256(result.Policy), name); err != nil {
		return ResolvedObservation{}, err
	}
	return result, nil
}
