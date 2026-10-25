package multihoprelay

import (
	"encoding/json"
	"errors"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativeopenvpn"
)

// NativeOpenVPNCapture is written into the fresh private lease directory by
// the agent. The native command binds all receipts to this exact config/session;
// it is not an authentication mechanism for untrusted or public callers.
type NativeOpenVPNCapture struct {
	Schema              int    `json:"schema"`
	SessionID           string `json:"session_id"`
	ConfigSHA256        string `json:"config_sha256"`
	ExternalFingerprint string `json:"external_fingerprint"`
	ExternalAttempt     string `json:"external_attempt"`
}

type NativeOpenVPNReceipt struct {
	Capture     NativeOpenVPNCapture        `json:"capture"`
	RequestID   string                      `json:"request_id"`
	Remote      nativeopenvpn.RemoteReceipt `json:"remote"`
	HeartbeatAt int64                       `json:"heartbeat_at"`
}

// A new request nonce is required for every observation. A heartbeat from an
// earlier query is not proof of the endpoint's current remote or generation.
type NativeOpenVPNQuery struct {
	Capture   NativeOpenVPNCapture `json:"capture"`
	RequestID string               `json:"request_id"`
}

func (q NativeOpenVPNQuery) Validate(capture NativeOpenVPNCapture) error {
	if capture.Validate() != nil || q.Capture != capture || !nonce.MatchString(q.RequestID) {
		return errors.New("native OpenVPN query does not belong to this runtime")
	}
	return nil
}

func (q *NativeOpenVPNQuery) UnmarshalJSON(raw []byte) error {
	bad := errors.New("bounded exact native OpenVPN query required")
	if len(raw) > 4096 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 2 {
		return bad
	}
	if _, ok := object["capture"].(map[string]any); !ok {
		return bad
	}
	if _, ok := object["request_id"].(string); !ok {
		return bad
	}
	type plain NativeOpenVPNQuery
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || NativeOpenVPNQuery(decoded).Validate(decoded.Capture) != nil {
		return bad
	}
	*q = NativeOpenVPNQuery(decoded)
	return nil
}

func (c NativeOpenVPNCapture) Validate() error {
	if c.Schema != 1 || !nonce.MatchString(c.SessionID) || !proofID.MatchString(c.ConfigSHA256) || !proofID.MatchString(c.ExternalFingerprint) || !nonce.MatchString(c.ExternalAttempt) {
		return errors.New("owned native OpenVPN capture is invalid")
	}
	return nil
}

func (c *NativeOpenVPNCapture) UnmarshalJSON(raw []byte) error {
	bad := errors.New("bounded exact native OpenVPN capture required")
	if len(raw) > 4096 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 5 {
		return bad
	}
	for _, name := range []string{"session_id", "config_sha256", "external_fingerprint", "external_attempt"} {
		if _, ok := object[name].(string); !ok {
			return bad
		}
	}
	if _, ok := object["schema"].(json.Number); !ok {
		return bad
	}
	type plain NativeOpenVPNCapture
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || NativeOpenVPNCapture(decoded).Validate() != nil {
		return bad
	}
	*c = NativeOpenVPNCapture(decoded)
	return nil
}

func (r *NativeOpenVPNReceipt) UnmarshalJSON(raw []byte) error {
	bad := errors.New("bounded exact native OpenVPN receipt required")
	if len(raw) > 8192 {
		return bad
	}
	object, err := applexray.Object(raw)
	if err != nil || len(object) != 4 {
		return bad
	}
	for _, name := range []string{"capture", "remote"} {
		if _, ok := object[name].(map[string]any); !ok {
			return bad
		}
	}
	if _, ok := object["heartbeat_at"].(json.Number); !ok {
		return bad
	}
	if _, ok := object["request_id"].(string); !ok {
		return bad
	}
	type plain NativeOpenVPNReceipt
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || !nonce.MatchString(decoded.RequestID) || decoded.HeartbeatAt <= 0 || decoded.HeartbeatAt > 1<<53-1 {
		return bad
	}
	*r = NativeOpenVPNReceipt(decoded)
	return nil
}

func (r NativeOpenVPNReceipt) Validate(capture NativeOpenVPNCapture, now time.Time) error {
	if capture.Validate() != nil || r.Capture != capture || !nonce.MatchString(r.RequestID) || r.Remote.Validate() != nil || r.Remote.ConnectedAt > r.HeartbeatAt+1000 || r.HeartbeatAt <= 0 || r.HeartbeatAt > now.Add(time.Second).UnixMilli() || r.HeartbeatAt < now.Add(-3*time.Second).UnixMilli() {
		return errors.New("native OpenVPN receipt is stale or belongs to a different runtime")
	}
	return nil
}
