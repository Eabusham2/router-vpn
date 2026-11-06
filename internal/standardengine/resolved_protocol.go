package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

// DecodeResolvedPolicy rejects unknown fields, duplicate JSON keys, reordered
// wire fields and substituted snapshots through exact canonical byte identity.
// A digest only identifies bytes; it never authenticates their sender.
func DecodeResolvedPolicy(raw []byte, expected string) (ResolvedPolicy, error) {
	var policy ResolvedPolicy
	if len(raw) == 0 || len(raw) > MaxResolvedPolicy || !resolvedDigest(expected, 32) || json.Unmarshal(raw, &policy) != nil {
		return ResolvedPolicy{}, errors.New("resolved policy frame is malformed")
	}
	canonical, err := policy.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || ResolvedPolicySHA256(raw) != expected {
		return ResolvedPolicy{}, errors.New("resolved policy differs from original canonical observation")
	}
	return policy, nil
}
