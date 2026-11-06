package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ResolvedLocalResult describes an original-daemon local-only reply. Local=false
// is emitted only for its authenticated NoSource verdict. It grants no public
// query: the caller must keep the same native authority live and current.
type ResolvedLocalResult struct {
	PolicySHA256  string        `json:"policy_sha256"`
	Name          string        `json:"name"`
	Local         bool          `json:"local"`
	CanonicalName string        `json:"canonical"`
	Addresses     []ResolvedDNS `json:"addresses"`
	Flags         uint64        `json:"flags"`
}

func (r ResolvedLocalResult) Canonical() ([]byte, error) {
	bad := errors.New("resolved local result has no exact bounded daemon observation")
	if !resolvedDigest(r.PolicySHA256, 32) || !ResolvedName(r.Name, false) {
		return nil, bad
	}
	if !r.Local {
		if r.CanonicalName != "" || len(r.Addresses) != 0 || r.Flags != 0 {
			return nil, bad
		}
	} else {
		if !ResolvedName(r.CanonicalName, false) || len(r.Addresses) == 0 || !resolvedDNSValid(r.Addresses) || r.Flags&(1<<9) == 0 || r.Flags&(1<<20|1<<23) != 0 {
			return nil, bad
		}
		for _, address := range r.Addresses {
			if address.Port != 0 || address.ServerName != "" {
				return nil, bad
			}
		}
	}
	return json.Marshal(r)
}

func DecodeResolvedLocal(raw []byte, policy, name string) (ResolvedLocalResult, error) {
	var r ResolvedLocalResult
	if len(raw) == 0 || len(raw) > 16<<10 || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("resolved local result frame malformed")
	}
	canonical, err := r.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || r.PolicySHA256 != policy || r.Name != name {
		return ResolvedLocalResult{}, errors.New("resolved local result belongs to another original policy or name")
	}
	return r, nil
}
