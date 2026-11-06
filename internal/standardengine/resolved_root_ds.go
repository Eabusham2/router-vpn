package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
)

const MaxResolvedRootDS = MaxResolvedAnchor + 4096
const ResolvedRootDSQueryFlags = uint64(1 | 1<<5 | 1<<11 | 1<<12 | 1<<13 | 1<<15)

// ResolvedRootDSDecision preserves an original local-only root DS decision.
// Synthetic unsigned root is not a negative trust anchor or a NoSource result.
// Positive records remain complete and cannot be discarded for zero-TA export.
type ResolvedRootDSDecision struct {
	PolicySHA256 string                `json:"policy_sha256"`
	Name         string                `json:"name"`
	Index        int32                 `json:"index"`
	DNSSEC       string                `json:"dnssec"`
	Selected     ResolvedDNS           `json:"selected"`
	Outcome      string                `json:"outcome"`
	Root         *ResolvedAnchorResult `json:"root"`
}

func (r ResolvedRootDSDecision) Canonical() ([]byte, error) {
	bad := errors.New("root DS decision omitted original route and exact local-only outcome")
	if !resolvedDigest(r.PolicySHA256, 32) || !ResolvedName(r.Name, false) || r.Index < 0 || !resolvedChoice(r.DNSSEC, "yes", "allow-downgrade") || !resolvedDNSValid([]ResolvedDNS{r.Selected}) {
		return nil, bad
	}
	switch r.Outcome {
	case "positive":
		if r.Root == nil || !r.Root.Present || r.Root.PolicySHA256 != r.PolicySHA256 || r.Root.Index != r.Index || r.Root.Name != "." || r.Root.Type != 43 {
			return nil, bad
		}
		if _, err := r.Root.Canonical(); err != nil {
			return nil, err
		}
	case "synthetic-unsigned":
		if r.DNSSEC != "allow-downgrade" || r.Root != nil {
			return nil, bad
		}
	case "no-trust-anchor":
		if r.DNSSEC != "yes" || r.Root != nil {
			return nil, bad
		}
	default:
		return nil, bad
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxResolvedRootDS {
		return nil, bad
	}
	return raw, nil
}
func (r ResolvedRootDSDecision) Matches(policy ResolvedPolicy, name string, index int32) bool {
	if _, err := r.Canonical(); err != nil {
		return false
	}
	raw, err := policy.Canonical()
	if err != nil || r.PolicySHA256 != ResolvedPolicySHA256(raw) || r.Name != name || r.Index != index {
		return false
	}
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return false
	}
	for _, route := range routes {
		if route.Index == index {
			return route.CurrentDNS != nil && *route.CurrentDNS == r.Selected && route.DNSSEC == r.DNSSEC
		}
	}
	return false
}
func DecodeResolvedRootDS(raw []byte, policy ResolvedPolicy, name string, index int32) (ResolvedRootDSDecision, error) {
	var r ResolvedRootDSDecision
	if len(raw) == 0 || len(raw) > MaxResolvedRootDS || json.Unmarshal(raw, &r) != nil {
		return r, errors.New("invalid bounded original root decision")
	}
	canonical, err := r.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || !r.Matches(policy, name, index) {
		return ResolvedRootDSDecision{}, errors.New("root decision changed original policy or request")
	}
	return r, nil
}
