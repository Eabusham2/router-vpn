package standardengine

import (
	"bytes"
	"errors"
)

// BuildResolvedDNSSECPlanWithRootDS replaces only the root DS observation.
// Other observations remain complete and ordered as Questions(), excluding
// literal root DS. The decision is tagged in the immutable canonical plan; an
// unsigned empty root result is never encoded as an ordinary NoSource miss.
func BuildResolvedDNSSECPlanWithRootDS(policy ResolvedPolicy, name string, index int32, root ResolvedRootDSDecision, observations []ResolvedAnchorResult) (*ResolvedDNSSECPlan, error) {
	return buildResolvedDNSSECPlan(policy, name, index, observations, &root)
}
func (p *ResolvedDNSSECPlan) HasRootDSDecision() bool { return p != nil && len(p.rootDecision) != 0 }
func (p *ResolvedDNSSECPlan) RecheckWithRootDS(root ResolvedRootDSDecision, observations []ResolvedAnchorResult) error {
	if !p.HasRootDSDecision() {
		return errors.New("DNSSEC plan omitted original typed root decision")
	}
	policy, err := DecodeResolvedPolicy(p.policy, ResolvedPolicySHA256(p.policy))
	if err != nil {
		return err
	}
	observed, err := BuildResolvedDNSSECPlanWithRootDS(policy, p.name, p.index, root, observations)
	if err != nil {
		return err
	}
	if !bytes.Equal(observed.canonical, p.canonical) {
		return errors.New("original root decision, anchor presence or captured policy changed")
	}
	return nil
}
