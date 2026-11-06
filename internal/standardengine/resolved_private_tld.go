package standardengine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"router-vpn/internal/common"
	"strings"
)

// ResolvedPrivateTLDProof authorizes only a derived TLD denial proof. It is
// not permission to adopt the original answer: the caller must separately
// prove an exact unsigned positive address candidate, retire both cohorts,
// and recheck the complete original plan before adopting that candidate.
// The lookup stays on the original name's scope, never ResolvedRoutes(TLD).
type ResolvedPrivateTLDProof struct {
	canonical            []byte
	policySHA, planSHA   string
	name, tld, candidate string
	index                int32
	kind                 uint16
	selected             ResolvedDNS
	inputs               ResolvedDNSSECInputs
}

func NewResolvedPrivateTLDProof(policy ResolvedPolicy, plan *ResolvedDNSSECPlan, kind uint16, candidateSHA256 string) (*ResolvedPrivateTLDProof, error) {
	bad := errors.New("private-TLD proof omitted exact original allow-downgrade root authority")
	if plan == nil || !plan.MatchesPolicy(policy) || plan.Mode() != "allow-downgrade" || (kind != 1 && kind != 28) || !resolvedDigest(candidateSHA256, 32) {
		return nil, bad
	}
	labels := strings.Split(plan.Name(), ".")
	if len(labels) != 2 || !ResolvedName(plan.Name(), false) {
		return nil, bad
	}
	route, err := resolvedDNSSECRoute(policy, plan.Name(), plan.Index())
	if err != nil {
		return nil, err
	}
	if route.DNSSEC != "allow-downgrade" || route.CurrentDNS == nil {
		return nil, bad
	}
	inputs, err := plan.ValidatorInputs()
	if err != nil {
		return nil, err
	}
	// Complete observations, not filtered validator inputs, decide islands.
	// A positive hidden by an NTA must never disappear from this exclusion.
	rootPositive := false
	positiveDS := map[string]bool{}
	for i, raw := range plan.observations {
		q := plan.questions[i]
		var observed ResolvedAnchorResult
		if q.Name == "." && q.Type == 43 && plan.HasRootDSDecision() {
			var root ResolvedRootDSDecision
			if json.Unmarshal(plan.rootDecision, &root) != nil || !root.Matches(policy, plan.Name(), plan.Index()) {
				return nil, bad
			}
			if root.Root != nil {
				observed = *root.Root
			}
		} else if json.Unmarshal(raw, &observed) != nil {
			return nil, bad
		}
		if observed.Present {
			if q.Name != "." {
				return nil, errors.New("private-TLD proof cannot bypass a captured positive island")
			}
			rootPositive = true
			if q.Type == 43 {
				positiveDS[""] = true
			}
		}
	}
	// Preserve unrelated original NTAs; reject insecurity covering either the
	// candidate or the derived proof under the original global/link precedence.
	global := resolvedDNSSECSet(route.GlobalNegativeTrustAnchors)
	link := map[string]bool{}
	if route.Index != 0 {
		link = resolvedDNSSECSet(route.NegativeTrustAnchors)
	}
	if !rootPositive || len(inputs.TrustAnchors) == 0 || plan.explicitInsecure || resolvedDNSSECNegative(labels[1], global, link, positiveDS) {
		return nil, bad
	}

	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	p := &ResolvedPrivateTLDProof{policySHA: ResolvedPolicySHA256(raw), planSHA: ResolvedPolicySHA256(plan.Canonical()), name: plan.Name(), tld: labels[1] + ".", candidate: candidateSHA256, index: plan.Index(), kind: kind, selected: *route.CurrentDNS, inputs: inputs}
	p.canonical, err = json.Marshal(struct {
		Purpose, PolicySHA256, PlanSHA256, Name, TLD, CandidateSHA256 string
		Index                                                         int32
		Type                                                          uint16
		Selected                                                      ResolvedDNS
	}{"private-tld-denial", ResolvedPolicySHA256(raw), p.planSHA, p.name, p.tld, p.candidate, p.index, p.kind, p.selected})
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (p *ResolvedPrivateTLDProof) Canonical() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.canonical)
}
func (p *ResolvedPrivateTLDProof) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}
func (p *ResolvedPrivateTLDProof) TLD() string {
	if p == nil {
		return ""
	}
	return p.tld
}
func (p *ResolvedPrivateTLDProof) Index() int32 {
	if p == nil {
		return -1
	}
	return p.index
}
func (p *ResolvedPrivateTLDProof) Inputs() ResolvedDNSSECInputs {
	if p == nil {
		return ResolvedDNSSECInputs{}
	}
	return ResolvedDNSSECInputs{TrustAnchors: append([]string(nil), p.inputs.TrustAnchors...), InsecureDomains: append([]string(nil), p.inputs.InsecureDomains...)}
}
func (p *ResolvedPrivateTLDProof) Matches(policy ResolvedPolicy, plan *ResolvedDNSSECPlan, kind uint16, candidateSHA256 string) bool {
	if p == nil {
		return false
	}
	next, err := NewResolvedPrivateTLDProof(policy, plan, kind, candidateSHA256)
	return err == nil && bytes.Equal(p.canonical, next.canonical)
}

// Question validates the derived proof purpose only. It does not grant an
// ordinary single-label address query or a query to any other route/server.
func (p *ResolvedPrivateTLDProof) Question(wire []byte) (ResolvedDNSSECQuestion, error) {
	if p == nil {
		return ResolvedDNSSECQuestion{}, errors.New("missing original private-TLD proof")
	}
	return resolvedDNSSECQuestionFromWire(p.tld, 1, wire)
}

func (p *ResolvedPrivateTLDProof) MatchesPolicy(policy ResolvedPolicy) bool {
	if p == nil {
		return false
	}
	raw, err := policy.Canonical()
	return err == nil && ResolvedPolicySHA256(raw) == p.policySHA
}

// CheckVerdict checks proof meaning after the caller has authenticated and
// naturally joined the exact child. An untrusted DNS AD bit cannot call this
// method on behalf of that lifecycle; State1 must come from the sealed child.
func (p *ResolvedPrivateTLDProof) CheckVerdict(question []byte, v DNSSECVerdict) error {
	bad := errors.New("private-TLD proof is not exact authenticated secure NXDOMAIN")
	q, err := p.Question(question)
	if err != nil || q.Name != p.TLD() || q.Type != 1 {
		return bad
	}
	if v.State != 1 || v.RCode != 3 || v.NXDomain != 1 || v.HaveData != 0 {
		return bad
	}
	if err := common.ValidateDNSProbeResponse(question, v.Packet); err != nil {
		return err
	}
	if v.Packet[3]&15 != 3 || binary.BigEndian.Uint16(v.Packet[6:]) != 0 {
		return bad
	}
	return nil
}
