package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"router-vpn/internal/common"
	"strings"
)

// ResolvedPrivateDSDependencies is an inert three-label dependency purpose.
// The two exact unsigned DS dependencies must complete on this original scope
// before a separate authenticated root-denial child can authorize a proof.
// It never changes an original validator State3 into State2 or grants AD.
type ResolvedPrivateDSDependencies struct {
	root      *ResolvedPrivateTLDProof
	questions []ResolvedDNSSECQuestion
}
type ResolvedPrivateDSReply struct {
	AuthoritySHA256    string
	Question, Response []byte
}
type ResolvedPrivateDSProof struct {
	original  *ResolvedPrivateDSDependencies
	canonical []byte
}

func NewResolvedPrivateDSDependencies(policy ResolvedPolicy, plan *ResolvedDNSSECPlan, kind uint16, candidate string) (*ResolvedPrivateDSDependencies, error) {
	root, err := newResolvedPrivateRootProof(policy, plan, kind, candidate, 3, "private-three-label-ds-dependencies")
	if err != nil {
		return nil, err
	}
	names := strings.Split(root.name, ".")
	return &ResolvedPrivateDSDependencies{root: root, questions: []ResolvedDNSSECQuestion{{Name: root.name + ".", Type: 43}, {Name: strings.Join(names[1:], ".") + ".", Type: 43}}}, nil
}
func (p *ResolvedPrivateDSDependencies) Canonical() []byte {
	if p == nil {
		return nil
	}
	return p.root.Canonical()
}
func (p *ResolvedPrivateDSDependencies) Name() string {
	if p == nil {
		return ""
	}
	return p.root.Name()
}
func (p *ResolvedPrivateDSDependencies) TLD() string {
	if p == nil {
		return ""
	}
	return p.root.TLD()
}
func (p *ResolvedPrivateDSDependencies) Index() int32 {
	if p == nil {
		return -1
	}
	return p.root.Index()
}
func (p *ResolvedPrivateDSDependencies) Inputs() ResolvedDNSSECInputs {
	if p == nil {
		return ResolvedDNSSECInputs{}
	}
	return p.root.Inputs()
}
func (p *ResolvedPrivateDSDependencies) Questions() []ResolvedDNSSECQuestion {
	if p == nil {
		return nil
	}
	return append([]ResolvedDNSSECQuestion(nil), p.questions...)
}
func (p *ResolvedPrivateDSDependencies) Matches(policy ResolvedPolicy, plan *ResolvedDNSSECPlan, kind uint16, candidate string) bool {
	if p == nil {
		return false
	}
	next, err := NewResolvedPrivateDSDependencies(policy, plan, kind, candidate)
	return err == nil && bytes.Equal(p.Canonical(), next.Canonical())
}
func (p *ResolvedPrivateDSDependencies) MatchesPolicy(policy ResolvedPolicy) bool {
	return p != nil && p.root.MatchesPolicy(policy)
}
func (p *ResolvedPrivateDSDependencies) Question(wire []byte) (ResolvedDNSSECQuestion, error) {
	var zero ResolvedDNSSECQuestion
	if p == nil || p.root == nil {
		return zero, errors.New("missing original private DS purpose")
	}
	q, err := resolvedDNSSECQuestionFromWire(p.root.name, p.root.kind, wire)
	if err != nil {
		return zero, err
	}
	for _, want := range p.questions {
		if q.Name == want.Name && q.Type == 43 {
			return q, nil
		}
	}
	return zero, errors.New("private DS dependency changed exact parent chain")
}
func (p *ResolvedPrivateDSDependencies) RootQuestion(wire []byte) (ResolvedDNSSECQuestion, error) {
	if p == nil {
		return ResolvedDNSSECQuestion{}, errors.New("missing original private DS purpose")
	}
	return p.root.Question(wire)
}

// Complete checks meaning only AFTER the caller has joined the dependency
// group and naturally authenticated/joined the original root-denial child.
// Fresh full-plan/current-tuple checks and all owner retirement still precede
// adoption. Upstream AD, timeout, aliases, positive DS or generic State3 do not
// stand in for any of these exact observations.
func (p *ResolvedPrivateDSDependencies) Complete(replies []ResolvedPrivateDSReply, rootQuestion []byte, rootVerdict DNSSECVerdict) (*ResolvedPrivateDSProof, error) {
	if p == nil || len(replies) != 2 {
		return nil, errors.New("private DS chain omitted an original dependency")
	}
	hashes := make([]string, 2)
	for i, r := range replies {
		if r.AuthoritySHA256 != SHA256(p.Canonical()) {
			return nil, errors.New("private DS reply lost original scope/plan/candidate authority")
		}
		q, err := p.Question(r.Question)
		if err != nil || q.Name != p.questions[i].Name {
			return nil, errors.New("private DS chain changed original order/name")
		}
		if err = common.ValidateUnsignedDSNegativeResponse(r.Question, r.Response); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(r)
		hashes[i] = SHA256(raw)
	}
	if err := p.root.CheckVerdict(rootQuestion, rootVerdict); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		Purpose, Authority, RootQuestion, RootPacket string
		Dependencies                                 []string
	}{"completed-private-three-label-ds-chain", SHA256(p.Canonical()), SHA256(rootQuestion), SHA256(rootVerdict.Packet), hashes})
	if err != nil {
		return nil, err
	}
	return &ResolvedPrivateDSProof{original: p, canonical: raw}, nil
}
func (p *ResolvedPrivateDSProof) Canonical() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.canonical)
}
func (p *ResolvedPrivateDSProof) Matches(policy ResolvedPolicy, plan *ResolvedDNSSECPlan, kind uint16, candidate string) bool {
	return p != nil && p.original.Matches(policy, plan, kind, candidate)
}
