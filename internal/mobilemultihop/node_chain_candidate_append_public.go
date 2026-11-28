package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

// CandidateKind and CandidateMeasurement describe the already captured next
// member. They never select a different source family for an existing plan.
func (s *NodeChainCandidateAppendSource) CandidateKind() string {
	if s.validate() != nil {
		return ""
	}
	if s.record.NextKind == "external" {
		return "external"
	}
	return "router-vpn"
}

func (s *NodeChainCandidateAppendSource) CandidateMeasurement() string {
	if s.validate() != nil {
		return ""
	}
	if s.record.NextKind == "external" {
		return hopmeasure.CandidatePublicResponseMeasurement
	}
	return hopmeasure.CandidatePrivateResponseMeasurement
}

func (p *NodeChainCandidatePreparation) CandidateKind() string {
	if p.validate() != nil {
		return ""
	}
	if p.appendSource != nil {
		return p.appendSource.CandidateKind()
	}
	switch p.candidates.measurement {
	case hopmeasure.CandidatePublicResponseMeasurement:
		return "external"
	case hopmeasure.CandidatePrivateResponseMeasurement:
		return "router-vpn"
	}
	return ""
}

func (p *NodeChainCandidatePreparation) CandidateMeasurement() string {
	if p.validate() != nil {
		return ""
	}
	if p.candidates.measurement == "" {
		return hopmeasure.CandidateTCPMeasurement
	}
	return p.candidates.measurement
}

// The prospective import keeps its original policy/member owner. Only its
// exact SS closure and saved hostname resolver are compiled; no paired API or final route is made.
func (s *NodeChainCandidateAppendSource) candidateImportedSSResponse(input string) (candidatePublicResponseSource, *nodeChainAppendImportedSeal, error) {
	bad := func() (candidatePublicResponseSource, *nodeChainAppendImportedSeal, error) {
		return candidatePublicResponseSource{}, nil, nodeChainCandidateAppendError
	}
	if s.validate() != nil || s.record.NextKind != "external" || s.record.NextMode != "shadowsocks" {
		return bad()
	}
	member, err := parseNodeChainImportedMember(input)
	if err != nil || member == nil {
		return bad()
	}
	original, err := rememberAppendImportedMember(member)
	if err != nil {
		return bad()
	}
	response, err := s.appendPublicCandidateMember(member)
	if err != nil {
		return bad()
	}
	config, proofs, err := s.candidateGraphConfig(nil, member)
	if err != nil {
		return bad()
	}
	closure, err := member.closure()
	if err != nil || !nodeChainAppendImportedClosure(member, closure) {
		return bad()
	}
	proof := proofs[len(proofs)-1]
	if proof.ProfileID != response.Target.ID || proof.SourceSHA256 != response.Target.SourceSHA256 ||
		proof.NodeID != "" || proof.Mode != "shadowsocks" || proof.StartLayer != "off" ||
		proof.NodeKind != "external" || proof.Kind != "public-path" {
		return bad()
	}
	projected, err := candidatePrefixClosure(config, proofs)
	want := predecessorCopy(closure.final)
	want["tag"], want["detour"] = proof.Tag, s.proofs[len(s.proofs)-1].Tag
	if member.hostname != nil {
		var projectionErr error
		want, projectionErr = s.appendHostnameCandidateOut(closure, proof)
		if projectionErr != nil {
			return bad()
		}
		var resolver map[string]any
		if json.Unmarshal([]byte(response.appendResolver), &resolver) != nil || !reflect.DeepEqual(projected["dns/"+predecessorText(resolver, "tag")], resolver) {
			return bad()
		}
	}
	if err != nil || !reflect.DeepEqual(projected["outbounds/"+proof.Tag], want) ||
		predecessorText(want, "method") != response.Method || predecessorText(want, "password") != response.Password {
		return bad()
	}
	return response, original, nil
}

func (s *NodeChainCandidateAppendSource) newPublicAppendCandidatePlan(inventory string, record NodeChainCandidateInventory) (*NodeChainCandidatePlan, error) {
	if s.validate() != nil || s.record.NextKind != "external" || s.record.NextMode != "shadowsocks" ||
		record.Schema != 1 || record.ResponseMode != "shadowsocks" || !nodeChainIdentityText(record.Revision) || len(record.Inputs) == 0 {
		return nil, nodeChainCandidateAppendError
	}
	keys, addresses, err := s.streamCandidateAliases()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(s.proofs))
	for _, proof := range s.proofs {
		ids[proof.ProfileID] = true
	}
	p := &NodeChainCandidatePlan{appendSource: s, metadataPages: &nodeChainCandidateMetadataCache{},
		inventory: inventory, revision: record.Revision, prefix: s.proofs[len(s.proofs)-1],
		measurement: hopmeasure.CandidatePublicResponseMeasurement, responseMode: "shadowsocks"}
	for _, input := range record.Inputs {
		response, original, err := s.candidateImportedSSResponse(input)
		if err != nil || original == nil || response.keyIdentity == "" || ids[response.Target.ID] ||
			keys[response.keyIdentity] || addresses[response.Target.Address] {
			return nil, nodeChainCandidateAppendError
		}
		ids[response.Target.ID], keys[response.keyIdentity], addresses[response.Target.Address] = true, true, true
		p.targets = append(p.targets, response.Target)
		p.publicResponses = append(p.publicResponses, response)
		p.appendImportSeals = append(p.appendImportSeals, original)
	}
	raw, err := json.Marshal([]any{nodeChainCandidateAppendPurpose, s.seal, s.sourceSHA, s.configSHA, p.prefix, inventory})
	if err != nil {
		return nil, nodeChainCandidateAppendError
	}
	p.capture = externalDigest(raw)
	clear(raw)
	p.seal = p.digest()
	return p, p.validate()
}

func (p *NodeChainCandidatePlan) validatePublicAppend() error {
	if p.appendSource.record.NextKind != "external" || p.responseMode != "shadowsocks" || p.preparedNativeResponse ||
		p.measurement != hopmeasure.CandidatePublicResponseMeasurement || p.responses != nil ||
		len(p.publicResponses) != len(p.targets) || len(p.appendImportSeals) != len(p.targets) {
		return nodeChainCandidateAppendError
	}
	for i, original := range p.appendImportSeals {
		if original == nil || original.owner == nil || !original.matches(original.owner) {
			return nodeChainCandidateAppendError
		}
		source, err := p.appendSource.appendPublicCandidateMember(original.owner)
		if err != nil || source != p.publicResponses[i] || source.Target != p.targets[i] {
			return nodeChainCandidateAppendError
		}
	}
	return nil
}

// AppendPublicResponseCandidateDepth reports only real retained members. An
// absent final member is never counted as complete-source response authority.
func (p *NodeChainCandidatePlan) AppendPublicResponseCandidateDepth(position int, id, tag string) int {
	if p.validateAppend() != nil || p.appendSource.record.NextKind != "external" ||
		p.prefix.Position != position || p.prefix.ProfileID != id || p.prefix.Tag != tag || position != len(p.appendSource.proofs)-1 {
		return 0
	}
	return len(p.appendSource.proofs)
}

// Both append stream metrics require this same original preparation. The
// public proof does not obtain an ordinary or selected runtime by describing
// an otherwise valid prefix or by copying an equal source capture.
func (p *NodeChainCandidatePlan) appendStreamRuntime(ctx context.Context, engine hopmeasure.CandidateEngine, capture string) (*NodeChainCandidatePreparationRuntime, error) {
	owner, ok := engine.(*NodeChainCandidatePreparationRuntime)
	if ctx == nil || !ok || owner == nil || !p.isAppendStreamResponse() || p.validateAppend() != nil ||
		owner.preparation == nil || owner.preparation.candidates != p || owner.preparation.appendSource != p.appendSource ||
		capture != owner.preparation.capture {
		return nil, hopmeasure.ErrStale
	}
	if err := owner.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	return owner, nil
}
