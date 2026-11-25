package mobilemultihop

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strconv"

	"router-vpn/internal/hopmeasure"
)

type candidatePublicResponseSource struct {
	Target           hopmeasure.CandidateTarget
	ExpectedIP       string
	Method, Password string
	keyIdentity      string
}

// PublicCandidatePrefixMeasurements classifies positions in one original
// public-final source. The returned labels cannot authorize a socket or trial.
func (c *NodeChain) PublicCandidatePrefixMeasurements() []string {
	if !c.HasExternalFinal() || c.validateCapture() != nil {
		return nil
	}
	metrics := make([]string, len(c.proofs))
	for i := range metrics {
		metrics[i] = c.candidatePrefixMeasurementValidated(i)
	}
	return metrics
}

func publicCandidateMember(m *nodeChainImportedMember) (candidatePublicResponseSource, error) {
	bad := errors.New("public candidate requires an original literal-address Shadowsocks2022 import with its expected public exit IP")
	if m == nil || m.hostname != nil || m.validate() != nil || !externalPublicIP(m.selection.ExpectedPublicIP) {
		return candidatePublicResponseSource{}, bad
	}
	ext, _ := m.selection.Profile["external"].(map[string]any)
	ss, _ := ext["shadowsocks"].(map[string]any)
	method, key := predecessorText(ss, "method"), predecessorText(ss, "password")
	keyIdentity := importedSS2022KeyIdentity(method, key)
	if ext["expected_public_ip"] != m.selection.ExpectedPublicIP || keyIdentity == "" {
		return candidatePublicResponseSource{}, bad
	}
	target, err := nodeChainCandidateLiteralTarget(m.id(), m.source, map[string]any{"server": ss["server"], "server_port": ss["port"]})
	if err != nil {
		return candidatePublicResponseSource{}, errors.Join(bad, err)
	}
	return candidatePublicResponseSource{Target: target, ExpectedIP: m.selection.ExpectedPublicIP, Method: method, Password: key, keyIdentity: keyIdentity}, nil
}

func parseCandidatePublicResponseSource(input string) (candidatePublicResponseSource, error) {
	m, err := parseNodeChainImportedMember(input)
	if err != nil {
		return candidatePublicResponseSource{}, errors.Join(errors.New("public candidate requires its independently captured source and expected public IP"), err)
	}
	return publicCandidateMember(m)
}

// Counts are private to one socket-free inventory calculation. Both members
// of an ambiguous group must be excluded, independent of catalog order.
type publicCandidateUses struct {
	ids, endpoints, keys map[string]int
}

func (u publicCandidateUses) add(s candidatePublicResponseSource) {
	u.ids[s.Target.ID]++
	u.endpoints[s.Target.Address]++
	u.keys[s.keyIdentity]++
}

func (u publicCandidateUses) unique(s candidatePublicResponseSource) bool {
	return u.ids[s.Target.ID] == 1 && u.endpoints[s.Target.Address] == 1 && u.keys[s.keyIdentity] == 1
}

func (c *NodeChain) publicCandidateUses(candidates []candidatePublicResponseSource) (publicCandidateUses, error) {
	u := publicCandidateUses{ids: map[string]int{}, endpoints: map[string]int{}, keys: map[string]int{}}
	if !c.HasExternalFinal() {
		return u, nodeChainError
	}
	u.ids[c.proofs[0].ProfileID]++
	for _, egress := range c.physical {
		u.endpoints[net.JoinHostPort(egress.Host, strconv.Itoa(egress.Port))]++
	}
	if c.proofs[0].StartLayer != "off" {
		entry, err := nodeMultihopPredecessor(c.nodes[0])
		if err != nil {
			return u, err
		}
		inner, key, err := externalFinalLayerTransport(entry)
		if err != nil || !inner.IsValid() {
			return u, nodeChainError
		}
		u.endpoints[inner.String()]++
		u.keys[key]++
	}
	for _, member := range c.importedNodes.members[1:] {
		s, err := publicCandidateMember(member)
		if err != nil {
			return u, err
		}
		u.add(s)
	}
	for _, s := range candidates {
		u.add(s)
	}
	return u, nil
}

// Use preserves the original prefix, suffix and public final. Reusing any of
// their identities, stream addresses or keys makes an issued plan ambiguous.
func (c *NodeChain) validatePublicCandidateInventory(candidates []candidatePublicResponseSource) error {
	if len(candidates) == 0 {
		return nodeChainError
	}
	uses, err := c.publicCandidateUses(candidates)
	if err != nil {
		return err
	}
	for _, s := range candidates {
		if !uses.unique(s) {
			return errors.New("public candidate must have an independent original node, endpoint and cipher key")
		}
	}
	return nil
}

// FilterPublicCandidateInventory constructs no plan and grants no transport.
// Preserve exact original bytes and revision for the independent rows, so one
// incompatible catalog record cannot suppress the other measured choices.
func (c *NodeChain) FilterPublicCandidateInventory(position int, inventory string) (string, error) {
	if c == nil || c.validateCapture() != nil || c.candidatePrefixMeasurementValidated(position) != hopmeasure.CandidatePublicResponseMeasurement {
		return "", nodeChainError
	}
	var original NodeChainCandidateInventory
	if exactJSON([]byte(inventory), &original, NodeChainInputLimit) != nil || original.Schema != 1 ||
		!nodeChainIdentityText(original.Revision) || original.Inputs == nil {
		return "", nodeChainError
	}
	var sources []candidatePublicResponseSource
	var inputs []string
	for _, input := range original.Inputs {
		s, err := parseCandidatePublicResponseSource(input)
		if err == nil {
			sources = append(sources, s)
			inputs = append(inputs, input)
		}
	}
	uses, err := c.publicCandidateUses(sources)
	if err != nil {
		return "", err
	}
	filtered := NodeChainCandidateInventory{Schema: 1, Revision: original.Revision, Inputs: []string{}}
	for i, s := range sources {
		if uses.unique(s) {
			filtered.Inputs = append(filtered.Inputs, inputs[i])
		}
	}
	out, err := json.Marshal(filtered)
	return string(out), err
}

func FilterNodeChainPublicCandidateInventory(source string, position int, inventory string) (string, error) {
	original, err := NewNodeChain(source)
	if err != nil {
		return "", err
	}
	return original.FilterPublicCandidateInventory(position, inventory)
}

func (p *NodeChainCandidatePlan) PublicResponseCandidateDepth(position int, id, tag string) int {
	if p.validate() != nil || p.multiple == nil || p.measurement != hopmeasure.CandidatePublicResponseMeasurement ||
		p.prefix.Position != position || p.prefix.ProfileID != id || p.prefix.Tag != tag ||
		!p.chain.HasExternalFinal() || p.chain.candidatePrefixMeasurementValidated(position) != p.measurement {
		return 0
	}
	return len(p.chain.proofs)
}

func (p *NodeChainCandidatePlan) newPublicResponseService(ctx context.Context, engine hopmeasure.CandidateEngine, prefix hopmeasure.CandidatePrefix) (*hopmeasure.CandidateService, error) {
	if wrapCandidateSS2022 == nil {
		return nil, errors.New("public response requires the captured native Shadowsocks2022 transport")
	}
	// The original Go runtime fixtures own their private TLS roots. The
	// native application cannot supply an alternate trust store to a plan.
	testTLS := p.chain.runtime.testTLS
	if prep, ok := engine.(*NodeChainCandidatePreparationRuntime); ok {
		testTLS = prep.testTLS
	}
	respond := func(ctx context.Context, target hopmeasure.CandidateTarget, begin, complete func() error) error {
		for _, source := range p.publicResponses {
			if source.Target == target {
				return source.exchange(ctx, engine.Dial, prefix.Tag, testTLS, begin, complete)
			}
		}
		return hopmeasure.ErrStale
	}
	return hopmeasure.NewPublicResponseCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p, respond)
}

func (s candidatePublicResponseSource) exchange(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), tag string, testTLS *tls.Config, begin, complete func() error) error {
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	_, err = externalProofHTTPMeasured(ctx, func(call context.Context, routedTag, destination string) (net.Conn, error) {
		if routedTag != tag || destination != "1.1.1.1:443" {
			return nil, hopmeasure.ErrStale
		}
		return dialCandidateStream(call, dial, wrapCandidateSS2022, tag, s.Target.Address, s.Method, s.Password, destination)
	}, tag, hopmeasure.CandidatePublicResponseEndpoint+"?routervpn_candidate="+nonce, "", "", testTLS, begin, func(data []byte) error {
		if err := externalTraceAddress(data, s.ExpectedIP); err != nil {
			return err
		}
		return complete()
	})
	return err
}
