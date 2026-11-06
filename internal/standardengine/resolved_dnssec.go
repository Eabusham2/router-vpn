package standardengine

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ResolvedDNSSECQuestion names one exact original loaded-store observation.
// Absence is retained just as presence is; neither network AD nor a disk file
// can replace these observations from the live authenticated daemon.
type ResolvedDNSSECQuestion struct {
	Name string
	Type uint16
}
type ResolvedDNSSECInputs struct {
	TrustAnchors    []string
	InsecureDomains []string
}
type ResolvedDNSSECPlan struct {
	policy, canonical []byte
	name, mode        string
	index             int32
	observations      [][]byte
	questions         []ResolvedDNSSECQuestion
	inputs            ResolvedDNSSECInputs
	explicitInsecure  bool
	rootDecision      []byte
	emptyRootTrust    bool
}

func resolvedDNSSECRoute(policy ResolvedPolicy, name string, index int32) (ResolvedRoute, error) {
	routes, err := policy.ResolvedRoutes(name)
	if err != nil {
		return ResolvedRoute{}, err
	}
	var found *ResolvedRoute
	for _, route := range routes {
		if route.Index == index {
			if found != nil {
				return ResolvedRoute{}, errors.New("ambiguous original DNSSEC scope")
			}
			copy := route
			found = &copy
		}
	}
	if found == nil || found.CurrentDNS == nil || found.DNSSEC != "yes" && found.DNSSEC != "allow-downgrade" {
		return ResolvedRoute{}, errors.New("DNSSEC plan omitted original selected validating scope")
	}
	return *found, nil
}
func resolvedDNSSECSuffixes(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var out []string
	for name != "" {
		out = append(out, name)
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	return append(out, ".")
}
func ResolvedDNSSECQuestions(policy ResolvedPolicy, name string, index int32) ([]ResolvedDNSSECQuestion, error) {
	if _, err := resolvedDNSSECRoute(policy, name, index); err != nil {
		return nil, err
	}
	var out []ResolvedDNSSECQuestion
	for _, suffix := range resolvedDNSSECSuffixes(name) {
		out = append(out, ResolvedDNSSECQuestion{suffix, 43}, ResolvedDNSSECQuestion{suffix, 48})
	}
	return out, nil
}
func resolvedDNSSECSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, name := range names {
		out[strings.ToLower(strings.TrimSuffix(name, "."))] = true
	}
	return out
}
func resolvedDNSSECNegative(name string, global, link, positiveDS map[string]bool) bool {
	// systemd v257 resolved-dns-trust-anchor.c:565 checks the exact global NTA
	// before positive DS at each suffix. Its second positive test is KEY(25),
	// not DNSKEY(48); loaded positive observations only expose DS/DNSKEY.
	// resolved-dns-transaction.c:2355 then checks per-link NTAs independently;
	// resolved-link.c link_negative_trust_anchor_lookup has no positive exception.
	for _, suffix := range resolvedDNSSECSuffixes(name) {
		key := strings.TrimSuffix(suffix, ".")
		if global[key] {
			return true
		}
		if positiveDS[key] {
			break
		}
	}
	for _, suffix := range resolvedDNSSECSuffixes(name) {
		if link[strings.TrimSuffix(suffix, ".")] {
			return true
		}
	}
	return false
}
func resolvedDNSSECText(rr []byte, name string, kind uint16) (string, error) {
	if !resolvedAnchorRecord(rr, name, kind) {
		return "", errors.New("invalid original standalone trust anchor")
	}
	offset := 0
	for rr[offset] != 0 {
		offset += 1 + int(rr[offset])
	}
	offset++
	ttl := binary.BigEndian.Uint32(rr[offset+4:])
	data := rr[offset+10:]
	owner := strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	if name == "." {
		owner = "."
	}
	if kind == 43 {
		return fmt.Sprintf("%s %d IN DS %d %d %d %s", owner, ttl, binary.BigEndian.Uint16(data), data[2], data[3], strings.ToUpper(hex.EncodeToString(data[4:]))), nil
	}
	return fmt.Sprintf("%s %d IN DNSKEY %d %d %d %s", owner, ttl, binary.BigEndian.Uint16(data), data[2], data[3], base64.StdEncoding.EncodeToString(data[4:])), nil
}

// BuildResolvedDNSSECPlan never enables validating traffic. It compiles one
// exact question/scope's immutable original trust inputs; a newly discovered
// CNAME/DNAME target requires another captured plan and fresh validator context.
func BuildResolvedDNSSECPlan(policy ResolvedPolicy, name string, index int32, observations []ResolvedAnchorResult) (*ResolvedDNSSECPlan, error) {
	return buildResolvedDNSSECPlan(policy, name, index, observations, nil)
}
func buildResolvedDNSSECPlan(policy ResolvedPolicy, name string, index int32, observations []ResolvedAnchorResult, root *ResolvedRootDSDecision) (*ResolvedDNSSECPlan, error) {
	route, err := resolvedDNSSECRoute(policy, name, index)
	if err != nil {
		return nil, err
	}
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	digest := ResolvedPolicySHA256(raw)
	questions, err := ResolvedDNSSECQuestions(policy, name, index)
	if err != nil {
		return nil, err
	}
	expected := len(questions)
	if root != nil {
		if !root.Matches(policy, name, index) {
			return nil, errors.New("typed root decision changed original policy/scope")
		}
		expected--
	}
	if len(observations) != expected {
		return nil, errors.New("DNSSEC plan omitted present or absent suffix observation")
	}
	p := &ResolvedDNSSECPlan{policy: bytes.Clone(raw), name: strings.ToLower(strings.TrimSuffix(name, ".")), mode: route.DNSSEC, index: index, questions: questions}
	positiveDS := map[string]bool{}
	material := make([]ResolvedAnchorResult, 0, len(questions))
	cursor := 0
	for _, q := range questions {
		if root != nil && q.Name == "." && q.Type == 43 {
			raw, err := root.Canonical()
			if err != nil {
				return nil, err
			}
			p.rootDecision = bytes.Clone(raw)
			tagged, err := json.Marshal(struct {
				RootDS json.RawMessage `json:"root_ds"`
			}{raw})
			if err != nil {
				return nil, err
			}
			p.observations = append(p.observations, tagged)
			if root.Root != nil {
				material = append(material, *root.Root)
				positiveDS[""] = true
			}
			continue
		}
		observation := observations[cursor]
		cursor++
		body, err := observation.Canonical()
		if err != nil {
			return nil, err
		}
		if observation.PolicySHA256 != digest || observation.Index != index || observation.Name != q.Name || observation.Type != q.Type {
			return nil, errors.New("DNSSEC observation changed original policy, scope or suffix")
		}
		p.observations = append(p.observations, bytes.Clone(body))
		material = append(material, observation)
		if observation.Present && q.Type == 43 {
			positiveDS[strings.TrimSuffix(q.Name, ".")] = true
		}
	}
	anyPositive := false
	for _, observation := range material {
		anyPositive = anyPositive || observation.Present
	}
	p.emptyRootTrust = root != nil && root.Outcome == "synthetic-unsigned" && !anyPositive
	global := resolvedDNSSECSet(route.GlobalNegativeTrustAnchors)
	link := map[string]bool{}
	if route.Index != 0 {
		link = resolvedDNSSECSet(route.NegativeTrustAnchors)
	}
	p.explicitInsecure = resolvedDNSSECNegative(p.name, global, link, positiveDS)
	seen := map[string]bool{}
	for _, names := range [][]string{route.GlobalNegativeTrustAnchors, route.NegativeTrustAnchors} {
		for _, domain := range names {
			domain = strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
			if !seen[domain] {
				seen[domain] = true
				p.inputs.InsecureDomains = append(p.inputs.InsecureDomains, domain)
			}
		}
	}
	// Omit only positive inputs whose owner is explicitly shadowed under the
	// original daemon's NTA rules. Their full observations remain in the plan and
	// must still be rechecked, so suppression cannot conceal store changes.
	for _, observation := range material {
		if !observation.Present || resolvedDNSSECNegative(observation.Name, global, link, positiveDS) {
			continue
		}
		for _, rr := range observation.Records {
			text, err := resolvedDNSSECText(rr, observation.Name, observation.Type)
			if err != nil {
				return nil, err
			}
			p.inputs.TrustAnchors = append(p.inputs.TrustAnchors, text)
		}
	}
	if root != nil && root.Outcome == "synthetic-unsigned" && anyPositive && len(p.inputs.TrustAnchors) == 0 {
		return nil, errors.New("synthetic root cannot discard captured positive trust islands")
	}
	wire := struct {
		Schema             int
		PolicySHA256, Name string
		Index              int32
		DNSSEC             string
		Observations       []json.RawMessage
		Inputs             ResolvedDNSSECInputs
	}{Schema: 1, PolicySHA256: digest, Name: p.name, Index: index, DNSSEC: p.mode, Inputs: p.inputs}
	for _, body := range p.observations {
		wire.Observations = append(wire.Observations, json.RawMessage(body))
	}
	p.canonical, err = json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (p *ResolvedDNSSECPlan) Canonical() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.canonical)
}
func (p *ResolvedDNSSECPlan) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}
func (p *ResolvedDNSSECPlan) Index() int32 {
	if p == nil {
		return -1
	}
	return p.index
}

// Mode preserves strict versus allow-downgrade. Neither mode permits adopting
// a bogus result, and this plan grants no policy-compatible downgrade decision.
func (p *ResolvedDNSSECPlan) Mode() string {
	if p == nil {
		return ""
	}
	return p.mode
}
func (p *ResolvedDNSSECPlan) Questions() []ResolvedDNSSECQuestion {
	if p == nil {
		return nil
	}
	return append([]ResolvedDNSSECQuestion(nil), p.questions...)
}
func (p *ResolvedDNSSECPlan) MatchesPolicy(policy ResolvedPolicy) bool {
	if p == nil {
		return false
	}
	raw, err := policy.Canonical()
	return err == nil && bytes.Equal(raw, p.policy)
}
func (p *ResolvedDNSSECPlan) Recheck(observations []ResolvedAnchorResult) error {
	if p == nil || len(p.rootDecision) != 0 || len(observations) != len(p.observations) {
		return errors.New("DNSSEC recheck omitted original loaded-store observations")
	}
	for i, r := range observations {
		raw, err := r.Canonical()
		if err != nil || !bytes.Equal(raw, p.observations[i]) {
			return errors.New("original DNSSEC presence, absence or loaded record changed")
		}
	}
	return nil
}
func (p *ResolvedDNSSECPlan) Inputs() ResolvedDNSSECInputs {
	if p == nil {
		return ResolvedDNSSECInputs{}
	}
	return ResolvedDNSSECInputs{append([]string(nil), p.inputs.TrustAnchors...), append([]string(nil), p.inputs.InsecureDomains...)}
}

// ValidatorInputs reports the current pinned ABI's capacity without truncating
// the complete plan. The ABI can grow only with matching native bounds/tests.
func (p *ResolvedDNSSECPlan) ValidatorInputs() (ResolvedDNSSECInputs, error) {
	if p == nil {
		return ResolvedDNSSECInputs{}, errors.New("missing original DNSSEC plan")
	}
	if len(p.inputs.TrustAnchors) == 0 && !p.explicitInsecure && !p.emptyRootTrust {
		return ResolvedDNSSECInputs{}, errors.New("original trust-store absence is not an insecure-domain decision")
	}
	if len(p.inputs.TrustAnchors) > 32 || len(p.inputs.InsecureDomains) > 32 {
		return ResolvedDNSSECInputs{}, errors.New("complete original DNSSEC plan exceeds current validator input count")
	}
	total := 0
	for _, text := range p.inputs.TrustAnchors {
		total += len(text)
		if len(text) > 4096 || total > 32768 {
			return ResolvedDNSSECInputs{}, errors.New("complete original DNSSEC plan exceeds current validator input bytes")
		}
	}
	return p.Inputs(), nil
}
