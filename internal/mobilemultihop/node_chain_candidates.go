package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	"router-vpn/internal/hopmeasure"
)

// Revision belongs to the original host catalog, including its change-away-and-
// back generation. Inputs are exact validated private launch captures, not a
// host-supplied list of addresses or outbound tags.
type NodeChainCandidateInventory struct {
	Schema   int      `json:"schema"`
	Revision string   `json:"revision"`
	Inputs   []string `json:"inputs"`
}

// The host must observe both its live connection and the complete original
// candidate catalog at admission and publication. An immutable copied catalog
// alone cannot establish that a saved source has not changed or been removed.
type NodeChainCandidateOwner interface {
	NodeChainMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}

type NodeChainCandidatePlan struct {
	chain     *NodeChain
	inventory string
	revision  string
	prefix    NodeChainProof
	targets   []hopmeasure.CandidateTarget
	capture   string
	seal      string
}

func (c *NodeChain) NewCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	if c == nil || c.validateCapture() != nil || position < 0 || position >= len(c.proofs) ||
		c.nodes[position] == nil || !NodeChainPrefixMode(c.proofs[position].Mode) {
		// WG/AWG TCP dialing waits for the destination handshake. A lazy SS
		// stream would measure an upstream socket instead, so cannot acquire
		// this particular TCP connection timing capability.
		return nil, errors.New("candidate timing requires an original paired packet prefix")
	}
	var record NodeChainCandidateInventory
	if exactJSON([]byte(inventory), &record, NodeChainInputLimit) != nil || record.Schema != 1 ||
		!nodeChainIdentityText(record.Revision) || len(record.Inputs) == 0 || len(record.Inputs) > hopmeasure.CandidateMaximumTargets {
		return nil, errors.New("candidate timing requires the complete original source inventory")
	}
	plan := &NodeChainCandidatePlan{chain: c, inventory: inventory, revision: record.Revision, prefix: c.proofs[position]}
	ids, proofs := map[string]bool{}, map[string]bool{}
	for _, member := range c.proofs[:position+1] {
		ids[member.ProfileID] = true
		if member.NodeID != "" {
			proofs[member.NodeID] = true
		}
	}
	for _, input := range record.Inputs {
		target, proof, err := nodeChainCandidateTarget(input)
		if err != nil || ids[target.ID] || proof != "" && proofs[proof] {
			return nil, errors.Join(err, errors.New("candidate source duplicates or changes the captured prefix inventory"))
		}
		ids[target.ID] = true
		if proof != "" {
			proofs[proof] = true
		}
		plan.targets = append(plan.targets, target)
	}
	raw, _ := json.Marshal([]any{"routervpn-node-chain-candidate-capture-v1", c.SourceSHA256(), c.ConfigSHA256(), plan.prefix, inventory})
	plan.capture = externalDigest(raw)
	clear(raw)
	plan.seal = plan.digest()
	return plan, plan.validate()
}

// NodeChainCandidateInputSupported is a socket-free eligibility check using
// the same exact original-source compiler as candidate plan construction. It
// exposes no endpoint, credentials or reusable native route capability.
func NodeChainCandidateInputSupported(input string) bool {
	if len(input) == 0 || len(input) > NodeChainInputLimit {
		return false
	}
	_, _, err := nodeChainCandidateTarget(input)
	return err == nil
}

// Original literal SS2022, SOCKS5 and HTTP/HTTPS CONNECT sources supply a candidate
// TCP endpoint. This measures connection establishment, not the candidate's
// authentication or TLS. UDP-only transports never gain a guessed TCP port.
func nodeChainCandidateTarget(input string) (hopmeasure.CandidateTarget, string, error) {
	bad := errors.New("candidate requires its original literal unlayered SS2022 source")
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(input), &header) != nil {
		return hopmeasure.CandidateTarget{}, "", bad
	}
	if header.Kind == "routervpn-node-chain-socks-member" {
		// The existing typed SOCKS compiler owns version, credentials, literal
		// transport and Off-layer admission. A TCP score never grants a UDP
		// association or proves SOCKS authentication.
		middle, err := parseNodeChainSOCKSMember(input)
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		closure, err := middle.closure()
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		target, err := nodeChainCandidateLiteralTarget(middle.selection.ExitID, middle.source, closure.final)
		return target, "", err
	}
	if header.Kind == "routervpn-node-chain-connect-member" {
		// Keep CONNECT's complete source compiler authoritative for protocol,
		// credentials, verified-TLS configuration, literal address and Off layer.
		// No ordinary NodeProfile or host-provided endpoint grants this scope.
		middle, err := parseNodeChainCONNECTMember(input)
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		closure, err := middle.closure()
		if err != nil {
			return hopmeasure.CandidateTarget{}, "", err
		}
		target, err := nodeChainCandidateLiteralTarget(middle.selection.ExitID, middle.source, closure.final)
		return target, "", err
	}
	var closure *externalPredecessor
	var id, source, proof string
	var err error
	if header.Kind == "routervpn-node-chain-imported-member" {
		middle, parseErr := parseNodeChainImportedMember(input)
		if parseErr != nil {
			return hopmeasure.CandidateTarget{}, "", parseErr
		}
		closure, err = middle.closure()
		id, source = middle.id(), middle.source
	} else {
		node, parseErr := ParseNodeLaunchInput(input)
		if parseErr != nil || node == nil || node.mode != "shadowsocks" {
			return hopmeasure.CandidateTarget{}, "", bad
		}
		layer := predecessorText(node.profile, "start_layer")
		if layer != "" && layer != "off" {
			return hopmeasure.CandidateTarget{}, "", bad
		}
		closure, err = nodeMultihopPredecessor(node)
		id, source, proof = predecessorText(node.profile, "id"), node.SourceSHA256(), predecessorText(node.profile, "node_proof_id")
	}
	if err != nil || closure == nil || closure.final["type"] != "shadowsocks" ||
		closure.final["detour"] != nil || closure.final["domain_resolver"] != nil ||
		closure.final["network"] != nil || closure.final["udp_over_tcp"] != nil ||
		!importedSS2022Credentials(predecessorText(closure.final, "method"), predecessorText(closure.final, "password")) {
		return hopmeasure.CandidateTarget{}, "", bad
	}
	target, err := nodeChainCandidateLiteralTarget(id, source, closure.final)
	return target, proof, err
}

// Called only after the candidate's original typed compiler validated its
// complete closure. Never resolve an arbitrary host or infer a default port.
func nodeChainCandidateLiteralTarget(id, source string, final map[string]any) (hopmeasure.CandidateTarget, error) {
	address, err := netip.ParseAddr(predecessorText(final, "server"))
	port, ok := final["server_port"].(float64)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() ||
		!ok || math.IsNaN(port) || math.IsInf(port, 0) || math.Trunc(port) != port || port < 1 || port > 65535 {
		return hopmeasure.CandidateTarget{}, errors.New("candidate requires its captured literal TCP address and port")
	}
	return hopmeasure.CandidateTarget{ID: id, SourceSHA256: source, Address: net.JoinHostPort(address.String(), strconv.Itoa(int(port)))}, nil
}

func (p *NodeChainCandidatePlan) CaptureSHA256() string {
	if p == nil {
		return ""
	}
	return p.capture
}

// Metadata is safe for the chooser. It contains no private endpoint, source
// input, API token, PSK or reusable native dialing capability.
func (p *NodeChainCandidatePlan) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	type member struct {
		ID     string `json:"id"`
		Source string `json:"source_sha256"`
	}
	targets := make([]member, len(p.targets))
	for i, target := range p.targets {
		targets[i] = member{target.ID, target.SourceSHA256}
	}
	raw, _ := json.Marshal(struct {
		Schema         int      `json:"schema"`
		Capture        string   `json:"capture_sha256"`
		PrefixPosition int      `json:"prefix_position"`
		PrefixID       string   `json:"prefix_id"`
		Source         string   `json:"source_sha256"`
		Config         string   `json:"config_sha256"`
		Targets        []member `json:"targets"`
	}{1, p.capture, p.prefix.Position, p.prefix.ProfileID, p.chain.SourceSHA256(), p.chain.ConfigSHA256(), targets})
	return string(raw)
}

func (p *NodeChainCandidatePlan) digest() string {
	if p == nil || p.chain == nil {
		return ""
	}
	raw, _ := json.Marshal([]any{p.chain.SourceSHA256(), p.chain.ConfigSHA256(), p.inventory, p.revision, p.prefix, p.targets, p.capture})
	defer clear(raw)
	return externalDigest(raw)
}

func (p *NodeChainCandidatePlan) validate() error {
	if p == nil || p.chain == nil || p.chain.validateCapture() != nil || p.seal == "" || p.seal != p.digest() ||
		p.prefix.Position < 0 || p.prefix.Position >= len(p.chain.proofs) || p.prefix != p.chain.proofs[p.prefix.Position] {
		return errors.New("candidate plan changed its sealed original capture")
	}
	return nil
}

func (p *NodeChainCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainCandidateOwner) (*hopmeasure.CandidateService, error) {
	if ctx == nil {
		return nil, errors.New("candidate measurement requires an original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.validate() != nil || owner == nil {
		return nil, errors.New("candidate measurement lost its original source owner")
	}
	active, err := owner.MeasurementChainContext(ctx)
	if err != nil || active == nil || active.SourceSHA256() != p.chain.SourceSHA256() || active.ConfigSHA256() != p.chain.ConfigSHA256() {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	identity, reader := active.runtime.identity, active.runtime.engine
	active.runtime.mu.Unlock()
	engine := &nodeChainCandidateEngine{plan: p, owner: owner, active: active, identity: identity, reader: reader}
	return hopmeasure.NewPrefixCandidatesContext(ctx, engine,
		hopmeasure.CandidatePrefix{Position: p.prefix.Position, ID: p.prefix.ProfileID, Tag: p.prefix.Tag, CaptureSHA256: p.capture}, p.targets)
}

type nodeChainCandidateEngine struct {
	plan     *NodeChainCandidatePlan
	owner    NodeChainCandidateOwner
	active   *NodeChain
	identity NodeChainIdentity
	reader   NodeChainEngine
	revoked  atomic.Bool
}

func (e *nodeChainCandidateEngine) current(ctx context.Context) (active *NodeChain, err error) {
	if ctx == nil {
		return nil, hopmeasure.ErrStale
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.revoked.Load() {
		return nil, hopmeasure.ErrStale
	}
	defer func() {
		// An observed foreign catalog/reader/native owner cannot revive this
		// capture by changing back. A canceled caller alone is not a mutation.
		if err != nil && ctx.Err() == nil {
			e.revoked.Store(true)
		}
	}()
	if e.plan.validate() != nil || e.reader == nil {
		return nil, hopmeasure.ErrStale
	}
	if err := e.owner.CandidateInventoryCurrentContext(ctx, e.plan.capture); err != nil {
		return nil, err
	}
	active, err = e.owner.MeasurementChainContext(ctx)
	if err != nil || active != e.active || active == nil || active.SourceSHA256() != e.plan.chain.SourceSHA256() || active.ConfigSHA256() != e.plan.chain.ConfigSHA256() {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	identity, reader := active.runtime.identity, active.runtime.engine
	active.runtime.mu.Unlock()
	if identity != e.identity || reader != e.reader {
		return nil, hopmeasure.ErrStale
	}
	return active, ctx.Err()
}

func (e *nodeChainCandidateEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}
func (e *nodeChainCandidateEngine) IdentityContext(ctx context.Context) (string, error) {
	if _, err := e.current(ctx); err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{e.identity, e.plan.capture})
	return string(raw), err
}
func (e *nodeChainCandidateEngine) VerifyMeasurement(ctx context.Context) error {
	_, err := e.current(ctx)
	return err
}
func (e *nodeChainCandidateEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := e.current(ctx); err != nil {
		return nil, err
	}
	release, err := e.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, errors.New("candidate measurement activity unavailable"))
	}
	if _, err := e.current(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (e *nodeChainCandidateEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	active, err := e.current(ctx)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, target := range e.plan.targets {
		allowed = allowed || target.Address == address
	}
	if tag != e.plan.prefix.Tag || !allowed {
		return nil, errors.New("candidate dial differs from the captured prefix or original endpoint")
	}
	connection, err := active.dial(ctx, tag, address)
	_, observeErr := e.current(ctx)
	if err != nil || observeErr != nil || ctx.Err() != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, errors.Join(err, observeErr, ctx.Err())
	}
	return connection, nil
}
