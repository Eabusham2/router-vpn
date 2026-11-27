package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// This carrier belongs only to one first-suffix candidate. It is never exposed
// as the active Server worker's carrier or as a retained prefix outbound.
type nodeChainServerFirstPacketCandidateCarrier struct {
	self        *nodeChainServerFirstPacketCandidateCarrier
	carrier     *NodeChainServerCarrier
	source      string
	capture     string
	dialOptions string
}

func (p *NodeChainServerPolicy) firstPacketCandidateSource(c multihoprelay.NodeChainCandidateCapture, r *NodeChainServerPacketCandidateResponder) (string, int, error) {
	if p == nil || c.Request.Schema != 5 || !r.valid(c) || p.validateCapture() != nil || !p.descriptor.FirstPacketCandidateResponse(c.Request.CandidateMode) {
		return "", 0, nodeChainServerError
	}
	if _, err := p.FirstPacketResponseCandidateTarget(c); err != nil {
		return "", 0, err
	}
	var source NodeChainServerSource
	if exactJSON([]byte(p.sourceJSON), &source, NodeChainInputLimit) != nil || len(source.Nodes) < 2 || source.Schema != 1 && source.Schema != 6 {
		return "", 0, nodeChainServerError
	}
	source.Nodes[0], source.IdentitySources[0] = r.original.Input, r.original.IdentitySource
	pair := r.original.Pair
	pair.Position = 1
	pairs := make([]NodeChainPacketCandidatePair, 0, len(source.PacketCandidatePairs)+1)
	for _, old := range source.PacketCandidatePairs {
		if old.Position != 1 {
			pairs = append(pairs, old)
		}
	}
	source.PacketCandidatePairs = append(pairs, pair)
	if !sameServerPacketReplacementAt(p, source, 0) {
		return "", 0, nodeChainServerError
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return "", 0, err
	}
	defer clear(raw)
	family := 0
	if source.Schema == 6 {
		family = 6
	}
	// Compile every member before opening a route observer. No prospective
	// endpoint, DNS transport, listener or application route is started here.
	prospective, err := newNodeChainServerPolicyFamily(string(raw), nil, family)
	if err != nil || prospective.blockIPv6 != p.blockIPv6 || !reflect.DeepEqual(prospective.blockedCIDRs, p.blockedCIDRs) || len(prospective.proofs) != len(p.proofs) {
		return "", 0, nodeChainServerError
	}
	return prospective.sourceJSON, family, nil
}

// NewFirstPacketRequestContext is the distinct first-suffix entry point. The
// caller publishes its original Prepare join before calling this constructor.
// A non-nil request is returned with any late error so its carrier can be joined.
func (r *NodeChainServerPacketCandidateResponder) NewFirstPacketRequestContext(ctx, lifetime context.Context, policy *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture, reader NodeChainServerPacketEngine) (*NodeChainServerCandidatePacketRequest, error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || c.Request.Schema != 5 || !r.valid(c) || reader == nil || !reflect.TypeOf(reader).Comparable() {
		return nil, nodeChainServerError
	}
	source, family, err := policy.firstPacketCandidateSource(c, r)
	if err != nil {
		return nil, err
	}
	owner := &nodeChainServerFirstPacketCandidateCarrier{source: source, capture: r.capture}
	owner.self = owner
	request := &NodeChainServerCandidatePacketRequest{reader: reader, policy: policy, responder: r, capture: c.Clone(), source: r.source, first: owner}
	request.self = request
	owner.carrier, err = newNodeChainServerFirstCandidateCarrierContext(ctx, lifetime, source, family)
	if err != nil || owner.carrier == nil || ctx.Err() != nil || lifetime.Err() != nil {
		return request, errors.Join(err, ctx.Err(), lifetime.Err(), nodeChainServerError)
	}
	prospective, err := owner.carrier.ProjectContext(ctx)
	if err != nil || prospective == nil || prospective.sourceJSON != source || prospective.carrier != owner.carrier || prospective.blockIPv6 != policy.blockIPv6 || !reflect.DeepEqual(prospective.blockedCIDRs, policy.blockedCIDRs) || len(prospective.proofs) != len(policy.proofs) {
		return request, errors.Join(err, nodeChainServerError)
	}
	endpoints, err := packetCandidateEndpoints(prospective.config)
	if err != nil {
		return request, err
	}
	endpoint := endpoints[prospective.proofs[0].Tag]
	carrierTag := "routervpn-server-carrier-" + owner.carrier.seal[:24]
	if endpoint == nil || endpoint["type"] != nodeChainPrefixType(c.Request.CandidateMode) || endpoint["detour"] != carrierTag || !candidateUnboundPacket(endpoint) {
		return request, nodeChainServerError
	}
	// These options came from the complete compiler using this observer's
	// interface and route bounds, including its actual WG/AWG envelope.
	delete(endpoint, "detour")
	endpoint["tag"] = "proxy"
	raw, err := json.Marshal(endpoint)
	if err != nil {
		return request, err
	}
	request.source.PacketOptions = string(raw)
	request.optionsSHA = externalDigest(raw)
	clear(raw)
	binding := map[string]string{"bind_interface": owner.carrier.snapshot.InterfaceName}
	field := "inet4_bind_address"
	if netip.MustParseAddr(owner.carrier.snapshot.SourceAddress).Is6() {
		field = "inet6_bind_address"
	}
	binding[field] = owner.carrier.snapshot.SourceAddress
	raw, err = json.Marshal(binding)
	if err != nil {
		return request, err
	}
	owner.dialOptions = string(raw)
	if owner.carrier.source != source || owner.carrier.CurrentContext(ctx) != nil || lifetime.Err() != nil {
		return request, nodeChainServerError
	}
	return request, nil
}

func (r *NodeChainServerCandidatePacketRequest) originalFirstCarrier() bool {
	return r != nil && r.self == r && r.capture.Request.Schema == 5 && r.capture.Request.Position == 0 && r.tag == "" && r.first != nil && r.first.self == r.first && r.first.carrier != nil && r.responder.valid(r.capture) && r.first.capture == r.responder.capture && r.first.source == r.first.carrier.source && r.first.dialOptions != ""
}

// FirstCarrierAdmitContext only observes this original owner. It grants no
// dialer, endpoint, or permission to replace the active Server graph.
func (r *NodeChainServerCandidatePacketRequest) FirstCarrierAdmitContext(ctx context.Context) error {
	if !r.originalFirstCarrier() {
		return nodeChainServerError
	}
	return r.first.carrier.AdmitContext(ctx)
}

func (r *NodeChainServerCandidatePacketRequest) FirstCarrierObserveContext(ctx context.Context, reader NodeChainServerPacketEngine, policy *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) error {
	if _, _, err := r.ReadServer(ctx, reader, policy, c); err != nil {
		return err
	}
	if !r.originalFirstCarrier() {
		return nodeChainServerError
	}
	return r.first.carrier.CurrentContext(ctx)
}

func (r *NodeChainServerCandidatePacketRequest) FirstCarrierOptions(ctx context.Context, reader NodeChainServerPacketEngine, policy *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) (string, error) {
	if err := r.FirstCarrierObserveContext(ctx, reader, policy, c); err != nil {
		return "", err
	}
	return r.first.dialOptions, nil
}

// CloseFirstCarrierContext is called only after Prepare, reads, samples and the
// actual packet endpoint have joined. Failure keeps the original owner retained.
func (r *NodeChainServerCandidatePacketRequest) CloseFirstCarrierContext(ctx context.Context) error {
	if r == nil || r.self != r || r.capture.Request.Schema != 5 || r.first == nil || r.first.self != r.first {
		return nodeChainServerError
	}
	if r.first.carrier == nil {
		return nil
	}
	return r.first.carrier.CloseContext(ctx)
}
