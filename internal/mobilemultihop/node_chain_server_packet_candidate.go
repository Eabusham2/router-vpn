package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net"
	"reflect"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

type NodeChainServerPacketCandidateResponder struct {
	self     *NodeChainServerPacketCandidateResponder
	capture  string
	original nodeChainServerPacketCandidateInput
	node     *NodeProfile
	source   candidateResponseSource
}

func NewNodeChainServerPacketCandidateResponder(c multihoprelay.NodeChainCandidateCapture, input string) (*NodeChainServerPacketCandidateResponder, error) {
	seal, err := c.Digest()
	var original nodeChainServerPacketCandidateInput
	if err != nil || !c.Request.IsPacketResponse() || exactJSON([]byte(input), &original, NodeChainInputLimit) != nil ||
		original.Schema != 1 || !proofID.MatchString(original.RegistrationSHA256) {
		return nil, nodeChainServerError
	}
	node, err := ParseNodeLaunchInput(original.Input)
	if err != nil || original.Pair.validateServer(node) != nil || validateNodeChainIdentity(original.IdentitySource, node) != nil {
		return nil, nodeChainServerError
	}
	pair := original.Pair
	q := c.Request
	response, err := parseCandidateNativeResponseSource(original.Input, q.CandidateMode)
	if err != nil || pair.LocalSourceSHA256 != q.CandidateSourceSHA256 || pair.LocalClientPublicKey != q.CandidateClientPublicKey ||
		pair.ProfileID != q.CandidateID || pair.Mode != q.CandidateMode || response.Target.ID != q.CandidateID || response.Target.Address != q.Address ||
		pair.NodeID == c.Lease.Source.EntryNodeID || pair.ProfileID == c.Lease.Source.EntryID {
		return nil, nodeChainServerError
	}
	keys := map[string]bool{pair.ServerClientPublicKey: true, pair.PeerPublicKey: true, pair.LocalClientPublicKey: true}
	for _, key := range c.Lease.Request.LocalPacketPublicKeys {
		if keys[key] {
			return nil, nodeChainServerError
		}
	}
	for _, member := range c.Lease.Source.Members {
		if member.NodeID == pair.NodeID || member.ProfileID == pair.ProfileID || keys[member.ClientPublicKey] || keys[member.ServerPublicKey] {
			return nil, nodeChainServerError
		}
	}
	r := &NodeChainServerPacketCandidateResponder{capture: seal, original: original, node: node, source: response}
	r.self = r
	return r, nil
}
func (r *NodeChainServerPacketCandidateResponder) PairingSHA256() string {
	if r == nil || r.self != r || r.node == nil || r.original.Pair.validateServer(r.node) != nil {
		return ""
	}
	return r.original.digest()
}
func (r *NodeChainServerPacketCandidateResponder) PacketKeys() ([]string, error) {
	if r.PairingSHA256() == "" {
		return nil, nodeChainServerError
	}
	return []string{r.original.Pair.ServerClientPublicKey, r.original.Pair.PeerPublicKey, r.original.Pair.LocalClientPublicKey}, nil
}
func (r *NodeChainServerPacketCandidateResponder) valid(c multihoprelay.NodeChainCandidateCapture) bool {
	digest, err := c.Digest()
	return err == nil && r != nil && r.self == r && r.capture == digest && r.PairingSHA256() != "" && c.Request.IsPacketResponse()
}

// Compilation validates the complete prospective Server suffix under the same
// actual first carrier. No prospective graph or suffix endpoint is started.
func (p *NodeChainServerPolicy) packetCandidateOptions(c multihoprelay.NodeChainCandidateCapture, r *NodeChainServerPacketCandidateResponder) (string, error) {
	if p == nil || p.validateCapture() != nil || !r.valid(c) || !p.descriptor.PacketCandidateResponsePrefix(c.Request.Position, c.Request.CandidateMode) {
		return "", nodeChainServerError
	}
	if _, err := p.binding(c.Lease); err != nil {
		return "", err
	}
	position := c.Request.Position
	var source NodeChainServerSource
	if exactJSON([]byte(p.sourceJSON), &source, NodeChainInputLimit) != nil || position < 1 || position >= len(source.Nodes)-1 ||
		source.Schema != 1 && source.Schema != 6 {
		return "", nodeChainServerError
	}
	source.Nodes[position] = r.original.Input
	source.IdentitySources[position] = r.original.IdentitySource
	pair := r.original.Pair
	pair.Position = position + 1
	nextPairs := make([]NodeChainPacketCandidatePair, 0, len(source.PacketCandidatePairs)+1)
	for _, value := range source.PacketCandidatePairs {
		if value.Position != pair.Position {
			nextPairs = append(nextPairs, value)
		}
	}
	source.PacketCandidatePairs = append(nextPairs, pair)
	if !sameServerPacketReplacement(p, source, position) {
		return "", nodeChainServerError
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	family := 0
	if source.Schema == 6 {
		family = 6
	}
	prospective, err := newNodeChainServerPolicyFamilyReplacement(string(raw), p.carrier, family, p, position)
	if err != nil || prospective.blockIPv6 != p.blockIPv6 || !reflect.DeepEqual(prospective.blockedCIDRs, p.blockedCIDRs) || len(prospective.proofs) != len(p.proofs) ||
		!reflect.DeepEqual(prospective.proofs[:position], p.proofs[:position]) {
		return "", nodeChainServerError
	}
	normalize := func(rows []NodeChainProof) []NodeChainProof {
		copyRows := append([]NodeChainProof(nil), rows...)
		for i := range copyRows {
			copyRows[i].Position = i
		}
		return copyRows
	}
	before, err := candidatePrefixClosure(p.config, normalize(p.proofs[:position]))
	if err != nil {
		return "", err
	}
	after, err := candidatePrefixClosure(prospective.config, normalize(prospective.proofs[:position]))
	if err != nil || !reflect.DeepEqual(before, after) {
		return "", nodeChainServerError
	}
	endpoints, err := packetCandidateEndpoints(prospective.config)
	if err != nil {
		return "", err
	}
	endpoint := endpoints[prospective.proofs[position].Tag]
	if endpoint == nil || endpoint["type"] != nodeChainPrefixType(c.Request.CandidateMode) ||
		endpoint["detour"] != p.proofs[position-1].Tag || !candidateUnboundPacket(endpoint) {
		return "", nodeChainServerError
	}
	delete(endpoint, "detour")
	endpoint["tag"] = "proxy"
	raw, err = json.Marshal(endpoint)
	return string(raw), err
}

// This native worker interface is a different capability from connected Local,
// closed preparation, and selected Local. Implementations retain one original
// operation, its protected source file and its exact native prefix pointer.
type NodeChainServerPacketEngine interface {
	ServerCandidateCurrentContext(context.Context, *NodeChainServerCandidatePacketRequest) error
	DialServerCandidatePacketContext(context.Context, *NodeChainServerCandidatePacketRequest) (net.Conn, error)
}
type NodeChainServerCandidatePacketRequest struct {
	first           *nodeChainServerFirstPacketCandidateCarrier
	self            *NodeChainServerCandidatePacketRequest
	reader          NodeChainServerPacketEngine
	policy          *NodeChainServerPolicy
	responder       *NodeChainServerPacketCandidateResponder
	capture         multihoprelay.NodeChainCandidateCapture
	source          candidateResponseSource
	tag, optionsSHA string
}

func (r *NodeChainServerPacketCandidateResponder) NewPacketRequest(ctx context.Context, policy *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture, reader NodeChainServerPacketEngine) (*NodeChainServerCandidatePacketRequest, error) {
	if ctx == nil || ctx.Err() != nil || c.Request.Schema != 4 || !r.valid(c) || reader == nil || !reflect.TypeOf(reader).Comparable() {
		return nil, nodeChainServerError
	}
	options, err := policy.packetCandidateOptions(c, r)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	source := r.source
	source.PacketOptions = options
	q := &NodeChainServerCandidatePacketRequest{reader: reader, policy: policy, responder: r, capture: c.Clone(), source: source,
		tag: policy.proofs[c.Request.Position-1].Tag, optionsSHA: externalDigest([]byte(options))}
	q.self = q
	return q, nil
}
func (r *NodeChainServerCandidatePacketRequest) ReadServer(ctx context.Context, reader NodeChainServerPacketEngine, policy *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.self != r || reader == nil || !reflect.TypeOf(reader).Comparable() ||
		reader != r.reader || policy == nil || policy != r.policy || policy.validateCapture() != nil || !r.responder.valid(c) ||
		!reflect.DeepEqual(c, r.capture) || r.source.PacketOptions == "" || r.optionsSHA != externalDigest([]byte(r.source.PacketOptions)) {
		return "", "", nodeChainServerError
	}
	if _, err := policy.binding(c.Lease); err != nil {
		return "", "", err
	}
	if c.Request.Schema == 5 {
		if r.tag != "" || r.FirstCarrierAdmitContext(ctx) != nil {
			return "", "", nodeChainServerError
		}
	} else if c.Request.Schema != 4 || r.first != nil || c.Request.Position < 1 || r.tag != policy.proofs[c.Request.Position-1].Tag {
		return "", "", nodeChainServerError
	}
	if err := reader.ServerCandidateCurrentContext(ctx, r); err != nil {
		return "", "", err
	}
	return r.tag, r.source.Target.Address, nil
}
func (r *NodeChainServerCandidatePacketRequest) nativePacketCurrent(ctx context.Context) error {
	_, _, err := r.ReadServer(ctx, r.reader, r.policy, r.capture)
	return err
}
func (r *NodeChainServerCandidatePacketRequest) nativePacketSource() candidateResponseSource {
	return r.source
}
func (r *NodeChainServerCandidatePacketRequest) nativePacketMode() string {
	return r.capture.Request.CandidateMode
}
func (r *NodeChainServerCandidatePacketRequest) nativePacketAddress() string {
	return r.source.Target.Address
}
func (r *NodeChainServerCandidatePacketRequest) dial(ctx context.Context) (net.Conn, error) {
	if err := r.nativePacketCurrent(ctx); err != nil {
		return nil, err
	}
	conn, err := r.reader.DialServerCandidatePacketContext(ctx, r)
	return conn, errors.Join(err, r.nativePacketCurrent(ctx), ctx.Err())
}
func (r *NodeChainServerPacketCandidateResponder) ReplyPacket(ctx context.Context, c multihoprelay.NodeChainCandidateCapture, endpoint NodeChainCandidateEndpoint, nonce, request string) (string, error) {
	if ctx == nil || ctx.Err() != nil || endpoint == nil || !r.ValidChallenge(c, nonce, request) {
		return "", nodeChainServerError
	}
	var reply string
	err := r.source.exchangeChallenge(ctx, func(call context.Context, tag, address string) (net.Conn, error) {
		if tag != "selected-server-packet-candidate" {
			return nil, nodeChainServerError
		}
		return endpoint.DialPrivate(call, address)
	}, "selected-server-packet-candidate", nonce, func(value string) error { reply = value; return ctx.Err() })
	if err != nil || reply == "" {
		return "", errors.Join(err, nodeChainServerError)
	}
	return reply, nil
}

func (r *NodeChainServerPacketCandidateResponder) ValidChallenge(c multihoprelay.NodeChainCandidateCapture, nonce, request string) bool {
	return r.valid(c) && hopmeasure.ValidCandidateNonce(nonce) && hmac.Equal([]byte(request), []byte(hopmeasure.CandidateChallengeMAC(r.source.Token, r.source.NodeID, nonce, false)))
}
