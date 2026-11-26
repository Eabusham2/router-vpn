package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"

	"router-vpn/internal/hopmeasure"
)

// Only the pinned native build supplies the Shadowsocks2022 cipher. The
// standalone source compiler can describe, but cannot execute, this capability.
var wrapCandidateSS2022 func(context.Context, net.Conn, string, string, string) (net.Conn, error)

// The pinned native build supplies the actual QUIC client. Its packet request
// retains the original Local reader; no general-purpose dialer is accepted.
var openCandidateHysteria2 func(context.Context, *NodeChainCandidatePacketRequest, string) (net.Conn, error)

type candidateResponseSource struct {
	Target                               hopmeasure.CandidateTarget
	NodeID, API, Token, Method, Password string
	Hysteria2Options                     string `json:",omitempty"`
	PacketMode, PacketOptions            string `json:",omitempty"`
}

func parseCandidatePacketResponseSource(input, mode string) (candidateResponseSource, error) {
	bad := errors.New("candidate response requires its original paired WG/AWG source with Start Layer off")
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil || !NodeChainPrefixMode(mode) || node.mode != mode {
		return candidateResponseSource{}, bad
	}
	layer := predecessorText(node.profile, "start_layer")
	api, apiErr := privateAPI(predecessorText(node.profile, "router_api"))
	token, proof := predecessorText(node.profile, "api_token"), predecessorText(node.profile, "node_proof_id")
	if layer != "" && layer != "off" || apiErr != nil || token == "" || !proofID.MatchString(proof) {
		return candidateResponseSource{}, bad
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || closure == nil || closure.final["type"] != nodeChainPrefixType(mode) ||
		closure.final["system"] != false || closure.final["detour"] != nil || closure.final["domain_resolver"] != nil || closure.final["realm"] != nil {
		return candidateResponseSource{}, bad
	}
	if port, present := closure.final["listen_port"]; present && port != float64(0) {
		return candidateResponseSource{}, bad
	}
	peers, ok := closure.final["peers"].([]any)
	if !ok || len(peers) != 1 {
		return candidateResponseSource{}, bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return candidateResponseSource{}, bad
	}
	target, err := nodeChainCandidateLiteralTarget(predecessorText(node.profile, "id"), node.SourceSHA256(), map[string]any{
		"server": peer["address"], "server_port": peer["port"],
	})
	if err != nil {
		return candidateResponseSource{}, bad
	}
	options, err := json.Marshal(closure.final)
	if err != nil || len(options) > 4<<20 {
		return candidateResponseSource{}, bad
	}
	return candidateResponseSource{Target: target, NodeID: proof, API: strings.TrimRight(api.String(), "/"), Token: token,
		PacketMode: mode, PacketOptions: string(options)}, nil
}

// ConnectedPacketSuccessorCandidateMode describes the exact next packet role.
// It never grants a carrier to a selected, temporary, imported or layered path.
func (c *NodeChain) ConnectedPacketSuccessorCandidateMode(position int) string {
	if c == nil || c.validateCapture() != nil || len(c.nodes) < 3 || len(c.nodes) > NodeChainExtendedLocalMaximumNodes ||
		position < 0 || position >= len(c.nodes)-2 || c.importedNodes != nil || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil {
		return ""
	}
	if len(c.nodes) > NodeChainMaximumNodes && c.ExtendedPairedLocalNodeCount() != len(c.nodes) {
		return ""
	}
	for i, node := range c.nodes {
		proof := c.proofs[i]
		if node == nil || proof.NodeKind != "" || proof.Kind != "" || proof.StartLayer != "off" || !proofID.MatchString(proof.NodeID) ||
			proof.SourceSHA256 != node.SourceSHA256() || i < len(c.nodes)-1 && !NodeChainPrefixMode(proof.Mode) ||
			i == len(c.nodes)-1 && proof.Mode != "shadowsocks" && proof.Mode != "hysteria2" {
			return ""
		}
	}
	return c.proofs[position+1].Mode
}

func (c *NodeChain) connectedCandidateResponseMode(position int, mode string) bool {
	if mode == "hysteria2" {
		return c.SupportsConnectedHysteria2FinalCandidate(position)
	}
	return NodeChainPrefixMode(mode) && c.ConnectedPacketSuccessorCandidateMode(position) == mode
}

// Reject identities already in the complete active graph before a candidate
// handshake can roam that peer. Different clamped private-key encodings are
// compared by their derived public identity, including client/server aliases.
func (c *NodeChain) validatePacketSuccessorCandidate(position int, input string, response *candidateResponseSource) error {
	bad := errors.New("packet candidate changes or aliases the original complete path")
	if response == nil || c.ConnectedPacketSuccessorCandidateMode(position) != response.PacketMode || !NodeChainPrefixMode(response.PacketMode) {
		return bad
	}
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil || node.mode != response.PacketMode || node.SourceSHA256() != response.Target.SourceSHA256 {
		return bad
	}
	keys := func(node *NodeProfile) (string, string, error) {
		client, err := node.PacketClientPublicKey()
		if err != nil {
			return "", "", bad
		}
		closure, err := nodeMultihopPredecessor(node)
		if err != nil || closure == nil {
			return "", "", bad
		}
		peers, ok := closure.final["peers"].([]any)
		if !ok || len(peers) != 1 {
			return "", "", bad
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return "", "", bad
		}
		return client, predecessorText(peer, "public_key"), nil
	}
	client, server, err := keys(node)
	if err != nil || client == server {
		return bad
	}
	for i, original := range c.nodes {
		if c.proofs[i].ProfileID == response.Target.ID || c.proofs[i].NodeID == response.NodeID {
			return bad
		}
		if !NodeChainPrefixMode(original.mode) {
			continue
		}
		activeClient, activeServer, err := keys(original)
		if err != nil || client == activeClient || client == activeServer || server == activeClient || server == activeServer {
			return bad
		}
	}
	proposed := append([]*NodeProfile(nil), c.nodes...)
	proposed[position+1] = node
	config, proofs, _, _, err := compileNodeChain(proposed)
	if err != nil || len(proofs) != len(proposed) {
		return bad
	}
	// The original complete compiler owns nested packet MTU and fixed policy.
	// Reuse only its candidate interface budget; credentials, outer endpoint,
	// obfuscation and the retained prefix remain the original sealed capture.
	var graph, options map[string]any
	if exactJSON([]byte(config), &graph, NodeChainInputLimit) != nil ||
		exactJSON([]byte(response.PacketOptions), &options, 4<<20) != nil ||
		options["type"] != nodeChainPrefixType(response.PacketMode) {
		return bad
	}
	rows, ok := graph["endpoints"].([]any)
	if !ok {
		return bad
	}
	mtu := 0
	for _, raw := range rows {
		endpoint, ok := raw.(map[string]any)
		if !ok {
			return bad
		}
		if endpoint["tag"] != proofs[position+1].Tag {
			continue
		}
		if mtu != 0 || endpoint["type"] != options["type"] {
			return bad
		}
		mtu, err = mtuNumber(endpoint["mtu"])
		if err != nil {
			return bad
		}
	}
	if mtu == 0 {
		return bad
	}
	options["mtu"] = mtu
	encoded, err := json.Marshal(options)
	if err != nil {
		return bad
	}
	response.PacketOptions = string(encoded)
	return nil
}

func parseCandidateResponseSource(input string) (candidateResponseSource, error) {
	bad := errors.New("candidate response requires an original paired Shadowsocks2022 node with Start Layer off and a private proof endpoint")
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil || node.mode != "shadowsocks" {
		return candidateResponseSource{}, bad
	}
	layer := predecessorText(node.profile, "start_layer")
	if layer != "" && layer != "off" {
		return candidateResponseSource{}, bad
	}
	api, err := privateAPI(predecessorText(node.profile, "router_api"))
	token, nodeID := predecessorText(node.profile, "api_token"), predecessorText(node.profile, "node_proof_id")
	if err != nil || token == "" || !proofID.MatchString(nodeID) {
		return candidateResponseSource{}, bad
	}
	target, proof, err := nodeChainCandidateTarget(input)
	if err != nil || proof != nodeID {
		return candidateResponseSource{}, bad
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || closure == nil {
		return candidateResponseSource{}, bad
	}
	return candidateResponseSource{Target: target, NodeID: nodeID, API: strings.TrimRight(api.String(), "/"), Token: token,
		Method: predecessorText(closure.final, "method"), Password: predecessorText(closure.final, "password")}, nil
}

func parseCandidateHysteria2ResponseSource(input string) (candidateResponseSource, error) {
	bad := errors.New("candidate response requires its original paired Hysteria2 node with Start Layer off and a private proof endpoint")
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil || node.mode != "hysteria2" {
		return candidateResponseSource{}, bad
	}
	layer := predecessorText(node.profile, "start_layer")
	if layer != "" && layer != "off" {
		return candidateResponseSource{}, bad
	}
	api, err := privateAPI(predecessorText(node.profile, "router_api"))
	token, nodeID := predecessorText(node.profile, "api_token"), predecessorText(node.profile, "node_proof_id")
	if err != nil || token == "" || !proofID.MatchString(nodeID) {
		return candidateResponseSource{}, bad
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainFinalClosure(node, closure) || closure.final["type"] != "hysteria2" ||
		closure.final["detour"] != nil || closure.final["domain_resolver"] != nil || closure.final["realm"] != nil ||
		closure.final["server_ports"] != nil {
		return candidateResponseSource{}, bad
	}
	target, err := nodeChainCandidateLiteralTarget(predecessorText(node.profile, "id"), node.SourceSHA256(), closure.final)
	if err != nil {
		return candidateResponseSource{}, bad
	}
	options, err := json.Marshal(closure.final)
	if err != nil || len(options) > 4<<20 {
		return candidateResponseSource{}, bad
	}
	return candidateResponseSource{Target: target, NodeID: nodeID, API: strings.TrimRight(api.String(), "/"), Token: token,
		Hysteria2Options: string(options)}, nil
}

// SupportsConnectedHysteria2FinalCandidate is descriptive source metadata.
// The packet carrier is acquired separately from the live ordinary Local
// owner. No imported, dormant, selected Server/Compare or layered source
// receives this admission; the original complete packet prefix stays intact.
func (c *NodeChain) SupportsConnectedHysteria2FinalCandidate(position int) bool {
	if c == nil || c.validateCapture() != nil || len(c.nodes) < 2 || len(c.nodes) > NodeChainMaximumNodes ||
		position != len(c.nodes)-2 || c.importedNodes != nil || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil {
		return false
	}
	for i, node := range c.nodes {
		proof := c.proofs[i]
		if node == nil || proof.NodeKind != "" || proof.Kind != "" || proof.StartLayer != "off" || !proofID.MatchString(proof.NodeID) ||
			proof.SourceSHA256 != node.SourceSHA256() {
			return false
		}
		if i <= position {
			if !NodeChainPrefixMode(proof.Mode) {
				return false
			}
		} else if proof.Mode != "hysteria2" || proof.StartLayer != "off" {
			return false
		}
	}
	return true
}

// NodeChainCandidatePacketEngine is implemented by the ordinary Local and
// separately owned preparation native adapters. Their distinct request reads
// supply one original UDP endpoint and prefix; a caller cannot supply a tag,
// address or replacement native owner.
type NodeChainCandidatePacketEngine interface {
	DialCandidatePacketContext(context.Context, *NodeChainCandidatePacketRequest) (net.Conn, error)
}

// A connected or prepared Local adapter can construct this endpoint only
// after its own exact request read succeeds. The private stream destination
// comes from the sealed candidate, not a caller.
type NodeChainCandidatePacketEndpointEngine interface {
	OpenCandidatePacketEndpointContext(context.Context, *NodeChainCandidatePacketRequest) (NodeChainCandidatePacketEndpoint, error)
}

type NodeChainCandidatePacketEndpoint interface {
	DialPrivateContext(context.Context) (net.Conn, error)
	Close() error
}

type NodeChainCandidatePacketCapture struct {
	Mode, Options, PrivateAddress string
}

type NodeChainCandidatePacketRequest struct {
	self     *NodeChainCandidatePacketRequest
	engine   *nodeChainCandidateEngine
	prepared *nodeChainCandidatePreparationPacketCapability
	response candidateResponseSource
}

func (r *NodeChainCandidatePacketRequest) Read(ctx context.Context, reader NodeChainEngine, original *NodeChain) (NodeChainIdentity, string, string, error) {
	if r == nil || r.self != r || r.prepared != nil || r.engine == nil || reader == nil ||
		!reflect.TypeOf(reader).Comparable() || reader != r.engine.reader || original == nil ||
		original != r.engine.active || r.engine.plan == nil || original != r.engine.plan.chain ||
		r.engine.plan.preparedPacket != nil {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if _, err := r.engine.current(ctx); err != nil {
		return NodeChainIdentity{}, "", "", err
	}
	return r.readResponse(r.engine.plan, r.engine.identity)
}

// ReadPreparation accepts only the independently sealed temporary capability.
// A connected request, copied preparation, replaced reader or reopened ingress
// cannot borrow this route even when its original profile bytes match.
func (r *NodeChainCandidatePacketRequest) ReadPreparation(ctx context.Context, reader NodeChainCandidatePreparationPacketEngine, preparation *NodeChainCandidatePreparation) (NodeChainIdentity, string, string, error) {
	if r == nil || r.self != r || r.engine != nil || r.prepared == nil || reader == nil ||
		!reflect.TypeOf(reader).Comparable() || reader != r.prepared.reader ||
		r.prepared.runtime == nil || preparation == nil || preparation != r.prepared.runtime.preparation ||
		preparation.candidates != r.prepared.plan {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if err := r.prepared.current(ctx); err != nil {
		return NodeChainIdentity{}, "", "", err
	}
	return r.readResponse(r.prepared.plan, r.prepared.identity)
}

func (r *NodeChainCandidatePacketRequest) readResponse(plan *NodeChainCandidatePlan, identity NodeChainIdentity) (NodeChainIdentity, string, string, error) {
	mode := plan.responseMode
	if mode == "hysteria2" {
		if r.response.Hysteria2Options == "" || r.response.PacketMode != "" || r.response.PacketOptions != "" {
			return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
		}
	} else if !NodeChainPrefixMode(mode) || r.response.PacketMode != mode || r.response.PacketOptions == "" || r.response.Hysteria2Options != "" {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	for _, source := range plan.responses {
		if source == r.response {
			return identity, plan.prefix.Tag, source.Target.Address, nil
		}
	}
	return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
}

func (r *NodeChainCandidatePacketRequest) readCurrent(ctx context.Context) (NodeChainIdentity, string, string, error) {
	if r != nil && r.engine != nil && r.prepared == nil {
		return r.Read(ctx, r.engine.reader, r.engine.active)
	}
	if r != nil && r.engine == nil && r.prepared != nil && r.prepared.runtime != nil {
		return r.ReadPreparation(ctx, r.prepared.reader, r.prepared.runtime.preparation)
	}
	return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
}

func (r *NodeChainCandidatePacketRequest) packetCapture() (NodeChainCandidatePacketCapture, error) {
	api, err := privateAPI(r.response.API)
	if err != nil || !NodeChainPrefixMode(r.response.PacketMode) || r.response.PacketOptions == "" {
		return NodeChainCandidatePacketCapture{}, hopmeasure.ErrStale
	}
	return NodeChainCandidatePacketCapture{r.response.PacketMode, r.response.PacketOptions, api.Host}, nil
}
func (r *NodeChainCandidatePacketRequest) ReadPacketEndpoint(ctx context.Context, reader NodeChainEngine, original *NodeChain) (NodeChainCandidatePacketCapture, error) {
	if _, _, _, err := r.Read(ctx, reader, original); err != nil {
		return NodeChainCandidatePacketCapture{}, err
	}
	return r.packetCapture()
}
func (r *NodeChainCandidatePacketRequest) ReadPreparationPacketEndpoint(ctx context.Context, reader NodeChainCandidatePreparationPacketEngine, preparation *NodeChainCandidatePreparation) (NodeChainCandidatePacketCapture, error) {
	if _, _, _, err := r.ReadPreparation(ctx, reader, preparation); err != nil {
		return NodeChainCandidatePacketCapture{}, err
	}
	return r.packetCapture()
}
func (r *NodeChainCandidatePacketRequest) readCurrentPacketEndpoint(ctx context.Context) (NodeChainCandidatePacketCapture, error) {
	if _, _, _, err := r.readCurrent(ctx); err != nil {
		return NodeChainCandidatePacketCapture{}, err
	}
	return r.packetCapture()
}

func (r *NodeChainCandidatePacketRequest) dial(ctx context.Context) (net.Conn, error) {
	if _, _, _, err := r.readCurrent(ctx); err != nil {
		return nil, err
	}
	var reader NodeChainCandidatePacketEngine
	if r.engine != nil {
		reader, _ = r.engine.reader.(NodeChainCandidatePacketEngine)
	} else {
		reader = r.prepared.reader
	}
	if reader == nil {
		return nil, hopmeasure.ErrStale
	}
	connection, err := reader.DialCandidatePacketContext(ctx, r)
	_, _, _, observed := r.readCurrent(ctx)
	// Retain every late nonnil result. The protocol carrier joins its exact
	// Close before the connected or prepared measurement lease is released.
	return connection, errors.Join(err, observed, ctx.Err())
}

func NodeChainCandidateInputSupportedForMeasurement(input, measurement string) bool {
	switch measurement {
	case hopmeasure.CandidateTCPMeasurement:
		return NodeChainCandidateInputSupported(input)
	case hopmeasure.CandidatePublicResponseMeasurement:
		if len(input) == 0 || len(input) > NodeChainInputLimit {
			return false
		}
		_, err := parseCandidatePublicResponseSource(input)
		return err == nil
	case hopmeasure.CandidatePrivateResponseMeasurement:
		if len(input) == 0 || len(input) > NodeChainInputLimit {
			return false
		}
		_, err := parseCandidateResponseSource(input)
		return err == nil
	}
	return false
}

func (c *NodeChain) CandidatePrefixMeasurement(position int) string {
	if c == nil || c.validateCapture() != nil {
		return ""
	}
	return c.candidatePrefixMeasurementValidated(position)
}

// ConnectedCandidatePrefixMeasurement also describes the final replacement
// response available through a proved original OpenVPN or imported-entry
// prefix. It does not grant a temporary prefix graph or selected Server route.
func (c *NodeChain) ConnectedCandidatePrefixMeasurement(position int) string {
	if c == nil || c.validateCapture() != nil {
		return ""
	}
	if c.connectedFinalResponsePrefix(position) {
		return hopmeasure.CandidatePrivateResponseMeasurement
	}
	return c.candidatePrefixMeasurementValidated(position)
}

// The complete source has already been validated. Both families retain a
// private SS final and may only replace that final; their imported prefix is
// owned by the live complete graph, never reconstructed for measurement.
func (c *NodeChain) connectedFinalResponsePrefix(position int) bool {
	if c == nil || len(c.nodes) < 3 || len(c.nodes) > NodeChainMaximumNodes ||
		position != len(c.nodes)-2 || c.nodes[position] != nil ||
		c.nodes[len(c.nodes)-1] == nil || c.proofs[len(c.proofs)-1].Mode != "shadowsocks" ||
		c.proofs[len(c.proofs)-1].StartLayer != "off" {
		return false
	}
	proof := c.proofs[position]
	if proof.NodeKind != "external" || proof.Kind != "public-path" || proof.StartLayer != "off" {
		return false
	}
	if c.openVPNMiddle != nil {
		return proof.Mode == "openvpn" && c.openVPNOwners != nil
	}
	return c.HasImportedEntry() && position == 1 && proof.Mode == "shadowsocks"
}

// CandidatePrefixProof returns one descriptive row from the original sealed
// route. A stream that carries a later packet prefix need not itself be a
// measurable stop. This readback does not grant dial authority for either.
func (c *NodeChain) CandidatePrefixProof(position int) (NodeChainProof, bool) {
	if c == nil || c.validateCapture() != nil || position < 0 || position >= len(c.proofs)-1 {
		return NodeChainProof{}, false
	}
	return c.proofs[position], true
}

// The complete capture has already validated each source and proof, including
// the independent private identities attached to the schema-six stream route.
func (c *NodeChain) pairedCandidateStream(position int) bool {
	if c.importedNodes == nil || c.importedNodes.customEntry ||
		position < 1 || position+1 >= len(c.nodes) || c.nodes[position] == nil || c.nodes[position].mode != "shadowsocks" {
		return false
	}
	proof := c.proofs[position]
	return proofID.MatchString(proof.NodeID) && proof.SourceSHA256 == c.nodes[position].source &&
		proof.NodeKind == "" && proof.Kind == ""
}

func (c *NodeChain) candidatePrefixMeasurementValidated(position int) string {
	if position < 0 || position >= len(c.proofs) {
		return ""
	}
	if c.socksSource != nil {
		return c.socksSource.CandidatePrefixMeasurement(position)
	}
	if c.connectSource != nil {
		return c.connectSource.CandidatePrefixMeasurement(position)
	}
	if c.nodes[position] != nil && NodeChainPrefixMode(c.proofs[position].Mode) && !((c.openVPNMiddle != nil || c.importedMiddle != nil) && position >= len(c.nodes)-2) {
		if position > 7 && (position >= len(c.proofs)-1 || c.ExtendedPairedLocalNodeCount() != len(c.nodes) && position >= c.ExtendedMixedLocalPacketCount()) {
			return ""
		}
		return hopmeasure.CandidateTCPMeasurement
	}
	last := len(c.proofs) - 1
	if c.HasExternalFinal() && position > 0 && position < last {
		return hopmeasure.CandidatePublicResponseMeasurement
	}
	if position < 1 || position >= last || c.nodes[position] != nil && !c.pairedCandidateStream(position) || c.nodes[0] == nil ||
		c.nodes[last] == nil || c.proofs[last].Mode != "shadowsocks" || c.proofs[last].StartLayer != "off" {
		return ""
	}
	if len(c.nodes) > NodeChainMaximumNodes && (c.importedNodes == nil || c.ExtendedLocalNodeCount() != len(c.nodes)) {
		return ""
	}
	// Every packet endpoint and imported stream through this position belongs
	// to the original validated graph. A packet after a stream lacks a
	// packet-carrying predecessor in this measured family.
	stream := false
	for i := 0; i <= position; i++ {
		proof := c.proofs[i]
		if proof.StartLayer != "off" {
			return ""
		}
		if c.nodes[i] != nil {
			if c.pairedCandidateStream(i) {
				stream = true
				continue
			}
			if stream || !NodeChainPrefixMode(proof.Mode) || proof.NodeKind != "" || proof.Kind != "" {
				return ""
			}
			continue
		}
		member := c.importedSSMemberAt(i)
		if member == nil || proof.Kind != "public-path" || proof.NodeKind != "external" || proof.Mode != "shadowsocks" {
			return ""
		}
		if member.hostname != nil {
			if c.importedNodes == nil && (member != c.importedMiddle || i != position) {
				return ""
			}
			if !NodeChainPrefixMode(c.proofs[i-1].Mode) {
				previous := c.importedSSMemberAt(i - 1)
				if c.importedNodes == nil || previous == nil || previous.hostname != nil {
					return ""
				}
			}
		}
		stream = true
	}
	return hopmeasure.CandidatePrivateResponseMeasurement
}

func (p *NodeChainCandidatePlan) PacketCandidateDepth(position int, id, tag string) int {
	if p.validate() != nil || p.prefix.Position != position || p.prefix.ProfileID != id || p.prefix.Tag != tag || p.measurement != "" {
		return 0
	}
	if p.multiple != nil && position < p.chain.ExtendedMixedLocalPacketCount() {
		return p.chain.ExtendedLocalNodeCount()
	}
	return p.chain.ExtendedPairedLocalNodeCount()
}

func (p *NodeChainCandidatePlan) ResponseCandidateDepth(position int, id, tag string) int {
	if p.validate() != nil || p.measurement != hopmeasure.CandidatePrivateResponseMeasurement ||
		p.prefix.Position != position || p.prefix.ProfileID != id || p.prefix.Tag != tag {
		return 0
	}
	// Only the existing independently owned all-WG-to-SS Local capture grants
	// a deeper native packet session. Its complete original compiler and
	// replacement compiler retain every prefix, suffix and MTU policy.
	if p.responseMode == "wg" && p.multiple == nil && !p.connectedFinalResponse &&
		p.chain.ConnectedPacketSuccessorCandidateMode(position) == "wg" {
		return p.chain.ExtendedPairedLocalNodeCount()
	}
	if p.responseMode != "" || p.multiple == nil || p.chain.candidatePrefixMeasurementValidated(position) != p.measurement {
		return 0
	}
	return p.chain.ExtendedLocalNodeCount()
}

func (p *NodeChainCandidatePreparation) ExtendedCandidateDepth() int {
	if p.validate() != nil {
		return 0
	}
	proof := p.proofs[p.position]
	if p.candidates.measurement == hopmeasure.CandidatePublicResponseMeasurement {
		return p.candidates.PublicResponseCandidateDepth(p.position, proof.ProfileID, proof.Tag)
	}
	if p.candidates.measurement == hopmeasure.CandidatePrivateResponseMeasurement {
		return p.candidates.ResponseCandidateDepth(p.position, proof.ProfileID, proof.Tag)
	}
	return p.candidates.PacketCandidateDepth(p.position, proof.ProfileID, proof.Tag)
}

func (p *NodeChainCandidatePreparation) ExtendedPacketDepth() int {
	if p.validate() != nil {
		return 0
	}
	return p.candidates.PacketCandidateDepth(p.position, p.proofs[p.position].ProfileID, p.proofs[p.position].Tag)
}

func (p *NodeChainCandidatePlan) newService(ctx context.Context, engine hopmeasure.CandidateEngine, capture string) (*hopmeasure.CandidateService, error) {
	prefix := hopmeasure.CandidatePrefix{Position: p.prefix.Position, ID: p.prefix.ProfileID, Tag: p.prefix.Tag, CaptureSHA256: capture}
	if p.measurement == "" {
		if p.prefix.Position > 7 {
			return hopmeasure.NewExtendedPacketCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p)
		}
		return hopmeasure.NewCapturedPrefixCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit)
	}
	if p.measurement == hopmeasure.CandidatePublicResponseMeasurement {
		return p.newPublicResponseService(ctx, engine, prefix)
	}
	var requestFor func(candidateResponseSource) *NodeChainCandidatePacketRequest
	var factory NodeChainCandidatePacketEndpointEngine
	if p.responseMode != "" {
		var original *nodeChainCandidateEngine
		var prepared *nodeChainCandidatePreparationPacketCapability
		switch owner := engine.(type) {
		case *nodeChainCandidateEngine:
			if owner.plan != p || p.preparedPacket != nil {
				return nil, hopmeasure.ErrStale
			}
			original = owner
			factory, _ = owner.reader.(NodeChainCandidatePacketEndpointEngine)
		case *NodeChainCandidatePreparationRuntime:
			var err error
			prepared, err = owner.packetCapability(ctx, p)
			if err != nil {
				return nil, err
			}
			factory, _ = prepared.reader.(NodeChainCandidatePacketEndpointEngine)
		default:
			return nil, hopmeasure.ErrStale
		}
		requestFor = func(source candidateResponseSource) *NodeChainCandidatePacketRequest {
			request := &NodeChainCandidatePacketRequest{engine: original, prepared: prepared, response: source}
			request.self = request
			return request
		}
	}
	if NodeChainPrefixMode(p.responseMode) {
		if factory == nil {
			return nil, errors.New("authenticated packet candidate requires its exact Local endpoint factory")
		}
		open := func(ctx context.Context, target hopmeasure.CandidateTarget) (hopmeasure.CandidateResponseSession, error) {
			for _, source := range p.responses {
				if source.Target != target {
					continue
				}
				request := requestFor(source)
				if _, _, _, err := request.readCurrent(ctx); err != nil {
					return nil, err
				}
				endpoint, err := factory.OpenCandidatePacketEndpointContext(ctx, request)
				if endpoint == nil {
					return nil, errors.Join(err, errors.New("packet candidate returned no original endpoint"))
				}
				_, _, _, observed := request.readCurrent(ctx)
				// Preserve a late nonnil endpoint even when its open failed. The
				// generalized worker joins this exact Close before publishing.
				return &candidatePacketResponseSession{request: request, endpoint: endpoint, prefix: p.prefix.Tag}, errors.Join(err, observed, ctx.Err())
			}
			return nil, hopmeasure.ErrStale
		}
		if len(p.chain.proofs) > NodeChainMaximumNodes {
			return hopmeasure.NewExtendedResponseSessionCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p, open)
		}
		return hopmeasure.NewCapturedResponseSessionCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, open)
	}
	if p.responseMode == "hysteria2" {
		if requestFor == nil || openCandidateHysteria2 == nil {
			return nil, errors.New("authenticated Hysteria2 candidate requires its original Local packet carrier")
		}
		respond := func(ctx context.Context, target hopmeasure.CandidateTarget, complete func() error) error {
			for _, source := range p.responses {
				if source.Target == target {
					request := requestFor(source)
					nonce, err := randomHex(16)
					if err != nil {
						return err
					}
					return source.exchangeChallenge(ctx, func(call context.Context, tag, destination string) (net.Conn, error) {
						if tag != p.prefix.Tag {
							return nil, hopmeasure.ErrStale
						}
						return openCandidateHysteria2(call, request, destination)
					}, p.prefix.Tag, nonce, func(string) error { return complete() })
				}
			}
			return hopmeasure.ErrStale
		}
		return hopmeasure.NewCapturedResponseCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, respond)
	}
	if p.measurement != hopmeasure.CandidatePrivateResponseMeasurement || wrapCandidateSS2022 == nil {
		return nil, errors.New("authenticated candidate response requires its native Shadowsocks2022 transport")
	}
	respond := func(ctx context.Context, target hopmeasure.CandidateTarget, complete func() error) error {
		for _, source := range p.responses {
			if source.Target == target {
				return source.exchange(ctx, engine, p.prefix.Tag, complete)
			}
		}
		return hopmeasure.ErrStale
	}
	if prefix.Position >= NodeChainMaximumNodes-1 {
		return hopmeasure.NewExtendedResponseCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p, respond)
	}
	return hopmeasure.NewCapturedResponseCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, respond)
}

type candidatePacketResponseSession struct {
	request  *NodeChainCandidatePacketRequest
	endpoint NodeChainCandidatePacketEndpoint
	prefix   string
}

func (s *candidatePacketResponseSession) Respond(ctx context.Context, complete func() error) error {
	if s == nil || s.request == nil || s.endpoint == nil || complete == nil {
		return hopmeasure.ErrStale
	}
	r := s.request
	if _, _, _, err := r.readCurrent(ctx); err != nil {
		return err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	return r.response.exchangeChallenge(ctx, func(call context.Context, tag, destination string) (net.Conn, error) {
		capture, err := r.readCurrentPacketEndpoint(call)
		if err != nil || tag != s.prefix || destination != capture.PrivateAddress {
			return nil, hopmeasure.ErrStale
		}
		connection, err := s.endpoint.DialPrivateContext(call)
		_, _, _, observed := r.readCurrent(call)
		return connection, errors.Join(err, observed, call.Err())
	}, s.prefix, nonce, func(string) error { return complete() })
}

func (s *candidatePacketResponseSession) Close() error {
	if s == nil || s.endpoint == nil {
		return nil
	}
	return s.endpoint.Close()
}

func (s candidateResponseSource) exchange(ctx context.Context, engine hopmeasure.CandidateEngine, tag string, complete func() error) error {
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	return s.exchangeNonce(ctx, engine.Dial, wrapCandidateSS2022, tag, nonce, func(string) error { return complete() })
}

func (s candidateResponseSource) exchangeNonce(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error), tag, nonce string, accept func(string) error) error {
	return s.exchangeChallenge(ctx, func(call context.Context, tag, destination string) (net.Conn, error) {
		return dialCandidateStream(call, dial, wrap, tag, s.Target.Address, s.Method, s.Password, destination)
	}, tag, nonce, accept)
}

func (s candidateResponseSource) exchangeChallenge(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), tag, nonce string, accept func(string) error) error {
	request := hopmeasure.CandidateChallengeMAC(s.Token, s.NodeID, nonce, false)
	api, err := privateAPI(s.API)
	if err != nil {
		return err
	}
	_, err = externalProofHTTPVerified(ctx, func(call context.Context, routedTag, privateAddress string) (net.Conn, error) {
		if routedTag != tag || privateAddress != api.Host {
			return nil, hopmeasure.ErrStale
		}
		return dial(call, tag, privateAddress)
	}, tag, s.API+hopmeasure.CandidateChallengePath+"?nonce="+nonce, request, "", nil, func(data []byte) error {
		var result struct {
			Node     string `json:"node_id"`
			Nonce    string `json:"nonce"`
			Response string `json:"response"`
		}
		expected := hopmeasure.CandidateChallengeMAC(s.Token, s.NodeID, nonce, true)
		if exactJSON(data, &result, 1024) != nil || result.Node != s.NodeID || result.Nonce != nonce || !hmac.Equal([]byte(result.Response), []byte(expected)) {
			return errors.New("candidate failed its original fresh private agent challenge")
		}
		return accept(result.Response)
	})
	return err
}

// Both response measures open the separately captured candidate cipher over
// the selected prefix socket. Cancellation joins the original handshake and
// Close before either measurement can publish.
func dialCandidateStream(call context.Context, dial func(context.Context, string, string) (net.Conn, error), wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error), tag, endpoint, method, password, destination string) (net.Conn, error) {
	raw, err := dial(call, tag, endpoint)
	if err != nil || raw == nil {
		return raw, errors.Join(err, errors.New("original candidate transport unavailable"))
	}
	// DialConn can send its first handshake synchronously. The original
	// raw socket and its close stay owned even during that initial write.
	stopClose := make(chan struct{})
	stop := context.AfterFunc(call, func() { _ = raw.Close(); close(stopClose) })
	deadline, _ := call.Deadline()
	var conn net.Conn
	if err = raw.SetDeadline(deadline); err == nil {
		conn, err = wrap(call, raw, method, password, destination)
	}
	if !stop() {
		<-stopClose
		return nil, call.Err()
	}
	if err != nil || conn == nil {
		_ = raw.Close()
		return nil, errors.Join(err, errors.New("candidate cipher handshake unavailable"))
	}
	return conn, nil
}
