package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"

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
	PacketOptions, ClientKey, ServerKey  string `json:",omitempty"`
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

func parseCandidateNativeResponseSource(input, mode string) (candidateResponseSource, error) {
	bad := errors.New("candidate response requires its original paired native node with Start Layer off and a private proof endpoint")
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil || node.mode != mode || !nodeChainNativeResponseMode(mode) {
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
	if err != nil || !nodeChainFinalClosure(node, closure) ||
		closure.final["detour"] != nil || closure.final["domain_resolver"] != nil || closure.final["realm"] != nil ||
		closure.final["server_ports"] != nil {
		return candidateResponseSource{}, bad
	}
	result := candidateResponseSource{NodeID: nodeID, API: strings.TrimRight(api.String(), "/"), Token: token}
	targetSource := closure.final
	if NodeChainPrefixMode(mode) {
		peer, ok := closure.final["peers"].([]any)[0].(map[string]any)
		if !ok {
			return candidateResponseSource{}, bad
		}
		result.ClientKey, err = node.PacketClientPublicKey()
		result.ServerKey = predecessorText(peer, "public_key")
		if err != nil || !nodeChainCanonicalPeer(result.ServerKey) || result.ClientKey == result.ServerKey {
			return candidateResponseSource{}, bad
		}
		targetSource = map[string]any{"server": peer["address"], "server_port": peer["port"]}
	}
	target, err := nodeChainCandidateLiteralTarget(predecessorText(node.profile, "id"), node.SourceSHA256(), targetSource)
	if err != nil {
		return candidateResponseSource{}, bad
	}
	options, err := json.Marshal(closure.final)
	if err != nil || len(options) > 4<<20 {
		return candidateResponseSource{}, bad
	}
	result.Target = target
	if mode == "hysteria2" {
		result.Hysteria2Options = string(options)
	} else {
		result.PacketOptions = string(options)
	}
	return result, nil
}

// Compile the complete prospective route, including every unchanged suffix.
// Its replacement uses the same nested MTU and peer options as future launch.
// The active prefix cannot be resized to accommodate a replacement candidate.
func (c *NodeChain) candidatePacketOptions(position int, input string) (string, error) {
	candidate, err := ParseNodeLaunchInput(input)
	if err != nil || candidate == nil || c == nil {
		return "", errors.Join(err, nodeChainCandidatePreparationError)
	}
	nodes := append([]*NodeProfile(nil), c.nodes...)
	successor := position + 1
	if position < 0 || successor >= len(nodes) {
		return "", nodeChainCandidatePreparationError
	}
	nodes[successor] = candidate
	var config string
	var proofs []NodeChainProof
	var physical []PhysicalEgress
	if c.importedNodes != nil {
		// Keep the exact registry and every original imported policy. A paired
		// successor is replaced; no imported source is decoded as a Router node.
		if c.ConnectedPacketSuccessorCandidateMode(position) != candidate.mode {
			return "", nodeChainCandidatePreparationError
		}
		config, proofs, _, physical, err = c.importedNodes.compile(nodes)
	} else {
		config, proofs, _, physical, err = compileNodeChain(nodes)
	}
	if err != nil || !reflect.DeepEqual(physical, c.physical) || len(proofs) != len(c.proofs) ||
		!reflect.DeepEqual(proofs[:successor], c.proofs[:successor]) {
		return "", nodeChainCandidatePreparationError
	}
	original, err := candidatePrefixClosure(c.config, c.proofs[:successor])
	if err != nil {
		return "", err
	}
	prospectivePrefix, err := candidatePrefixClosure(config, proofs[:successor])
	if err != nil || !reflect.DeepEqual(original, prospectivePrefix) {
		return "", nodeChainCandidatePreparationError
	}
	prospective, err := packetCandidateEndpoints(config)
	if err != nil {
		return "", err
	}
	endpoint := prospective[proofs[successor].Tag]
	if endpoint == nil || endpoint["type"] != nodeChainPrefixType(candidate.mode) || endpoint["detour"] != proofs[position].Tag {
		return "", nodeChainCandidatePreparationError
	}
	if successor < len(nodes)-1 && !candidateUnboundPacket(endpoint) {
		return "", nodeChainCandidatePreparationError
	}
	delete(endpoint, "detour") // Replaced exclusively by the sealed live prefix dialer.
	endpoint["tag"] = "proxy"
	raw, err := json.Marshal(endpoint)
	return string(raw), err
}

// Compare complete compiler-owned prefix transport and resolver closures. An
// imported SS proof is an outbound, and a packet's Start Layer has its own
// outbound and credentials; neither can be reduced to an endpoint MTU check.
// The caller supplies proofs from its already validated original source.
func candidatePrefixClosure(config string, proofs []NodeChainProof) (map[string]any, error) {
	var graph struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
		DNS       struct {
			Servers []map[string]any `json:"servers"`
		} `json:"dns"`
	}
	if len(config) > 4<<20 || json.Unmarshal([]byte(config), &graph) != nil || len(proofs) == 0 {
		return nil, nodeChainCandidatePreparationError
	}
	result := make(map[string]any)
	for i, proof := range proofs {
		if proof.Position != i || len(proof.SourceSHA256) != 64 || proof.Tag == "" {
			return nil, nodeChainCandidatePreparationError
		}
		for _, family := range []struct {
			name, namespace string
			rows            []map[string]any
		}{
			{"outbounds", "node", graph.Outbounds},
			{"endpoints", "node", graph.Endpoints},
			{"dns", "dns", graph.DNS.Servers},
		} {
			// Every row name comes from compileNodeChainGraph and the same
			// original full source hash; this projection grants no dial access.
			prefix := nodeChainNamespace(i, proof.SourceSHA256, family.namespace, "")
			prefix = prefix[:len(prefix)-12]
			for _, row := range family.rows {
				tag := predecessorText(row, "tag")
				if !strings.HasPrefix(tag, prefix) {
					continue
				}
				key := family.name + "/" + tag
				if _, exists := result[key]; exists {
					return nil, nodeChainCandidatePreparationError
				}
				result[key] = row
			}
		}
		_, outbound := result["outbounds/"+proof.Tag]
		_, endpoint := result["endpoints/"+proof.Tag]
		if outbound == endpoint {
			return nil, nodeChainCandidatePreparationError
		}
	}
	return result, nil
}

func candidateUnboundPacket(endpoint map[string]any) bool {
	port, present := endpoint["listen_port"]
	return !present || port == float64(0)
}

func packetCandidateEndpoints(config string) (map[string]map[string]any, error) {
	var graph struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal([]byte(config), &graph) != nil {
		return nil, nodeChainCandidatePreparationError
	}
	result := make(map[string]map[string]any, len(graph.Endpoints))
	for _, endpoint := range graph.Endpoints {
		result[predecessorText(endpoint, "tag")] = endpoint
	}
	return result, nil
}

// ConnectedPacketSuccessorCandidateMode describes the exact next packet role.
// This source readback grants no carrier. Connected and prepared owners are acquired separately.
func (c *NodeChain) ConnectedPacketSuccessorCandidateMode(position int) string {
	if c == nil || c.validateCapture() != nil || len(c.nodes) < 3 || len(c.nodes) > NodeChainExtendedLocalMaximumNodes ||
		position < 0 || position >= len(c.nodes)-2 || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil {
		return ""
	}
	if len(c.nodes) > NodeChainMaximumNodes && c.ExtendedPairedLocalNodeCount() != len(c.nodes) {
		return ""
	}
	if c.importedNodes != nil && (c.importedNodes.customEntry || c.importedNodes.externalFinal || len(c.nodes) > NodeChainMaximumNodes) {
		return ""
	}
	successor := c.nodes[position+1]
	if successor == nil || !NodeChainPrefixMode(successor.mode) || c.proofs[position+1].StartLayer != "off" {
		return ""
	}
	for i, node := range c.nodes {
		proof := c.proofs[i]
		if node == nil {
			member := c.importedSSMemberAt(i)
			if c.importedNodes == nil || member == nil || member.hostname != nil || i == 0 || i == len(c.nodes)-1 ||
				proof.NodeKind != "external" || proof.Kind != "public-path" || proof.Mode != "shadowsocks" ||
				proof.StartLayer != "off" || proof.SourceSHA256 != member.source {
				return ""
			}
			continue
		}
		if proof.NodeKind != "" || proof.Kind != "" || !proofID.MatchString(proof.NodeID) ||
			proof.SourceSHA256 != node.SourceSHA256() || i < len(c.nodes)-1 && !NodeChainPrefixMode(proof.Mode) ||
			i == len(c.nodes)-1 && proof.Mode != "shadowsocks" && proof.Mode != "hysteria2" {
			return ""
		}
		// Only an already retained prefix may carry a Start Layer. This
		// purpose never changes the successor's layer or a suffix member.
		if proof.StartLayer != "off" && (i > position ||
			proof.StartLayer != "aes-256-gcm" && proof.StartLayer != "aes-256-gcm+xor-whitening") {
			return ""
		}
	}
	return successor.mode
}

func (c *NodeChain) candidateNativeResponseModeAt(position int) string {
	if mode := c.nativeFinalCandidateMode(position); mode != "" {
		return mode
	}
	return c.ConnectedPacketSuccessorCandidateMode(position)
}

// SupportsConnectedHysteria2FinalCandidate is descriptive source metadata.
// The packet carrier is acquired separately from the live ordinary Local
// owner. No imported, dormant, selected Server/Compare or layered source
// receives this admission; the original complete packet prefix stays intact.
func (c *NodeChain) SupportsConnectedHysteria2FinalCandidate(position int) bool {
	return c.ConnectedFinalCandidateResponseMode(position) == "hysteria2"
}

func nodeChainNativeResponseMode(mode string) bool {
	return mode == "hysteria2" || NodeChainPrefixMode(mode)
}

func (c *NodeChain) ConnectedFinalCandidateResponseMode(position int) string {
	return c.nativeFinalCandidateMode(position)
}

// PreparedFinalCandidateResponseMode describes a potential replacement for
// this complete source. Only a separately acquired closed prefix can execute it.
func (c *NodeChain) PreparedFinalCandidateResponseMode(position int) string {
	return c.nativeFinalCandidateMode(position)
}

func (c *NodeChain) nativeFinalCandidateMode(position int) string {
	if c == nil || c.validateCapture() != nil || len(c.nodes) < 2 || len(c.nodes) > NodeChainMaximumNodes ||
		position != len(c.nodes)-2 || c.importedNodes != nil || c.importedMiddle != nil || c.openVPNMiddle != nil ||
		c.socksSource != nil || c.connectSource != nil {
		return ""
	}
	for i, node := range c.nodes {
		proof := c.proofs[i]
		if node == nil || proof.NodeKind != "" || proof.Kind != "" || proof.StartLayer != "off" || !proofID.MatchString(proof.NodeID) ||
			proof.SourceSHA256 != node.SourceSHA256() {
			return ""
		}
		if i <= position {
			if !NodeChainPrefixMode(proof.Mode) {
				return ""
			}
		} else if !nodeChainNativeResponseMode(proof.Mode) || proof.StartLayer != "off" {
			return ""
		}
	}
	return c.proofs[len(c.proofs)-1].Mode
}

// NodeChainCandidatePacketEngine is implemented only by the ordinary Local
// native adapter. The sealed request supplies one original UDP endpoint and
// prefix; the caller cannot supply a tag, address or replacement native owner.
type NodeChainCandidatePacketEngine interface {
	DialCandidatePacketContext(context.Context, *NodeChainCandidatePacketRequest) (net.Conn, error)
}

type NodeChainCandidateEndpoint interface {
	DialPrivate(context.Context, string) (net.Conn, error)
	Close() error
}

type NodeChainCandidateEndpointEngine interface {
	OpenCandidateEndpointContext(context.Context, *NodeChainCandidatePacketRequest) (NodeChainCandidateEndpoint, error)
}

// One request owns the candidate's key across all fifty streams. A second
// simultaneous WG device with that key would move the peer's reply endpoint.
type candidatePacketRun struct {
	ctx       context.Context
	cancel    context.CancelFunc
	request   *NodeChainCandidatePacketRequest
	open      func(context.Context, *NodeChainCandidatePacketRequest) (NodeChainCandidateEndpoint, error)
	endpoint  NodeChainCandidateEndpoint
	closeOnce sync.Once
	closeErr  error
}

func (r *candidatePacketRun) Respond(ctx context.Context, complete func() error) error {
	q := r.request
	if _, _, _, err := q.current(ctx); err != nil {
		return err
	}
	if r.endpoint == nil {
		// Construction and the initial handshake belong to the first sample.
		// Keep the endpoint only after its original per-sample budget succeeds.
		owned, cancel := context.WithCancel(r.ctx)
		stop := context.AfterFunc(ctx, cancel)
		var err error
		r.endpoint, err = r.open(owned, q)
		if !stop() || err != nil || r.endpoint == nil || ctx.Err() != nil {
			cancel()
			return errors.Join(err, ctx.Err(), hopmeasure.ErrStale)
		}
		r.cancel = cancel
	}
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	return q.response.exchangeChallenge(ctx, func(call context.Context, tag, address string) (net.Conn, error) {
		if tag != q.plan.prefix.Tag {
			return nil, hopmeasure.ErrStale
		}
		return r.endpoint.DialPrivate(call, address)
	}, q.plan.prefix.Tag, nonce, func(string) error { return complete() })
}

func (r *candidatePacketRun) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		if r.endpoint != nil {
			r.closeErr = r.endpoint.Close()
		}
		// Failed retirement retains the original key reservation and endpoint.
		// A different request must not move a peer while that owner is unjoined.
		if r.closeErr != nil {
			return
		}
		mu, keys := r.request.reservations()
		mu.Lock()
		defer mu.Unlock()
		for _, key := range []string{r.request.response.ClientKey, r.request.response.ServerKey} {
			if (*keys)[key] == r {
				delete(*keys, key)
			}
		}
	})
	return r.closeErr
}

// The temporary Box retains its own closed ingress, physical identity and
// native prefix instances. Neither interface supplies an arbitrary UDP socket.
type NodeChainPreparedPacketEngine interface {
	ObservePreparationContext(context.Context) (NodeChainIdentity, error)
	DialPreparedCandidatePacketContext(context.Context, *NodeChainCandidatePacketRequest) (net.Conn, error)
	OpenPreparedCandidateEndpointContext(context.Context, *NodeChainCandidatePacketRequest) (NodeChainCandidateEndpoint, error)
}

type nodeChainPreparedPacketOwner interface {
	PreparedPacketEngineContext(context.Context, *NodeChainCandidatePreparation) (NodeChainPreparedPacketEngine, error)
}

type NodeChainCandidatePacketRequest struct {
	self           *NodeChainCandidatePacketRequest
	plan           *NodeChainCandidatePlan
	engine         *nodeChainCandidateEngine
	prepared       *NodeChainCandidatePreparationRuntime
	preparedReader NodeChainPreparedPacketEngine
	appendHysteria *nodeChainAppendExecutionHysteria
	selected       *nodeChainExecutionEntryCandidateEngine
	response       candidateResponseSource
}

func (r *NodeChainCandidatePacketRequest) source(identity NodeChainIdentity) (NodeChainIdentity, string, string, error) {
	if nodeChainNativeResponseMode(r.plan.responseMode) && (r.response.Hysteria2Options != "" || r.response.PacketOptions != "") {
		for _, source := range r.plan.responses {
			if source == r.response {
				return identity, r.plan.prefix.Tag, source.Target.Address, nil
			}
		}
	}
	return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
}

func (r *NodeChainCandidatePacketRequest) Read(ctx context.Context, reader NodeChainEngine, original *NodeChain) (NodeChainIdentity, string, string, error) {
	if r == nil || r.self != r || r.engine == nil || r.prepared != nil || r.selected != nil || reader == nil || !reflect.TypeOf(reader).Comparable() || reader != r.engine.reader ||
		original == nil || original != r.engine.active || r.plan == nil || r.plan != r.engine.plan || r.plan.preparedNativeResponse || original != r.plan.chain || r.plan.appendSource != nil {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if _, err := r.engine.current(ctx); err != nil {
		return NodeChainIdentity{}, "", "", err
	}
	return r.source(r.engine.identity)
}

func (r *NodeChainCandidatePacketRequest) ReadPrepared(ctx context.Context, reader NodeChainPreparedPacketEngine, original *NodeChainCandidatePreparation) (NodeChainIdentity, string, string, error) {
	if r == nil || r.self != r || r.engine != nil || r.prepared == nil || r.selected != nil || reader == nil || !reflect.TypeOf(reader).Comparable() || reader != r.preparedReader ||
		original == nil || original != r.prepared.preparation || r.plan == nil || !r.plan.preparedNativeResponse || original.candidates != r.plan {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if original.appendSource != nil || r.plan.appendSource != nil {
		if original.appendSource == nil || original.appendSource != r.plan.appendSource ||
			original.original != nil || r.plan.chain != nil || original.validateAppend() != nil || r.plan.validateAppend() != nil {
			return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
		}
	}
	native, err := r.prepared.retainedPacketEngine(ctx)
	if err != nil || native != reader {
		return NodeChainIdentity{}, "", "", errors.Join(err, hopmeasure.ErrStale)
	}
	identity, err := reader.ObservePreparationContext(ctx)
	if err != nil || identity.SourceSHA256 != original.sourceSHA || identity.ConfigSHA256 != original.configSHA {
		return NodeChainIdentity{}, "", "", errors.Join(err, hopmeasure.ErrStale)
	}
	if err = externalObservationLock(ctx, &r.prepared.mu); err != nil {
		return NodeChainIdentity{}, "", "", err
	}
	current := r.prepared.started && !r.prepared.retired && r.prepared.identity == identity
	r.prepared.mu.Unlock()
	if !current {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	return r.source(identity)
}

func (r *NodeChainCandidatePacketRequest) current(ctx context.Context) (NodeChainIdentity, string, string, error) {
	if r != nil && r.self == r {
		if r.selected != nil {
			if r.selected.plan == nil {
				return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
			}
			return r.ReadSelected(ctx, r.selected.plan.native, r.selected.plan.projection)
		}
		if r.prepared != nil {
			return r.ReadPrepared(ctx, r.preparedReader, r.prepared.preparation)
		}
		if r.engine != nil {
			return r.Read(ctx, r.engine.reader, r.engine.active)
		}
	}
	return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
}

func (r *NodeChainCandidatePacketRequest) dial(ctx context.Context) (net.Conn, error) {
	if _, _, _, err := r.current(ctx); err != nil {
		return nil, err
	}
	var connection net.Conn
	var err error
	if r.selected != nil {
		connection, err = r.selected.dialPacket(ctx, r)
	} else if r.prepared != nil {
		connection, err = r.preparedReader.DialPreparedCandidatePacketContext(ctx, r)
	} else {
		reader, ok := r.engine.reader.(NodeChainCandidatePacketEngine)
		if !ok {
			return nil, hopmeasure.ErrStale
		}
		connection, err = reader.DialCandidatePacketContext(ctx, r)
	}
	_, _, _, observed := r.current(ctx)
	// Retain nonnil late connections for the original transport's joined Close.
	return connection, errors.Join(err, observed, ctx.Err())
}

func (r *NodeChainCandidatePacketRequest) reservations() (*sync.Mutex, *map[string]*candidatePacketRun) {
	if r.selected != nil {
		return &r.selected.plan.runtime.mu, &r.selected.plan.runtime.candidatePacketKeys
	}
	if r.prepared != nil {
		return &r.prepared.mu, &r.prepared.candidatePacketKeys
	}
	runtime := &r.engine.active.runtime
	return &runtime.mu, &runtime.candidatePacketKeys
}

func (r *NodeChainCandidatePacketRequest) reserve(ctx context.Context) (hopmeasure.CandidateResponseRun, error) {
	run := &candidatePacketRun{ctx: ctx, request: r}
	if r.selected != nil {
		reader, ok := r.selected.plan.native.(NodeChainSelectedPacketEngine)
		if !ok {
			return nil, hopmeasure.ErrStale
		}
		run.open = reader.OpenSelectedCandidateEndpointContext
	} else if r.prepared != nil {
		run.open = r.preparedReader.OpenPreparedCandidateEndpointContext
	} else {
		reader, ok := r.engine.reader.(NodeChainCandidateEndpointEngine)
		if !ok {
			return nil, hopmeasure.ErrStale
		}
		run.open = reader.OpenCandidateEndpointContext
	}
	mu, keys := r.reservations()
	if err := externalObservationLock(ctx, mu); err != nil {
		return nil, err
	}
	defer mu.Unlock()
	if r.selected != nil {
		p := r.selected.plan
		if p.runtime.closed || p.runtime.retired.Load() || p.runtime.active != p.trial || p.runtime.identity != p.identity || p.runtime.engine != p.native || p.trial.execution != "local" || p.trial.lifetime.Err() != nil {
			return nil, hopmeasure.ErrStale
		}
	} else if r.prepared != nil {
		if r.prepared.retired || r.prepared.lifetime == nil || r.prepared.lifetime.Err() != nil {
			return nil, hopmeasure.ErrStale
		}
	} else {
		runtime := &r.engine.active.runtime
		if runtime.closed || runtime.identity != r.engine.identity || runtime.engine != r.engine.reader {
			return nil, hopmeasure.ErrStale
		}
	}
	source := r.response
	if (*keys)[source.ClientKey] != nil || (*keys)[source.ServerKey] != nil {
		return nil, hopmeasure.ErrStale
	}
	if *keys == nil {
		*keys = make(map[string]*candidatePacketRun)
	}
	(*keys)[source.ClientKey], (*keys)[source.ServerKey] = run, run
	return run, nil
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
	if position < 0 || position >= len(c.proofs)-1 {
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
	if p.appendSource != nil {
		// This depth belongs exclusively to the sealed incomplete prefix and
		// its one prospective append, never to a complete NodeChain.
		return len(p.appendSource.nodes) + 1
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
		if p.appendSource != nil {
			return p.candidates.AppendPublicResponseCandidateDepth(p.position, proof.ProfileID, proof.Tag)
		}
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
	appendStream := p.isAppendStreamResponse()
	if appendStream {
		if _, err := p.appendStreamRuntime(ctx, engine, capture); err != nil {
			return nil, err
		}
	}
	if p.responseMode != "" && !appendStream {
		var base NodeChainCandidatePacketRequest
		base.plan = p
		switch owner := engine.(type) {
		case *nodeChainExecutionEntryCandidateEngine:
			if p.preparedNativeResponse || owner.plan == nil || owner.plan.plan != p || owner.plan.trial.execution != "local" || !NodeChainPrefixMode(p.responseMode) {
				return nil, hopmeasure.ErrStale
			}
			if _, ok := owner.plan.native.(NodeChainSelectedPacketEngine); !ok {
				return nil, hopmeasure.ErrStale
			}
			base.selected = owner
		case *nodeChainCandidateEngine:
			if p.preparedNativeResponse || owner.plan != p {
				return nil, hopmeasure.ErrStale
			}
			base.engine = owner
		case *NodeChainCandidatePreparationRuntime:
			if !p.preparedNativeResponse || owner.preparation == nil || owner.preparation.candidates != p {
				return nil, hopmeasure.ErrStale
			}
			native, err := owner.retainedPacketEngine(ctx)
			if err != nil {
				return nil, err
			}
			base.prepared, base.preparedReader = owner, native
		default:
			return nil, hopmeasure.ErrStale
		}
		requestFor := func(ctx context.Context, target hopmeasure.CandidateTarget) (*NodeChainCandidatePacketRequest, error) {
			for _, source := range p.responses {
				if source.Target == target {
					request := base
					request.self, request.response = &request, source
					_, _, _, err := request.current(ctx)
					return &request, err
				}
			}
			return nil, hopmeasure.ErrStale
		}
		if NodeChainPrefixMode(p.responseMode) {
			if base.engine != nil {
				if _, ok := base.engine.reader.(NodeChainCandidateEndpointEngine); !ok {
					return nil, hopmeasure.ErrStale
				}
			}
			open := func(ctx context.Context, target hopmeasure.CandidateTarget) (hopmeasure.CandidateResponseRun, error) {
				request, err := requestFor(ctx, target)
				if err != nil {
					return nil, err
				}
				return request.reserve(ctx)
			}
			if p.appendSource != nil && len(p.appendSource.nodes)+1 > NodeChainMaximumNodes ||
				p.chain != nil && len(p.chain.proofs) > NodeChainMaximumNodes {
				return hopmeasure.NewExtendedResponseRunContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p, open)
			}
			return hopmeasure.NewCapturedResponseRunContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, open)
		}
		if p.responseMode != "hysteria2" || openCandidateHysteria2 == nil {
			return nil, hopmeasure.ErrStale
		}
		respond := func(ctx context.Context, target hopmeasure.CandidateTarget, complete func() error) error {
			request, err := requestFor(ctx, target)
			if err != nil {
				return err
			}
			nonce, err := randomHex(16)
			if err != nil {
				return err
			}
			return request.response.exchangeChallenge(ctx, func(call context.Context, tag, destination string) (net.Conn, error) {
				if tag != p.prefix.Tag {
					return nil, hopmeasure.ErrStale
				}
				return openCandidateHysteria2(call, request, destination)
			}, p.prefix.Tag, nonce, func(string) error { return complete() })
		}
		if p.appendSource != nil && len(p.appendSource.nodes)+1 > NodeChainMaximumNodes {
			return hopmeasure.NewExtendedResponseCandidatesContext(ctx, engine, prefix, p.targets, NodeChainInputLimit, p, respond)
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
