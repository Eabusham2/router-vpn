package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"errors"
	"net"
	"strings"

	"router-vpn/internal/hopmeasure"
)

// Only the pinned native build supplies the Shadowsocks2022 cipher. The
// standalone source compiler can describe, but cannot execute, this capability.
var wrapCandidateSS2022 func(context.Context, net.Conn, string, string, string) (net.Conn, error)

type candidateResponseSource struct {
	Target                               hopmeasure.CandidateTarget
	NodeID, API, Token, Method, Password string
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
	return candidateResponseSource{target, nodeID, strings.TrimRight(api.String(), "/"), token, predecessorText(closure.final, "method"), predecessorText(closure.final, "password")}, nil
}

func NodeChainCandidateInputSupportedForMeasurement(input, measurement string) bool {
	switch measurement {
	case hopmeasure.CandidateTCPMeasurement:
		return NodeChainCandidateInputSupported(input)
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
	if c.nodes[position] != nil && NodeChainPrefixMode(c.proofs[position].Mode) && !((c.openVPNMiddle != nil || c.importedMiddle != nil) && position >= len(c.nodes)-2) {
		if position > 7 && (position >= len(c.proofs)-1 || c.ExtendedPairedLocalNodeCount() != len(c.nodes) && position >= c.ExtendedMixedLocalPacketCount()) {
			return ""
		}
		return hopmeasure.CandidateTCPMeasurement
	}
	last := len(c.proofs) - 1
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
				if c.importedNodes == nil || i != 2 || previous == nil || previous.hostname != nil {
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
	if p.validate() != nil || p.multiple == nil || p.measurement != hopmeasure.CandidatePrivateResponseMeasurement || p.prefix.Position != position || p.prefix.ProfileID != id || p.prefix.Tag != tag || p.chain.candidatePrefixMeasurementValidated(position) != p.measurement {
		return 0
	}
	return p.chain.ExtendedLocalNodeCount()
}

func (p *NodeChainCandidatePreparation) ExtendedCandidateDepth() int {
	if p.validate() != nil {
		return 0
	}
	proof := p.proofs[p.position]
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
	request := hopmeasure.CandidateChallengeMAC(s.Token, s.NodeID, nonce, false)
	api, err := privateAPI(s.API)
	if err != nil {
		return err
	}
	_, err = externalProofHTTPVerified(ctx, func(call context.Context, routedTag, privateAddress string) (net.Conn, error) {
		if routedTag != tag || privateAddress != api.Host {
			return nil, hopmeasure.ErrStale
		}
		raw, err := engine.Dial(call, tag, s.Target.Address)
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
			conn, err = wrapCandidateSS2022(call, raw, s.Method, s.Password, privateAddress)
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
		return complete()
	})
	return err
}
