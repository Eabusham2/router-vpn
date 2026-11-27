package mobilemultihop

import "router-vpn/internal/multihoprelay"

// NodeChainServerCandidateTarget is a bounded handshake or challenge target
// compiled from the original private server policy. It is not a proof exception.
// Native admission still needs the original worker, operation and live endpoint.
type NodeChainServerCandidateTarget struct {
	firstPacket    bool
	publicOriginal *nodeChainServerPublicCandidateTarget
	self           *NodeChainServerCandidateTarget
	policy         *NodeChainServerPolicy
	node           *NodeProfile
	stream         *nodeChainImportedMember
	socks          *nodeChainSOCKSMember
	connect        *nodeChainCONNECTMember
	openvpn        *nodeChainOpenVPNMember
	capture        multihoprelay.NodeChainCandidateCapture
	tag            string
}

func (p *NodeChainServerPolicy) CandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if c.Request.Schema != 1 {
		return nil, nodeChainServerError
	}
	return p.originalCandidateTarget(c)
}
func (p *NodeChainServerPolicy) ResponseCandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if c.Request.Schema != 2 {
		return nil, nodeChainServerError
	}
	return p.originalCandidateTarget(c)
}
func (p *NodeChainServerPolicy) originalCandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if c.Validate() != nil {
		return nil, nodeChainServerError
	}
	if _, err := p.binding(c.Lease); err != nil {
		return nil, err
	}
	index := c.Request.Position - 1
	if index < 0 || index >= len(p.nodes)-1 || index >= len(p.proofs) || c.Member != p.descriptor.Members[index] {
		return nil, nodeChainServerError
	}
	node := p.nodes[index]
	var stream *nodeChainImportedMember
	var socks *nodeChainSOCKSMember
	var connect *nodeChainCONNECTMember
	var openvpn *nodeChainOpenVPNMember
	if c.Request.Schema == 4 {
		if !p.descriptor.PacketCandidateResponsePrefix(c.Request.Position, c.Request.CandidateMode) {
			return nil, nodeChainServerError
		}
		// Packet members bind public keys; their descriptor source hash is
		// intentionally empty. The sealed original prefix proof carries the
		// complete private node source. Imported members carry their own hash.
		if c.Member.NodeKind == "external" {
			stream = p.importedSSMemberAt(index)
			if node != nil || stream == nil || stream.source != c.Member.SourceSHA256 || stream.hostname != nil {
				return nil, nodeChainServerError
			}
		} else if node == nil || !NodeChainPrefixMode(node.mode) || node.source != p.proofs[index].SourceSHA256 {
			return nil, nodeChainServerError
		}
	} else if c.Request.Schema == 3 {
		if !p.descriptor.PublicCandidateResponsePrefix(c.Request.Position) || p.externalFinal == nil {
			return nil, nodeChainServerError
		}
		stream = p.importedSSMemberAt(index)
		if node != nil || stream == nil || stream.source != c.Member.SourceSHA256 || stream.hostname != nil {
			return nil, nodeChainServerError
		}
	} else if c.Request.Schema == 2 {
		if !p.descriptor.CandidateResponsePrefix(c.Request.Position) {
			return nil, nodeChainServerError
		}
		if c.Member.NodeKind == "external" {
			if node != nil {
				return nil, nodeChainServerError
			}
			switch c.Member.Mode {
			case "socks5":
				socks = p.socksMiddle
				if p.socks == nil || p.socks.middle != socks || socks == nil || socks.source != c.Member.SourceSHA256 {
					return nil, nodeChainServerError
				}
			case "http-connect", "https-connect":
				connect = p.connectMiddle
				if p.connect == nil || p.connect.middle != connect || connect == nil || connect.source != c.Member.SourceSHA256 {
					return nil, nodeChainServerError
				}
			case "openvpn":
				openvpn = p.openvpnMiddle
				if p.openvpn == nil || p.openvpn.middle != openvpn || openvpn == nil || openvpn.source != c.Member.SourceSHA256 {
					return nil, nodeChainServerError
				}
			case "shadowsocks":
				if p.multiple != nil {
					stream = p.multiple.members[index]
				} else {
					stream = p.importedMiddle
				}
				if stream == nil || stream.source != c.Member.SourceSHA256 || stream.hostname != nil {
					return nil, nodeChainServerError
				}
			default:
				return nil, nodeChainServerError
			}
		} else if node == nil || node.mode != "shadowsocks" || node.source != c.Member.SourceSHA256 {
			return nil, nodeChainServerError
		}
	} else if node == nil || !NodeChainPrefixMode(node.mode) {
		return nil, nodeChainServerError
	}
	// No Destinations: an original API/DNS proof exception must never override
	// the selected application LAN/IPv6 policy for an arbitrary candidate.
	policy := NodeChainServerFrontRoute{Final: true, BlockIPv6: p.blockIPv6, BlockedCIDRs: append([]string(nil), p.blockedCIDRs...)}
	network := "tcp"
	if c.Request.Schema == 4 {
		network = "udp"
	}
	if !policy.AllowsDestination(network, c.Request.Address) {
		return nil, nodeChainServerError
	}
	target := &NodeChainServerCandidateTarget{policy: p, node: node, stream: stream, socks: socks, connect: connect, openvpn: openvpn, capture: c.Clone(), tag: p.proofs[index].Tag}
	target.self = target
	return target, nil
}

// Read returns only the exact original prefix tag and literal TCP destination.
// The worker admits a handshake or its registered authenticated challenge,
// never arbitrary application forwarding.
func (t *NodeChainServerCandidateTarget) Read(p *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) (string, string, error) {
	if t == nil || t.self != t || p == nil || p != t.policy {
		return "", "", nodeChainServerError
	}
	if t.firstPacket || c.Request.Schema == 5 {
		fresh, err := p.FirstPacketResponseCandidateTarget(c)
		want, before := t.capture.Digest()
		got, after := c.Digest()
		if err != nil || before != nil || after != nil || want != got || !t.firstPacket || fresh.node != t.node || t.tag != "" {
			return "", "", nodeChainServerError
		}
		return "", t.capture.Request.Address, nil
	}
	if t.publicOriginal != nil || c.Request.Schema == 3 {
		return t.readPublicCandidate(p, c)
	}
	want, err := t.capture.Digest()
	got, other := c.Digest()
	if err != nil || other != nil || want != got {
		return "", "", nodeChainServerError
	}
	fresh, err := p.originalCandidateTarget(c)
	if err != nil || fresh.node != t.node || fresh.stream != t.stream || fresh.socks != t.socks ||
		fresh.connect != t.connect || fresh.openvpn != t.openvpn || fresh.tag != t.tag || t.tag == "" {
		return "", "", nodeChainServerError
	}
	return t.tag, t.capture.Request.Address, nil
}

func (p *NodeChainServerPolicy) PacketResponseCandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if c.Request.Schema != 4 {
		return nil, nodeChainServerError
	}
	return p.originalCandidateTarget(c)
}

// The first Server suffix has no preceding Server outbound. Its separate
// candidate request acquires a new, source-bound physical carrier in Prepare.
func (p *NodeChainServerPolicy) FirstPacketResponseCandidateTarget(c multihoprelay.NodeChainCandidateCapture) (*NodeChainServerCandidateTarget, error) {
	if p == nil || c.Request.Schema != 5 || c.Validate() != nil || p.validateCapture() != nil || !p.descriptor.FirstPacketCandidateResponse(c.Request.CandidateMode) {
		return nil, nodeChainServerError
	}
	if _, err := p.binding(c.Lease); err != nil {
		return nil, err
	}
	route := NodeChainServerFrontRoute{Final: true, BlockIPv6: p.blockIPv6, BlockedCIDRs: append([]string(nil), p.blockedCIDRs...)}
	if !route.AllowsDestination("udp", c.Request.Address) || len(p.nodes) < 2 || p.nodes[0] == nil {
		return nil, nodeChainServerError
	}
	target := &NodeChainServerCandidateTarget{firstPacket: true, policy: p, node: p.nodes[0], capture: c.Clone()}
	target.self = target
	return target, nil
}
