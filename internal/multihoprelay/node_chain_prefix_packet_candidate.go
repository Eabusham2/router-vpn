package multihoprelay

// NodeChainPrefixPacketCandidatePair commits to two independently captured
// packet clients for one paired NEXT destination. It grants no native endpoint,
// complete route, application ingress, or permission to reuse a prior lease.
type NodeChainPrefixPacketCandidatePair struct {
	Position              int    `json:"position"`
	ProfileID             string `json:"profile_id"`
	NodeID                string `json:"node_id"`
	Mode                  string `json:"mode"`
	LocalSourceSHA256     string `json:"local_source_sha256"`
	LocalClientPublicKey  string `json:"local_client_public_key"`
	ServerSourceSHA256    string `json:"server_source_sha256"`
	ServerClientPublicKey string `json:"server_client_public_key"`
	PeerPublicKey         string `json:"peer_public_key"`
	TransportSHA256       string `json:"transport_sha256"`
}

func (p NodeChainPrefixPacketCandidatePair) Validate() error {
	if p.Position < 1 || p.Position > NodeChainPrefixMaximumMembers ||
		!prefixProfileID(p.ProfileID) || !proofID.MatchString(p.NodeID) || !nodeChainPacketMode(p.Mode) ||
		!proofID.MatchString(p.LocalSourceSHA256) || !proofID.MatchString(p.ServerSourceSHA256) ||
		p.LocalSourceSHA256 == p.ServerSourceSHA256 || !proofID.MatchString(p.TransportSHA256) ||
		!nodeChainPacketPublic(p.LocalClientPublicKey) || !nodeChainPacketPublic(p.ServerClientPublicKey) ||
		!nodeChainPacketPublic(p.PeerPublicKey) || p.LocalClientPublicKey == p.ServerClientPublicKey ||
		p.LocalClientPublicKey == p.PeerPublicKey || p.ServerClientPublicKey == p.PeerPublicKey {
		return errNodeChainPrefix
	}
	return nil
}

func (p NodeChainPrefixPacketCandidatePair) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-node-chain-prefix-packet-candidate-pair-v1", p)
}

func (c NodeChainPrefixCandidate) validPacket(mode string) bool {
	return prefixProfileID(c.ProfileID) && proofID.MatchString(c.NodeID) &&
		nodeChainPacketMode(mode) && c.Mode == mode && c.StartLayer == "off" &&
		proofID.MatchString(c.SourceSHA256)
}

func (s NodeChainPrefixDescriptor) validatePacketCandidates() error {
	if s.Schema != 3 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) ||
		!proofID.MatchString(s.EntryNodeID) || len(s.LocalPrefix) < 1 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers ||
		s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 || len(s.Candidates) < 1 ||
		len(s.Candidates) > NodeChainPrefixMaximumCandidates || len(s.PacketCandidatePairs) != len(s.Candidates) ||
		len(s.EntryPeerAddresses) < 1 || len(s.EntryPeerAddresses) > 64 || s.LocalPrefix[0].NodeID != s.EntryNodeID {
		return errNodeChainPrefix
	}
	for i, address := range s.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && s.EntryPeerAddresses[i-1] >= address {
			return errNodeChainPrefix
		}
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, member := range s.LocalPrefix {
		if !member.valid(i) || ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] ||
			keys[member.ClientPublicKey] || keys[member.ServerPublicKey] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[member.ClientPublicKey], keys[member.ServerPublicKey] = true, true
	}
	for i, member := range s.Members {
		local := s.LocalPrefix[i+1]
		if !member.valid(i+1) || member.ProfileID != local.ProfileID || member.NodeID != local.NodeID ||
			member.Mode != local.Mode || member.ServerPublicKey != local.ServerPublicKey ||
			keys[member.ClientPublicKey] || sources[member.SourceSHA256] {
			return errNodeChainPrefix
		}
		keys[member.ClientPublicKey], sources[member.SourceSHA256] = true, true
	}
	mode := s.Candidates[0].Mode
	for i, candidate := range s.Candidates {
		pair := s.PacketCandidatePairs[i]
		if !candidate.validPacket(mode) || pair.Validate() != nil || pair.Position != len(s.LocalPrefix) ||
			pair.ProfileID != candidate.ProfileID || pair.NodeID != candidate.NodeID || pair.Mode != candidate.Mode ||
			pair.LocalSourceSHA256 != candidate.SourceSHA256 || ids[candidate.ProfileID] || nodes[candidate.NodeID] ||
			sources[pair.LocalSourceSHA256] || sources[pair.ServerSourceSHA256] ||
			keys[pair.LocalClientPublicKey] || keys[pair.ServerClientPublicKey] || keys[pair.PeerPublicKey] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID] = true, true
		sources[pair.LocalSourceSHA256], sources[pair.ServerSourceSHA256] = true, true
		keys[pair.LocalClientPublicKey], keys[pair.ServerClientPublicKey], keys[pair.PeerPublicKey] = true, true, true
	}
	return nil
}

// PacketCandidateMode is descriptive readback of the validated public
// commitment. The original policy, request and native owners remain mandatory.
func (s NodeChainPrefixDescriptor) PacketCandidateMode() string {
	if s.Schema != 3 && s.Schema != 4 && s.Schema != 6 || s.Validate() != nil || !nodeChainPacketMode(s.Candidates[0].Mode) {
		return ""
	}
	return s.Candidates[0].Mode
}

// IsPacket identifies the separate request family; it is not an admission.
func (q NodeChainPrefixCandidateRequest) IsPacket() bool {
	return q.Schema == 2
}

func (c NodeChainPrefixCandidateCapture) packetPair() (NodeChainPrefixPacketCandidatePair, error) {
	if !c.Request.IsPacket() || c.Lease.Source.Schema != 3 && c.Lease.Source.Schema != 4 && c.Lease.Source.Schema != 6 ||
		len(c.Lease.Source.PacketCandidatePairs) != len(c.Lease.Source.Candidates) {
		return NodeChainPrefixPacketCandidatePair{}, errNodeChainPrefix
	}
	for i, candidate := range c.Lease.Source.Candidates {
		if candidate != c.Candidate {
			continue
		}
		pair := c.Lease.Source.PacketCandidatePairs[i]
		if pair.Validate() != nil || pair.Position != c.Request.AppendPosition ||
			pair.ProfileID != c.Request.CandidateID || pair.NodeID != candidate.NodeID ||
			pair.Mode != c.Request.CandidateMode || pair.Mode != candidate.Mode ||
			pair.LocalSourceSHA256 != c.Request.CandidateSourceSHA256 ||
			pair.LocalSourceSHA256 != candidate.SourceSHA256 || pair.LocalClientPublicKey != c.Request.CandidateClientPublicKey {
			return NodeChainPrefixPacketCandidatePair{}, errNodeChainPrefix
		}
		return pair, nil
	}
	return NodeChainPrefixPacketCandidatePair{}, errNodeChainPrefix
}

func (c NodeChainPrefixCandidateCapture) validCandidate() bool {
	if c.Request.IsHysteria() {
		if !c.Candidate.validHysteria() {
			return false
		}
		_, err := c.hysteriaPair()
		return err == nil
	}
	if !c.Request.IsPacket() {
		return c.Candidate.valid()
	}
	if !c.Candidate.validPacket(c.Request.CandidateMode) {
		return false
	}
	_, err := c.packetPair()
	return err == nil
}

// PacketPair returns only this validated capture's original public commitment.
func (c NodeChainPrefixCandidateCapture) PacketPair() (NodeChainPrefixPacketCandidatePair, error) {
	if c.Validate() != nil {
		return NodeChainPrefixPacketCandidatePair{}, errNodeChainPrefix
	}
	return c.packetPair()
}
