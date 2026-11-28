package multihoprelay

// NodeChainPrefixHysteriaCandidatePair binds the actual selected HY2 transport
// to independently captured Local and Server companions. Companion keys do not
// grant selected packet authority, endpoint readiness or complete-route use.
type NodeChainPrefixHysteriaCandidatePair struct {
	Position                       int    `json:"position"`
	ProfileID                      string `json:"profile_id"`
	NodeID                         string `json:"node_id"`
	Mode                           string `json:"mode"`
	LocalSourceSHA256              string `json:"local_source_sha256"`
	ServerSourceSHA256             string `json:"server_source_sha256"`
	TransportSHA256                string `json:"transport_sha256"`
	LocalCompanionSHA256           string `json:"local_companion_sha256"`
	ServerCompanionSHA256          string `json:"server_companion_sha256"`
	LocalCompanionClientPublicKey  string `json:"local_companion_client_public_key"`
	ServerCompanionClientPublicKey string `json:"server_companion_client_public_key"`
	CompanionServerPublicKey       string `json:"companion_server_public_key"`
}

func (p NodeChainPrefixHysteriaCandidatePair) Validate() error {
	if p.Position < 1 || p.Position > NodeChainPrefixMaximumMembers || !prefixProfileID(p.ProfileID) || !proofID.MatchString(p.NodeID) ||
		p.Mode != "hysteria2" || !proofID.MatchString(p.LocalSourceSHA256) || !proofID.MatchString(p.ServerSourceSHA256) ||
		!proofID.MatchString(p.TransportSHA256) || !proofID.MatchString(p.LocalCompanionSHA256) || !proofID.MatchString(p.ServerCompanionSHA256) ||
		p.LocalCompanionSHA256 == p.ServerCompanionSHA256 || !nodeChainPacketPublic(p.LocalCompanionClientPublicKey) ||
		!nodeChainPacketPublic(p.ServerCompanionClientPublicKey) || !nodeChainPacketPublic(p.CompanionServerPublicKey) ||
		p.LocalCompanionClientPublicKey == p.ServerCompanionClientPublicKey || p.LocalCompanionClientPublicKey == p.CompanionServerPublicKey ||
		p.ServerCompanionClientPublicKey == p.CompanionServerPublicKey {
		return errNodeChainPrefix
	}
	return nil
}

func (p NodeChainPrefixHysteriaCandidatePair) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-node-chain-prefix-hysteria-candidate-pair-v1", p)
}

func (m NodeChainPrefixMember) validRetainedHysteria(position int) bool {
	return position > 0 && m.Position == position && prefixProfileID(m.ProfileID) && proofID.MatchString(m.NodeID) &&
		m.Mode == "hysteria2" && m.StartLayer == "off" && proofID.MatchString(m.SourceSHA256) &&
		m.ClientPublicKey == "" && m.ServerPublicKey == "" && proofID.MatchString(m.TransportSHA256) && proofID.MatchString(m.CompanionSHA256) &&
		nodeChainPacketPublic(m.CompanionClientPublicKey) && nodeChainPacketPublic(m.CompanionServerPublicKey) && m.CompanionClientPublicKey != m.CompanionServerPublicKey
}

func (m NodeChainPrefixMember) validHysteriaStream(position int) bool {
	return m.validRetainedSS(position) || m.validRetainedHysteria(position)
}

func (m NodeChainPrefixMember) hysteriaIdentityKeys() (string, string) {
	if m.Mode == "hysteria2" {
		return m.CompanionClientPublicKey, m.CompanionServerPublicKey
	}
	return m.identityKeys()
}

func (c NodeChainPrefixCandidate) validHysteria() bool {
	return prefixProfileID(c.ProfileID) && proofID.MatchString(c.NodeID) && c.Mode == "hysteria2" &&
		c.StartLayer == "off" && proofID.MatchString(c.SourceSHA256)
}

// Family 5 is selected only for HY2 NEXT or an already retained HY2 member.
// Packet members precede the first HY2; its retained tail admits only SS/HY2.
// Original families 1-4 keep their own unchanged canonical validators.
func (s NodeChainPrefixDescriptor) validateHysteriaPrefix() error {
	if s.Schema != 5 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.EntryNodeID) ||
		len(s.LocalPrefix) < 1 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers || s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 ||
		len(s.Candidates) < 1 || len(s.Candidates) > NodeChainPrefixMaximumCandidates || len(s.EntryPeerAddresses) < 1 || len(s.EntryPeerAddresses) > 64 ||
		s.LocalPrefix[0].NodeID != s.EntryNodeID || !nodeChainPacketMode(s.LocalPrefix[0].Mode) || s.PacketCandidatePairs != nil {
		return errNodeChainPrefix
	}
	for i, address := range s.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && s.EntryPeerAddresses[i-1] >= address {
			return errNodeChainPrefix
		}
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	hysteria := false
	for i, member := range s.LocalPrefix {
		if nodeChainPacketMode(member.Mode) {
			if hysteria || !member.valid(i) {
				return errNodeChainPrefix
			}
		} else {
			if !member.validHysteriaStream(i) || companions[member.CompanionSHA256] || transports[member.TransportSHA256] {
				return errNodeChainPrefix
			}
			hysteria = hysteria || member.Mode == "hysteria2"
			companions[member.CompanionSHA256], transports[member.TransportSHA256] = true, true
		}
		client, server := member.hysteriaIdentityKeys()
		if ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] || keys[client] || keys[server] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[client], keys[server] = true, true
	}
	mode := s.Candidates[0].Mode
	if mode == "hysteria2" {
		if len(s.HysteriaCandidatePairs) != len(s.Candidates) {
			return errNodeChainPrefix
		}
	} else if mode != "shadowsocks" || !hysteria || s.HysteriaCandidatePairs != nil {
		return errNodeChainPrefix
	}
	serverSources, serverKeys, serverCompanions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, member := range s.Members {
		local := s.LocalPrefix[i+1]
		if member.ProfileID != local.ProfileID || member.NodeID != local.NodeID || member.Mode != local.Mode || serverSources[member.SourceSHA256] {
			return errNodeChainPrefix
		}
		client, server := member.hysteriaIdentityKeys()
		_, localServer := local.hysteriaIdentityKeys()
		if server != localServer || keys[client] || serverKeys[client] {
			return errNodeChainPrefix
		}
		if nodeChainPacketMode(member.Mode) {
			if !member.valid(i+1) || sources[member.SourceSHA256] {
				return errNodeChainPrefix
			}
		} else if !member.validHysteriaStream(i+1) || member.TransportSHA256 != local.TransportSHA256 ||
			companions[member.CompanionSHA256] || serverCompanions[member.CompanionSHA256] ||
			sources[member.SourceSHA256] && member.SourceSHA256 != local.SourceSHA256 {
			return errNodeChainPrefix
		} else {
			serverCompanions[member.CompanionSHA256] = true
		}
		serverSources[member.SourceSHA256], serverKeys[client] = true, true
	}
	for i, candidate := range s.Candidates {
		if mode == "shadowsocks" {
			if !candidate.valid() || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] || serverSources[candidate.SourceSHA256] {
				return errNodeChainPrefix
			}
			ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
			continue
		}
		pair := s.HysteriaCandidatePairs[i]
		if !candidate.validHysteria() || pair.Validate() != nil || pair.Position != len(s.LocalPrefix) ||
			pair.ProfileID != candidate.ProfileID || pair.NodeID != candidate.NodeID || pair.Mode != candidate.Mode || pair.LocalSourceSHA256 != candidate.SourceSHA256 ||
			ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[pair.LocalSourceSHA256] || sources[pair.ServerSourceSHA256] ||
			serverSources[pair.LocalSourceSHA256] || serverSources[pair.ServerSourceSHA256] || transports[pair.TransportSHA256] ||
			companions[pair.LocalCompanionSHA256] || companions[pair.ServerCompanionSHA256] ||
			serverCompanions[pair.LocalCompanionSHA256] || serverCompanions[pair.ServerCompanionSHA256] ||
			keys[pair.LocalCompanionClientPublicKey] || keys[pair.ServerCompanionClientPublicKey] || keys[pair.CompanionServerPublicKey] ||
			serverKeys[pair.LocalCompanionClientPublicKey] || serverKeys[pair.ServerCompanionClientPublicKey] || serverKeys[pair.CompanionServerPublicKey] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID] = true, true
		sources[pair.LocalSourceSHA256], sources[pair.ServerSourceSHA256] = true, true
		companions[pair.LocalCompanionSHA256], companions[pair.ServerCompanionSHA256] = true, true
		keys[pair.LocalCompanionClientPublicKey], keys[pair.ServerCompanionClientPublicKey], keys[pair.CompanionServerPublicKey] = true, true, true
		transports[pair.TransportSHA256] = true
	}
	return nil
}

// HysteriaCandidateMode is descriptive; the original private policy and native
// endpoint are still required before a candidate can be prepared or observed.
func (s NodeChainPrefixDescriptor) HysteriaCandidateMode() string {
	if s.Schema != 5 && s.Schema != 6 || s.Validate() != nil || s.Candidates[0].Mode != "hysteria2" {
		return ""
	}
	return s.Candidates[0].Mode
}

// IsHysteria identifies the separate request family, not an admission.
func (q NodeChainPrefixCandidateRequest) IsHysteria() bool {
	return q.Schema == 3 && q.CandidateMode == "hysteria2"
}

func (c NodeChainPrefixCandidateCapture) hysteriaPair() (NodeChainPrefixHysteriaCandidatePair, error) {
	if !c.Request.IsHysteria() || c.Lease.Source.Schema != 5 && c.Lease.Source.Schema != 6 || c.Request.CandidateClientPublicKey != "" ||
		len(c.Lease.Source.HysteriaCandidatePairs) != len(c.Lease.Source.Candidates) {
		return NodeChainPrefixHysteriaCandidatePair{}, errNodeChainPrefix
	}
	for i, candidate := range c.Lease.Source.Candidates {
		if candidate != c.Candidate {
			continue
		}
		pair := c.Lease.Source.HysteriaCandidatePairs[i]
		digest, err := pair.Digest()
		if err != nil || digest != c.Request.CandidateHysteriaSHA256 || pair.Position != c.Request.AppendPosition ||
			pair.ProfileID != c.Request.CandidateID || pair.NodeID != candidate.NodeID || pair.Mode != c.Request.CandidateMode || pair.Mode != candidate.Mode ||
			pair.LocalSourceSHA256 != c.Request.CandidateSourceSHA256 || pair.LocalSourceSHA256 != candidate.SourceSHA256 {
			return NodeChainPrefixHysteriaCandidatePair{}, errNodeChainPrefix
		}
		return pair, nil
	}
	return NodeChainPrefixHysteriaCandidatePair{}, errNodeChainPrefix
}

// HysteriaPair returns only the original commitment of this validated capture.
func (c NodeChainPrefixCandidateCapture) HysteriaPair() (NodeChainPrefixHysteriaCandidatePair, error) {
	if c.Validate() != nil {
		return NodeChainPrefixHysteriaCandidatePair{}, errNodeChainPrefix
	}
	return c.hysteriaPair()
}
