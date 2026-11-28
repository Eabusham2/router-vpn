package multihoprelay

// Family 7 has a real paired Shadowsocks entry and no packet endpoints. Every
// companion remains identity only; source/descriptor/request versioning keeps
// this authority disjoint from the original packet-entry families.
func (m NodeChainPrefixMember) validProxyEntrySS(position int) bool {
	if position < 0 || position >= NodeChainPrefixMaximumMembers || m.Position != position || m.Mode != "shadowsocks" {
		return false
	}
	if position != 0 {
		return m.validRetainedSS(position)
	}
	member := m
	member.Position = 1
	return member.validRetainedSS(1)
}

func (s NodeChainPrefixDescriptor) validateProxyEntrySS() error {
	if s.Schema != 7 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.EntryNodeID) ||
		len(s.LocalPrefix) < 1 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers || s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 ||
		len(s.Candidates) < 1 || len(s.Candidates) > NodeChainPrefixMaximumCandidates || len(s.EntryPeerAddresses) != 1 ||
		!nodeChainPrivateAddress(s.EntryPeerAddresses[0]) || s.LocalPrefix[0].NodeID != s.EntryNodeID ||
		s.PacketCandidatePairs != nil || s.HysteriaCandidatePairs != nil {
		return errNodeChainPrefix
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	for i, member := range s.LocalPrefix {
		if !member.validProxyEntrySS(i) || ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] ||
			keys[member.CompanionClientPublicKey] || keys[member.CompanionServerPublicKey] ||
			companions[member.CompanionSHA256] || transports[member.TransportSHA256] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[member.CompanionClientPublicKey], keys[member.CompanionServerPublicKey] = true, true
		companions[member.CompanionSHA256], transports[member.TransportSHA256] = true, true
	}
	serverSources, serverKeys, serverCompanions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, member := range s.Members {
		local := s.LocalPrefix[i+1]
		if !member.validRetainedSS(i+1) || member.ProfileID != local.ProfileID || member.NodeID != local.NodeID ||
			member.Mode != local.Mode || member.TransportSHA256 != local.TransportSHA256 ||
			member.CompanionServerPublicKey != local.CompanionServerPublicKey ||
			keys[member.CompanionClientPublicKey] || serverKeys[member.CompanionClientPublicKey] ||
			companions[member.CompanionSHA256] || serverCompanions[member.CompanionSHA256] ||
			serverSources[member.SourceSHA256] || sources[member.SourceSHA256] && member.SourceSHA256 != local.SourceSHA256 {
			return errNodeChainPrefix
		}
		serverSources[member.SourceSHA256], serverKeys[member.CompanionClientPublicKey], serverCompanions[member.CompanionSHA256] = true, true, true
	}
	for _, candidate := range s.Candidates {
		if !candidate.valid() || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] || serverSources[candidate.SourceSHA256] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
	}
	return nil
}

// Selection schema 2 is exclusively the packetless proxy-entry family. It
// still selects only genuine rows from the original captured private catalog.
func (q NodeChainPrefixSelectionRequest) validateProxyEntrySS() error {
	challenge := ExternalPacketChallenge{Epoch: q.Epoch, Peer: q.Peer, ExpiresAt: q.AcquireExpiresAt}
	if q.Schema != 2 || q.Purpose != NodeChainPrefixSelectionPurpose || !proofID.MatchString(q.EntryNodeID) ||
		!proofID.MatchString(q.CatalogSHA256) || !proofID.MatchString(q.CatalogGenerationSHA256) ||
		!proofID.MatchString(q.Nonce) || !proofID.MatchString(q.ExecutionSourceSHA256) ||
		!proofID.MatchString(q.OriginalSourceSHA256) || !proofID.MatchString(q.InventorySHA256) ||
		challenge.Validate() != nil || !nodeChainPrivateAddress(q.Peer) ||
		len(q.LocalPrefix) < 1 || len(q.LocalPrefix) > NodeChainPrefixMaximumMembers || q.AppendPosition != len(q.LocalPrefix) ||
		len(q.Candidates) < 1 || len(q.Candidates) > NodeChainPrefixMaximumCandidates || q.LocalPrefix[0].NodeID != q.EntryNodeID {
		return errNodeChainPrefix
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	for i, member := range q.LocalPrefix {
		if !member.validProxyEntrySS(i) || ids[member.ProfileID] || nodes[member.NodeID] || sources[member.SourceSHA256] ||
			keys[member.CompanionClientPublicKey] || keys[member.CompanionServerPublicKey] ||
			companions[member.CompanionSHA256] || transports[member.TransportSHA256] {
			return errNodeChainPrefix
		}
		ids[member.ProfileID], nodes[member.NodeID], sources[member.SourceSHA256] = true, true, true
		keys[member.CompanionClientPublicKey], keys[member.CompanionServerPublicKey] = true, true
		companions[member.CompanionSHA256], transports[member.TransportSHA256] = true, true
	}
	for _, candidate := range q.Candidates {
		if !candidate.valid("shadowsocks") || ids[candidate.ProfileID] || nodes[candidate.NodeID] || sources[candidate.SourceSHA256] {
			return errNodeChainPrefix
		}
		ids[candidate.ProfileID], nodes[candidate.NodeID], sources[candidate.SourceSHA256] = true, true, true
	}
	return nil
}
