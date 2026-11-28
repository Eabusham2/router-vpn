package multihoprelay

// Family 6 binds a real packet continuation after an original HY2 transport.
// It retains the full ordered count independently of packet reservation keys.
// Families 1-5 keep their original canonical validators and digest domains.
func (s NodeChainPrefixDescriptor) validateHysteriaPacketPrefix() error {
	if s.Schema != 6 || s.Purpose != NodeChainPrefixPurpose || !proofID.MatchString(s.SourceSHA256) || !proofID.MatchString(s.EntryNodeID) ||
		len(s.LocalPrefix) < 2 || len(s.LocalPrefix) > NodeChainPrefixMaximumMembers || s.Members == nil || len(s.Members) != len(s.LocalPrefix)-1 ||
		len(s.Candidates) < 1 || len(s.Candidates) > NodeChainPrefixMaximumCandidates || len(s.EntryPeerAddresses) < 1 || len(s.EntryPeerAddresses) > 64 ||
		s.LocalPrefix[0].NodeID != s.EntryNodeID || !nodeChainPacketMode(s.LocalPrefix[0].Mode) {
		return errNodeChainPrefix
	}
	for i, address := range s.EntryPeerAddresses {
		if !nodeChainPrivateAddress(address) || i > 0 && s.EntryPeerAddresses[i-1] >= address {
			return errNodeChainPrefix
		}
	}
	ids, nodes, sources, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	companions, transports := map[string]bool{}, map[string]bool{}
	hysteria, packetAfterHysteria := false, false
	for i, member := range s.LocalPrefix {
		if nodeChainPacketMode(member.Mode) {
			if !member.valid(i) {
				return errNodeChainPrefix
			}
			packetAfterHysteria = packetAfterHysteria || hysteria
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
	packet := nodeChainPacketMode(mode)
	if !hysteria || !packet && !packetAfterHysteria {
		return errNodeChainPrefix
	}
	switch {
	case packet:
		if len(s.PacketCandidatePairs) != len(s.Candidates) || s.HysteriaCandidatePairs != nil {
			return errNodeChainPrefix
		}
	case mode == "hysteria2":
		if len(s.HysteriaCandidatePairs) != len(s.Candidates) || s.PacketCandidatePairs != nil {
			return errNodeChainPrefix
		}
	case mode == "shadowsocks":
		if s.PacketCandidatePairs != nil || s.HysteriaCandidatePairs != nil {
			return errNodeChainPrefix
		}
	default:
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
		if packet {
			pair := s.PacketCandidatePairs[i]
			if !candidate.validPacket(mode) || pair.Validate() != nil || pair.Position != len(s.LocalPrefix) ||
				pair.ProfileID != candidate.ProfileID || pair.NodeID != candidate.NodeID || pair.Mode != candidate.Mode ||
				pair.LocalSourceSHA256 != candidate.SourceSHA256 || ids[candidate.ProfileID] || nodes[candidate.NodeID] ||
				sources[pair.LocalSourceSHA256] || sources[pair.ServerSourceSHA256] ||
				serverSources[pair.LocalSourceSHA256] || serverSources[pair.ServerSourceSHA256] ||
				keys[pair.LocalClientPublicKey] || keys[pair.ServerClientPublicKey] || keys[pair.PeerPublicKey] ||
				serverKeys[pair.LocalClientPublicKey] || serverKeys[pair.ServerClientPublicKey] || serverKeys[pair.PeerPublicKey] ||
				transports[pair.TransportSHA256] {
				return errNodeChainPrefix
			}
			ids[candidate.ProfileID], nodes[candidate.NodeID] = true, true
			sources[pair.LocalSourceSHA256], sources[pair.ServerSourceSHA256] = true, true
			keys[pair.LocalClientPublicKey], keys[pair.ServerClientPublicKey], keys[pair.PeerPublicKey] = true, true, true
			transports[pair.TransportSHA256] = true
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
