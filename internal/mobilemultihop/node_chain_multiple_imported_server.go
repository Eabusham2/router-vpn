package mobilemultihop

import "reflect"

// This scope belongs to the original operator policy. It never supplies the
// omitted client entry, a measured outer packet capacity, or a live socket.
type nodeChainMultipleImportedServerScope struct {
	self               *nodeChainMultipleImportedServerScope
	policy             *NodeChainServerPolicy
	source             string
	carrier            *NodeChainServerCarrier
	members, originals []*nodeChainImportedMember
	nodes              []*NodeProfile
	policies           []*ExternalPolicy
	inputs             []string
	closures           []*externalPredecessor
	firstPacket        int
}

func NewNodeChainMultipleImportedServerPolicy(source string) (*NodeChainServerPolicy, error) {
	return newNodeChainServerPolicyFamily(source, nil, 6)
}

func (s *nodeChainMultipleImportedServerScope) freeze(p *NodeChainServerPolicy, closures []*externalPredecessor) error {
	if s == nil || s.self != nil || p == nil || p.multiple != s || len(s.members) != len(p.nodes) || len(closures) != len(p.nodes) {
		return nodeChainServerError
	}
	s.self, s.policy, s.source, s.carrier = s, p, p.sourceJSON, p.carrier
	s.originals = append([]*nodeChainImportedMember(nil), s.members...)
	s.nodes = append([]*NodeProfile(nil), p.nodes...)
	s.closures = append([]*externalPredecessor(nil), closures...)
	s.policies, s.inputs = make([]*ExternalPolicy, len(s.members)), make([]string, len(s.members))
	s.firstPacket = -1
	for i, m := range s.members {
		if m != nil {
			// Reuse the Local compiler's immutable input and policy snapshots.
			// Every later worker observation still compares both captured maps
			// and the original pointer before using the existing source digest.
			if len(s.members) > NodeChainMaximumNodes-1 {
				if err := m.rememberMultipleImportedMember(); err != nil {
					return err
				}
			}
			s.policies[i], s.inputs[i] = m.policy, m.input
		} else if i < len(s.members)-1 && NodeChainPrefixMode(p.nodes[i].mode) && s.firstPacket == -1 {
			s.firstPacket = i
		}
	}
	if (len(s.members) > NodeChainMaximumNodes-1 || p.descriptor.PrivateStreamPosition() > 0) && !extendedStreamClosures(closures) {
		return nodeChainServerError
	}
	if !s.original() {
		return nodeChainServerError
	}
	return nil
}

func (s *nodeChainMultipleImportedServerScope) original() bool {
	if s == nil || s.self != s || s.policy == nil || s.policy.multiple != s || s.policy.descriptor.Schema != 6 ||
		s.policy.sourceJSON != s.source || s.policy.carrier != s.carrier || s.policy.importedMiddle != nil ||
		s.policy.openvpn != nil || s.policy.openvpnMiddle != nil || s.policy.socks != nil || s.policy.socksMiddle != nil ||
		s.policy.connect != nil || s.policy.connectMiddle != nil || len(s.members) < 2 || len(s.members) > NodeChainExtendedLocalMaximumNodes-1 ||
		len(s.members) != len(s.policy.nodes) || len(s.nodes) != len(s.members) || len(s.originals) != len(s.members) ||
		len(s.policies) != len(s.members) || len(s.inputs) != len(s.members) || len(s.closures) != len(s.members) {
		return false
	}
	count, first := 0, -1
	for i, m := range s.members {
		if m != s.originals[i] || s.nodes[i] != s.policy.nodes[i] || s.closures[i] == nil {
			return false
		}
		if m != nil {
			if i == len(s.members)-1 || s.nodes[i] != nil || m.policy != s.policies[i] || m.input != s.inputs[i] ||
				m.hostname != nil || m.validate() != nil {
				return false
			}
			count++
		} else {
			node := s.nodes[i]
			if node == nil || s.policies[i] != nil || s.inputs[i] != "" || node.validateNodeDesktopCapture() != nil ||
				i < len(s.members)-1 && !NodeChainPrefixMode(node.mode) && !s.policy.descriptor.PrivateStreamAt(i+1) || i == len(s.members)-1 && node.mode != "shadowsocks" {
				return false
			}
			if i < len(s.members)-1 && NodeChainPrefixMode(node.mode) && first == -1 {
				first = i
			}
		}
	}
	return count > 0 && first == s.firstPacket && (s.carrier == nil || first == 0 && s.carrier.family == 6 && s.carrier.sealed())
}

func (s *nodeChainMultipleImportedServerScope) validateCompilation(members []nodeChainGraphMember, closures []*externalPredecessor) error {
	if !s.original() || len(members) != len(s.members) || len(closures) != len(s.closures) {
		return nodeChainServerError
	}
	for i, member := range members {
		if closures[i] != s.closures[i] {
			return nodeChainServerError
		}
		if original := s.members[i]; original != nil {
			if !member.imported || member.mode != "shadowsocks" || member.source != original.source || !reflect.DeepEqual(member.profile, original.selection.Profile) {
				return nodeChainServerError
			}
		} else {
			original := s.nodes[i]
			if member.imported || member.mode != original.mode || member.source != original.source || !reflect.DeepEqual(member.profile, original.profile) {
				return nodeChainServerError
			}
		}
	}
	return nil
}

// Only the first actual packet preceded entirely by original literal SS rows
// has no earlier packet interface in this suffix. The ordinary nonpacket-root
// MTU policy still applies; later packet edges retain the complete envelope.
func (s *nodeChainMultipleImportedServerScope) firstPhysicalPacket(position int) bool {
	if !s.original() || position <= 0 || position != s.firstPacket {
		return false
	}
	for i := 0; i < position; i++ {
		if s.members[i] == nil || s.nodes[i] != nil {
			return false
		}
	}
	return true
}

// Individual proofs can use TCP while a later packet interface carries UDP.
// Every projection stays within the original set and their union must equal
// that whole set, including the final application and selected-DNS projection.
func (s *nodeChainMultipleImportedServerScope) completePhysicalEgress(projections [][]PhysicalEgress, expected []PhysicalEgress) ([]PhysicalEgress, error) {
	if !s.original() || s.firstPacket <= 0 || len(projections) != len(s.members) || s.members[0] == nil {
		return nil, nodeChainServerError
	}
	actual, err := s.members[0].policy.DirectPhysicalEgress([]string{"tcp", "udp"})
	if err != nil || !nodeChainSamePhysical(actual, expected) || len(expected) != 2 {
		return nil, nodeChainServerError
	}
	allowed, union := map[PhysicalEgress]bool{}, map[PhysicalEgress]bool{}
	for _, tuple := range expected {
		if allowed[tuple] {
			return nil, nodeChainServerError
		}
		allowed[tuple] = true
	}
	for _, projection := range projections {
		if len(projection) == 0 {
			return nil, nodeChainServerError
		}
		seen := map[PhysicalEgress]bool{}
		for _, tuple := range projection {
			if !allowed[tuple] || seen[tuple] {
				return nil, nodeChainServerError
			}
			seen[tuple], union[tuple] = true, true
		}
	}
	if len(union) != len(allowed) || !s.original() {
		return nil, nodeChainServerError
	}
	return append([]PhysicalEgress(nil), expected...), nil
}

func (p *NodeChainServerPolicy) importedSSMemberAt(position int) *nodeChainImportedMember {
	if p == nil || position < 0 || position >= len(p.nodes) {
		return nil
	}
	if p.multiple != nil {
		if len(p.multiple.members) != len(p.nodes) {
			return nil
		}
		return p.multiple.members[position]
	}
	if position == len(p.nodes)-2 {
		return p.importedMiddle
	}
	return nil
}
