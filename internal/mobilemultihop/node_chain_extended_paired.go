package mobilemultihop

// Extended paired routes carry only standard WG prefixes with independently
// linked Router identities, followed by a paired SS2022 final. The ordinary
// closure compiler computes the actual nested packet MTU for every prefix.
func extendedPairedLocalNodes(nodes []*NodeProfile) bool {
	if len(nodes) <= NodeChainMaximumNodes || len(nodes) > NodeChainExtendedLocalMaximumNodes {
		return false
	}
	seen := map[PhysicalEgress]bool{}
	for i, n := range nodes {
		if n == nil {
			return false
		}
		mode := "wg"
		if i == len(nodes)-1 {
			mode = "shadowsocks"
		}
		layer := predecessorText(n.profile, "start_layer")
		if n.mode != mode || (layer != "" && layer != "off") {
			return false
		}
		sockets, err := n.PhysicalEgress()
		if err != nil || len(sockets) == 0 {
			return false
		}
		for _, socket := range sockets {
			if seen[socket] {
				return false
			}
			seen[socket] = true
		}
	}
	return true
}

func extendedPairedLocalProofs(proofs []NodeChainProof) bool {
	if len(proofs) <= NodeChainMaximumNodes || len(proofs) > NodeChainExtendedLocalMaximumNodes {
		return false
	}
	for i, p := range proofs {
		mode := "wg"
		if i == len(proofs)-1 {
			mode = "shadowsocks"
		}
		if p.Position != i || p.Mode != mode || p.StartLayer != "off" || p.Kind != "" || p.NodeKind != "" ||
			!proofID.MatchString(p.SourceSHA256) || !proofID.MatchString(p.NodeID) || !exactID.MatchString(p.ProfileID) {
			return false
		}
	}
	return true
}

// ExtendedPairedLocalNodeCount binds deeper packet operations to the complete
// independently captured source and the original native compiler instance.
func (c *NodeChain) ExtendedPairedLocalNodeCount() int {
	if c == nil || c.extendedPairedOwner != c || c.validateCapture() != nil {
		return 0
	}
	return len(c.nodes)
}
