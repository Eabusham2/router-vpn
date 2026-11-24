package mobilemultihop

// Extended selected execution retains one original AWG2 Fast packet entry,
// independently captured literal imports, and the original paired SS final.
// Local mixed routes with another packet, a private stream or a hostname do
// not acquire this separate remote-worker and TUN qualification.
func (c *NodeChain) extendedFastSelectedSource() bool {
	if c == nil || len(c.nodes) <= NodeChainMaximumNodes || c.ExtendedLocalNodeCount() != len(c.nodes) ||
		c.ExtendedMixedLocalPacketCount() != 1 || c.proofs[0].Mode != "awg2-fast" || c.hasPairedStreamInteriorValidated() {
		return false
	}
	for position := 1; position < len(c.nodes)-1; position++ {
		member := c.importedSSMemberAt(position)
		if member == nil || member.hostname != nil || c.nodes[position] != nil {
			return false
		}
	}
	return true
}
