package mobilemultihop

// A paired packet-only source may retain the already supported native
// Hysteria2 final, with its original independent layer and private TLS/QUIC closure.
// Imported transport families keep their separately proved final contracts.
// This eligibility check grants no listener, lease or live native proof.
func nodeChainServerFinalCapture(schema int, node *NodeProfile) bool {
	if node == nil {
		return false
	}
	if node.mode == "shadowsocks" {
		return true
	}
	return schema == 1 && node.mode == "hysteria2" && nodeChainFinalCapture(node)
}
