package mobilemultihop

// nodeChainFinalCapture is deliberately scoped to the paired Local compiler.
// Imported-middle, Server, Compare and candidate-target admission retain their
// own narrower guards. A mode name alone never authorizes a native closure.
func nodeChainFinalCapture(node *NodeProfile) bool {
	if node == nil {
		return false
	}
	switch node.mode {
	case "shadowsocks":
		return true
	case "hysteria2":
		layer := predecessorText(node.profile, "start_layer")
		return layer == "" || layer == "off"
	default:
		return false
	}
}

// The caller first validates the sealed NodeProfile and reconstructs its
// original closure. Hysteria2 keeps the native TLS, CA, password and Salamander
// configuration intact; no wrapper or alternate dial owner is introduced here.
func nodeChainFinalClosure(node *NodeProfile, closure *externalPredecessor) bool {
	if !nodeChainFinalCapture(node) || closure == nil || closure.final == nil {
		return false
	}
	if node.mode == "shadowsocks" {
		if closure.final["method"] == NativeStartLayerMethod {
			return closure.final["type"] == "shadowsocks" || closure.final["type"] == "routervpn-aes-xor"
		}
		// Other SS2022 ciphers retain their exact paired receiver declaration.
		// The separately validated source binds method, canonical key, node and
		// UoT version; it grants no generic HTTP datagram transport or AES layer.
		return closure.final["type"] == "shadowsocks" &&
			importedSS2022Method(predecessorText(closure.final, "method")) &&
			ValidateCapturedSSService(node.inputs.Files, predecessorText(node.profile, "node_proof_id")) == nil
	}
	return closure.final["type"] == "hysteria2" && closure.final["detour"] == nil
}
