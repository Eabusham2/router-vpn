package mobilemultihop

import "reflect"

// nodeChainFinalCapture retains the paired Local compiler's final choices.
// Server/Compare checks also bind the original source family; imported-member
// and candidate-target admission retain their separate guards. A mode name
// alone never authorizes a native closure.
func nodeChainFinalCapture(node *NodeProfile) bool {
	if node == nil {
		return false
	}
	switch node.mode {
	case "shadowsocks":
		return true
	case "hysteria2":
		layer := predecessorText(node.profile, "start_layer")
		return layer == "" || layer == "off" || layer == "aes-256-gcm" || layer == "aes-256-gcm+xor-whitening"
	default:
		return false
	}
}

// The caller first validates the sealed NodeProfile and reconstructs its
// original closure. Hysteria2 keeps the native TLS, CA, password and Salamander
// configuration intact. A selected final Start Layer must be the exact native
// owner already present in that node's captured single-node configuration.
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
	if closure.final["type"] != "hysteria2" {
		return false
	}
	layer := predecessorText(node.profile, "start_layer")
	if layer == "" || layer == "off" {
		return closure.final["detour"] == nil
	}
	outer := closure.nodes[NativeStartLayerTag]
	wantType := "shadowsocks"
	if layer == "aes-256-gcm+xor-whitening" {
		wantType = "routervpn-aes-xor"
	}
	if closure.final["detour"] != NativeStartLayerTag || closure.final["server"] != "127.0.0.1" ||
		outer == nil || outer["type"] != wantType || outer["method"] != NativeStartLayerMethod || outer["detour"] != nil {
		return false
	}
	// The graph composer will namespace the final and outer tags afterward.
	// Before that step, compare both complete native objects against the sealed
	// node configuration, including the original TLS/SNI, destination and keys.
	var captured map[string]any
	if exactJSON([]byte(node.config), &captured, 4<<20) != nil {
		return false
	}
	route, ok := captured["route"].(map[string]any)
	if !ok || route["final"] != closure.finalTag {
		return false
	}
	rows, ok := captured["outbounds"].([]any)
	if !ok {
		return false
	}
	var finalSource, outerSource map[string]any
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		switch row["tag"] {
		case closure.finalTag:
			finalSource = row
		case NativeStartLayerTag:
			outerSource = row
		}
	}
	return finalSource != nil && outerSource != nil && reflect.DeepEqual(closure.final, finalSource) && reflect.DeepEqual(outer, outerSource)
}
