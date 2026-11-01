package mobilemultihop

// DesktopLinuxNodePhysicalGraphSupported is the retained Linux host's bounded
// composition. Its three selections use the exact captured Shadowsocks source:
// Off, authenticated SS2022 AES, or that AES ciphertext with the
// native owned whitening adapter. Broader native families have separate gates.
func DesktopLinuxNodePhysicalGraphSupported(mode, startLayer string) bool {
	if mode != "shadowsocks" {
		return false
	}
	return startLayer == "" || startLayer == "off" || startLayer == "aes-256-gcm" || startLayer == "aes-256-gcm+xor-whitening"
}

// DesktopNodePhysicalGraphSupported identifies the graph families admitted by
// the native owned-socket composition. It is a capability gate, not a profile
// constructor: callers still validate the sealed policy and complete Box.
// Broader raw modes remain in the product catalog while their native lower
// composition is proved; they must never be relabeled as one of these graphs.
func DesktopNodePhysicalGraphSupported(mode, startLayer string) bool {
	if startLayer != "" && startLayer != "off" && startLayer != "aes-256-gcm" && startLayer != "aes-256-gcm+xor-whitening" {
		return false
	}
	switch mode {
	case "wg-pq", "awg2-pq":
		return true
	case "wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "split", "max", "ss-v2ray":
		return true
	default:
		return false
	}
}
