package mobilemultihop

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
	case "wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "split", "max":
		return true
	default:
		return false
	}
}
