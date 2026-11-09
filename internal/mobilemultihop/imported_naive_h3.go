package mobilemultihop

// These original entry protocols have their own datagram carrier. OpenVPN's
// captured TCP/UDP distinction is preserved by its endpoint compiler; either
// tunnel carries the final QUIC payload. HTTP CONNECT has no such authority.
func importedNaiveH3Entry(protocol string) bool {
	switch protocol {
	case "socks5", "shadowsocks", "hysteria2", "wireguard", "amneziawg", "openvpn":
		return true
	default:
		return false
	}
}

func importedNaiveH3DNS(graph, final map[string]any) error {
	return importedNaiveDNS(graph, final, "naive-h3", true)
}
