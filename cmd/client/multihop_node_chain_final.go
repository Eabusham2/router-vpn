package main

// This is the desktop producer's shape check. The sealed shared compiler still
// reconstructs and validates the complete original protocol, policy and owner.
// Imported-middle paths retain their separate SS2022-only final guard.
func desktopNodeChainFinalSupported(mode, startLayer string) bool {
	return mode == "shadowsocks" || mode == "hysteria2" && (startLayer == "" || startLayer == "off")
}
