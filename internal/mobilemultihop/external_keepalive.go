package mobilemultihop

// An omitted keepalive and an explicit zero both disable keepalives. Every
// nonzero value is a captured peer setting, never an engine default to invent.
func externalCapturedKeepalive(peer, source map[string]any) bool {
	value := func(object map[string]any) (float64, bool) {
		raw, exists := object["persistent_keepalive_interval"]
		if !exists {
			return 0, true
		}
		n, ok := raw.(float64)
		return n, ok && n >= 0 && n <= 65535 && float64(int(n)) == n
	}
	want, valid := value(source)
	actual, nativeValid := value(peer)
	return valid && nativeValid && want == actual
}
