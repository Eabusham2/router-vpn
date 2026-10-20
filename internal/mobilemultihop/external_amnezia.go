package mobilemultihop

import (
	"errors"
	"reflect"
)

// The native endpoint has already passed AmneziaRuntimeConfig. Bind every
// imported obfuscation parameter and optional keepalive to the captured node;
// a valid but different Fast/Strong policy cannot replace the selected one.
func externalCapturedAmnezia(endpoint, source map[string]any) error {
	bad := errors.New("imported AmneziaWG differs from its exact captured parameters or keepalive")
	for key := range source {
		switch key {
		case "private_key", "addresses", "peer_public_key", "preshared_key", "endpoint", "allowed_ips", "dns", "mtu", "persistent_keepalive_interval", "parameters":
		default:
			return bad
		}
	}
	if endpoint["type"] != AmneziaType || !reflect.DeepEqual(endpoint["amnezia"], source["parameters"]) {
		return bad
	}
	peers, ok := endpoint["peers"].([]any)
	if !ok || len(peers) != 1 {
		return bad
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return bad
	}
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
	if !valid || !nativeValid || want != actual {
		return bad
	}
	return nil
}
