package nativecomposite

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

const SSServiceAsset = "routervpn-ss-service.json"
const SSServiceImage = "ghcr.io/sagernet/sing-box:v1.13.12"

var ssServiceNode = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateSSServiceCompanion verifies configured receiver authority against the
// original unmodified source bytes. An empty node permits ordinary source-only
// validation; a capability consumer must supply its captured paired node ID.
// This declaration never establishes live service readiness.
func ValidateSSServiceCompanion(originalData, data []byte, node string) error {
	bad := errors.New("paired SS service declaration lost its exact configured source or owner")
	if len(originalData) > 4<<20 || len(data) > 16384 {
		return bad
	}
	original, err := object(originalData)
	if err != nil {
		return bad
	}
	claim, err := object(data)
	if err != nil {
		return bad
	}
	if len(claim) != 9 || claim["schema"] != float64(1) || claim["configured_image"] != SSServiceImage || claim["uot_version"] != float64(2) {
		return bad
	}
	owner, ok := claim["node_id"].(string)
	if !ok || !ssServiceNode.MatchString(owner) || (node != "" && (!ssServiceNode.MatchString(node) || owner != node)) {
		return bad
	}
	rows, ok := original["outbounds"].([]any)
	if !ok {
		return bad
	}
	var source map[string]any
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return bad
		}
		if row["tag"] == "proxy" {
			if source != nil {
				return bad
			}
			source = row
		}
	}
	if len(source) != 6 || source["type"] != "shadowsocks" {
		return bad
	}
	endpoint, ok := source["server"].(string)
	if !ok || endpoint == "" || claim["endpoint"] != endpoint {
		return bad
	}
	port, ok := source["server_port"].(float64)
	if !ok || port < 1 || port > 65535 || port != float64(int(port)) || claim["port"] != port || claim["method"] != source["method"] {
		return bad
	}
	key, ok := source["password"].(string)
	method, methodOK := source["method"].(string)
	if !ok || !methodOK || !ssServiceCredentials(method, key) {
		return bad
	}
	sourceHash, keyHash := sha256.Sum256(originalData), sha256.Sum256([]byte(key))
	if claim["source_sha256"] != hex.EncodeToString(sourceHash[:]) || claim["key_sha256"] != hex.EncodeToString(keyHash[:]) {
		return bad
	}
	return nil
}

// The configured receiver keeps the exact SS2022 method and key text. AES
// permits identity chains; ChaCha permits one PSK. This does not authorize
// CONNECT datagrams without the independently captured UoT-v2 declaration.
func ssServiceCredentials(method, password string) bool {
	if password == "" || len(password) > 4096 {
		return false
	}
	size := 32
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm":
	case "2022-blake3-chacha20-poly1305":
		if strings.Contains(password, ":") {
			return false
		}
	default:
		return false
	}
	for _, encoded := range strings.Split(password, ":") {
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		valid := err == nil && len(decoded) == size && base64.StdEncoding.EncodeToString(decoded) == encoded
		clear(decoded)
		if !valid {
			return false
		}
	}
	return true
}
