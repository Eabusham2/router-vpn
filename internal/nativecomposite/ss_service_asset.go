package nativecomposite

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
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
	if len(source) != 6 || source["type"] != "shadowsocks" || source["method"] != "2022-blake3-aes-256-gcm" {
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
	if !ok || key == "" {
		return bad
	}
	sourceHash, keyHash := sha256.Sum256(originalData), sha256.Sum256([]byte(key))
	if claim["source_sha256"] != hex.EncodeToString(sourceHash[:]) || claim["key_sha256"] != hex.EncodeToString(keyHash[:]) {
		return bad
	}
	return nil
}
