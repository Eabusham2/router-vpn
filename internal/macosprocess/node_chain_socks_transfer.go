package macosprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const nodeChainSOCKSTransferDomain = "routervpn-macos-node-chain-socks-transfer-v1\x00"

// NodeChainSOCKSTransferSHA256 binds typed SOCKS child readiness to the full original
// authenticated capture. Callers must obtain Selection from their retained
// Capture after Current and preserve that owner through use of this digest.
// A matching digest alone is not a native admission, liveness or PF proof.
func NodeChainSOCKSTransferSHA256(selection Selection) (string, error) {
	if selection.Family != NodeChainSOCKSFamily || !selection.valid() {
		return "", errors.New("typed SOCKS native readiness requires its original complete capture")
	}
	// Selection is a concrete struct of public immutable identities. Its JSON
	// field order and exact scalar encodings are shared by parent and child.
	raw, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(nodeChainSOCKSTransferDomain))
	_, _ = digest.Write(raw)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
