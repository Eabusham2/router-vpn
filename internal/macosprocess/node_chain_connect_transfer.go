package macosprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const nodeChainCONNECTTransferDomain = "routervpn-macos-node-chain-connect-transfer-v1\x00"

// NodeChainCONNECTTransferSHA256 binds typed CONNECT child readiness to the
// complete original capture. Selection must come from the retained Capture
// after Current; its digest does not replace native liveness or PF ownership.
func NodeChainCONNECTTransferSHA256(selection Selection) (string, error) {
	if selection.Family != NodeChainCONNECTFamily || !selection.valid() {
		return "", errors.New("typed CONNECT native readiness requires its original complete capture")
	}
	// Selection contains only public identities. Parent and child retain the
	// private credentials and exact source bytes in the inherited workspace.
	raw, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(nodeChainCONNECTTransferDomain))
	_, _ = digest.Write(raw)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
