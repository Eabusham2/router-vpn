package macosprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const nodeChainExecutionTransferDomain = "routervpn-macos-node-chain-execution-transfer-v1\x00"

// NodeChainExecutionTransferSHA256 binds Server/Compare child readiness to the
// original process capture and its exact private execution preparation. The
// retained Capture must still be Current; this digest cannot replace native
// process liveness, original PF ownership or the proved execution selection.
func NodeChainExecutionTransferSHA256(selection Selection) (string, error) {
	if selection.Family != NodeChainExecutionFamily || !selection.valid() {
		return "", errors.New("ordered execution readiness requires its original complete capture")
	}
	raw, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(nodeChainExecutionTransferDomain))
	_, _ = digest.Write(raw)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
