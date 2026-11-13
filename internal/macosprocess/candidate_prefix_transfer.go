package macosprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const candidatePrefixTransferDomain = "routervpn-macos-candidate-prefix-transfer-v1\x00"

// CandidatePrefixTransferSHA256 binds private prefix readiness to the complete
// original process capture, including the distinct prefix-only source family.
// Callers must retain that Capture and check Current through every use. This
// identity is neither ordinary connected proof nor evidence of native cleanup.
func CandidatePrefixTransferSHA256(selection Selection) (string, error) {
	if selection.Family != CandidatePrefixFamily || !selection.valid() {
		return "", errors.New("candidate prefix readiness requires its original complete capture")
	}
	raw, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(candidatePrefixTransferDomain))
	_, _ = digest.Write(raw)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
