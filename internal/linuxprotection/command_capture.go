package linuxprotection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// NodeCommandCaptureSHA256 binds the authenticated inherited channel to the
// exact native command identity before it opens private node inputs. Both
// sides must check the same values against the sealed compiled policy later.
// Parent profile selection and request ownership stay in its own journal.
func NodeCommandCaptureSHA256(session, source, config string) (string, error) {
	if !lowerHex(session, 32) || !lowerHex(source, 64) || !lowerHex(config, 64) {
		return "", errors.New("Linux Node command has no complete captured identity")
	}
	value := struct {
		Kind         string `json:"kind"`
		SessionID    string `json:"session_id"`
		SourceSHA256 string `json:"source_sha256"`
		ConfigSHA256 string `json:"config_sha256"`
	}{"routervpn-linux-node-command-v1", session, source, config}
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
