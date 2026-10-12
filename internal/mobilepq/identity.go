package mobilepq

import (
	"crypto/sha256"
	"encoding/hex"
)

// IsMode names the independent Rosenpass negotiation, never ordinary WG/AWG.
func IsMode(mode string) bool { return mode == "wg-pq" || mode == "awg2-pq" }

// ClientIdentity is a bounded public fingerprint, not a credential. Reusing a
// KEM public identity for independent negotiations can rekey a live peer even
// when its WireGuard key is different. Do not scope this identity by mode/version.
func ClientIdentity(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	hash := sha256.Sum256(config.Public)
	return hex.EncodeToString(hash[:]), nil
}
