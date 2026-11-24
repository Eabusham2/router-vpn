package hopmeasure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Request and reply have distinct domains. The bearer secret never travels
// over the candidate stream, and echoing the request cannot prove a reply.
const CandidateChallengePath = "/api/benchmark/candidate-response"

func ValidCandidateNonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	b, err := hex.DecodeString(nonce)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == nonce
}

func CandidateChallengeMAC(token, node, nonce string, reply bool) string {
	phase := "request"
	if reply {
		phase = "response"
	}
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("routervpn-private-candidate-response-v1\n" + phase + "\n" + node + "\n" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}
