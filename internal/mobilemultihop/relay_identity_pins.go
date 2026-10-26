package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/multihoprelay"
)

func validateMetadataIdentityPins(raw string, meta Metadata) error {
	bad := errors.New("invalid captured server identity pins")
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return bad
	}
	for key, value := range map[string]string{
		"expected_packet_public_key":  meta.ExpectedPacketPublicKey,
		"expected_pq_client_identity": meta.ExpectedPQClientIdentity,
	} {
		// Omission is the first-connection contract. Explicit null/empty values
		// must not erase the identity constraints of a captured restoration.
		if _, present := fields[key]; present && value == "" {
			return bad
		}
	}
	if multihoprelay.ValidateIdentityPins(meta.ExitMode, meta.ExpectedPacketPublicKey, meta.ExpectedPQClientIdentity) != nil {
		return bad
	}
	return nil
}

// Called while preparing an unpublished controller or holding leaseMu. Pins
// belong to its exact request and are independent from its local packet/KEM
// owner; selected labels alone cannot authorize a second roaming/rekey owner.
func (c *Controller) validateServerIdentityPins(required bool) error {
	bad := errors.New("captured server identity pins are missing, changed or not independently owned")
	q := c.proposal
	if q != c.expected.Request || multihoprelay.ValidateIdentityPins(q.ExitMode, q.ExpectedPacketPublicKey, q.ExpectedPQClientIdentity) != nil {
		return bad
	}
	packet := c.external == nil && (multihoprelay.PacketMode(q.ExitMode) || MAXMode(q.ExitMode))
	if !packet {
		if q.ExpectedPacketPublicKey != "" || q.ExpectedPQClientIdentity != "" {
			return bad
		}
		return nil
	}
	if required && q.ExpectedPacketPublicKey == "" || q.ExpectedPacketPublicKey != "" && q.ExpectedPacketPublicKey == c.localPublicKey {
		return bad
	}
	if q.ExpectedPQClientIdentity != "" && q.ExpectedPQClientIdentity == c.localPQIdentity {
		return bad
	}
	return nil
}

// ServerIdentityPinsJSON captures public identity constraints for a later
// reconstruction of this same proved connection. It performs no discovery and
// does not turn the snapshot into proof for a new provider or network owner.
// The host retains its complete path/source identity alongside these fields.
func (c *Controller) ServerIdentityPinsJSON() (string, error) {
	bad := errors.New("server identity capture requires the current healthy selected owner")
	if !c.Healthy() {
		return "", bad
	}
	c.mu.Lock()
	outcome := c.progress.Execution
	c.mu.Unlock()
	if outcome == "local" {
		if !c.Healthy() || c.requireValid() != nil {
			return "", bad
		}
		return "{}", nil
	}
	if outcome != "server" {
		return "", bad
	}
	c.leaseMu.Lock()
	if !c.ownsLease || !c.leaseFresh() || c.validateServerIdentityPins(true) != nil {
		c.leaseMu.Unlock()
		return "", bad
	}
	pins := struct {
		Packet string `json:"expected_packet_public_key,omitempty"`
		PQ     string `json:"expected_pq_client_identity,omitempty"`
	}{c.proposal.ExpectedPacketPublicKey, c.proposal.ExpectedPQClientIdentity}
	c.leaseMu.Unlock()
	// Native callbacks and lease release can run while the request is copied.
	// Do not hold either state lock while invoking the native health readback.
	if !c.Healthy() || c.requireValid() != nil {
		return "", bad
	}
	raw, err := json.Marshal(pins)
	if err != nil {
		return "", bad
	}
	return string(raw), nil
}
