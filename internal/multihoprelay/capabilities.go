package multihoprelay

import (
	"encoding/base64"
	"errors"
	"net/http"
)

const MaxPairedExits = 64
const MaxControlResponseBytes = 8 << 10

// Capabilities contain only public fingerprints, never registry key material.
// 64 maximally named PQ exits with Start Layers exceed the old 8 KiB limit.
const MaxCapabilitiesBytes = 64 << 10

// LeaseResponseLimit is used only on the authenticated private lease endpoint.
// Larger discovery catalogs do not enlarge proof, probe or mutation responses.
func LeaseResponseLimit(method string) int {
	if method == http.MethodGet {
		return MaxCapabilitiesBytes
	}
	return MaxControlResponseBytes
}

type Capability struct {
	ID         string `json:"exit_id"`
	Mode       string `json:"exit_mode"`
	NodeID     string `json:"exit_node_id"`
	PublicKey  string `json:"client_public_key,omitempty"`
	PQIdentity string `json:"pq_client_identity,omitempty"`
	Layer      string `json:"exit_start_layer,omitempty"`
}

type Capabilities struct {
	NodeID    string       `json:"node_id"`
	Execution string       `json:"execution"`
	Exits     []Capability `json:"exits"`
}

// Validate checks public shape/identity, not possession of the private keys.
// The caller still needs its authenticated tunnel, exact selected exit match,
// independent client keys, and the lease plus exit-node proof before Connected.
func (c Capabilities) Validate(expectedNode string) error {
	bad := errors.New("unproved, oversized or ambiguous relay capability catalog")
	if !proofID.MatchString(expectedNode) || c.NodeID != expectedNode || c.Execution != "server" || c.Exits == nil || len(c.Exits) > MaxPairedExits {
		return bad
	}
	seen := make(map[string]bool, len(c.Exits))
	for _, e := range c.Exits {
		if !ident.MatchString(e.ID) || !ident.MatchString(e.Mode) || !proofID.MatchString(e.NodeID) || e.NodeID == expectedNode || e.Layer != "" && !ValidLayerMode(e.Layer) {
			return bad
		}
		identity := e.ID + "/" + e.Mode + "/" + e.Layer
		if seen[identity] {
			return bad
		}
		seen[identity] = true
		if e.PublicKey != "" {
			key, err := base64.StdEncoding.Strict().DecodeString(e.PublicKey)
			if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != e.PublicKey {
				return bad
			}
		}
		if e.PQIdentity != "" && !proofID.MatchString(e.PQIdentity) {
			return bad
		}
	}
	return nil
}
