package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// SelectedDNS is the immutable resolver selected by the common Tor policy.
// It grants neither a native route nor evidence that a DNS query succeeded.
type SelectedDNS struct {
	Mode       string `json:"mode"`
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name,omitempty"`
	Path       string `json:"path,omitempty"`
}

// PredecessorProofKind distinguishes authenticated Router control from the
// selected ordinary provider's public-address proof. Neither grants the other
// kind's private DNS, server-execution or protection authority.
type PredecessorProofKind string

const (
	RouterPredecessorProofKind   PredecessorProofKind = "router-private-agent"
	ExternalPredecessorProofKind PredecessorProofKind = "external-public-ip"
)

// EntryProof is emitted after the native owner authenticates its captured
// entry. It contains no credential and is separate from the Tor exit proof.
type EntryProof struct {
	EntryID     string               `json:"entry_id"`
	EntrySHA256 string               `json:"entry_sha256"`
	CheckedAt   time.Time            `json:"checked_at"`
	EntryKind   PredecessorProofKind `json:"entry_kind,omitempty"`
}

func (p *PredecessorProof) Kind() PredecessorProofKind {
	if p == nil {
		return ""
	}
	return RouterPredecessorProofKind
}

// NodeID exposes only the public identity used by the private server registry.
func (p *PredecessorProof) NodeID() string {
	if p == nil {
		return ""
	}
	return p.node
}

func capturedHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
}

func capturedDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func selectedDNSMetadata(profile, selected map[string]any) (SelectedDNS, error) {
	encoded, err := json.Marshal(selected)
	if err != nil {
		return SelectedDNS{}, err
	}
	numbers, err := profileObject(string(encoded), 16<<10)
	if err != nil {
		return SelectedDNS{}, err
	}
	port, err := profileInteger(numbers, "server_port", 0)
	if err != nil || port < 1 || port > 65535 {
		return SelectedDNS{}, errors.New("Tor selected resolver lost its exact port")
	}
	dns := SelectedDNS{Mode: profileString(profile, "dns_mode"), Transport: profileString(selected, "type"), Address: profileString(selected, "server"), Port: port, Path: profileString(selected, "path")}
	if tls, ok := selected["tls"].(map[string]any); ok {
		dns.ServerName = profileString(tls, "server_name")
	}
	return dns, nil
}
