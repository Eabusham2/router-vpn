package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

// PredecessorProofKind distinguishes authenticated Router control from the
// selected ordinary provider's public-address proof. Neither grants the other
// kind's private DNS, server-execution or protection authority.
type PredecessorProofKind string

const (
	RouterPredecessorProofKind   PredecessorProofKind = "router-private-agent"
	ExternalPredecessorProofKind PredecessorProofKind = "external-public-ip"
)

func (p *PredecessorProof) Kind() PredecessorProofKind {
	if p == nil {
		return ""
	}
	return RouterPredecessorProofKind
}

// ExternalPredecessorProof captures an ordinary external transport through the
// same compiler used by its standalone native path. It is deliberately a
// different type from PredecessorProof: a provider's public address cannot
// impersonate a Router /health identity or authorize Home AdGuard. Construction
// opens no socket and does not claim either live DNS proof or Tor composition.
type ExternalPredecessorProof struct {
	id, protocol, expected               string
	profile, source, config, fingerprint string
	policy                               *mobilemultihop.ExternalPolicy
	mtu                                  torMTUPreferences
}

func NewExternalPredecessorProof(profileJSON, configJSON string) (*ExternalPredecessorProof, error) {
	failure := errors.New("Tor external predecessor requires one exact ordinary profile and native transport")
	profile, err := profileObject(profileJSON, 4<<20)
	if err != nil || profile["node_kind"] != "external" || !profileIdentifier.MatchString(profileString(profile, "id")) {
		return nil, failure
	}
	for _, key := range []string{"node_proof_id", "router_api", "api_token"} {
		if value, exists := profile[key]; exists && value != "" && value != nil {
			return nil, errors.New("ordinary Tor predecessor cannot borrow private Router control identity")
		}
	}
	external, ok := profile["external"].(map[string]any)
	if !ok {
		return nil, failure
	}
	protocol, expected := profileString(external, "protocol"), profileString(external, "expected_public_ip")
	protocolField := strings.ReplaceAll(protocol, "-", "_")
	for key := range external {
		switch key {
		case protocolField, "protocol", "expected_public_ip", "response_probe", "start_layer", "server_peer", "openvpn_pairing", "openvpn_response_probes", "openvpn_start_layers":
		default:
			return nil, errors.New("ordinary Tor predecessor contains another transport owner")
		}
	}
	graph, err := profileObject(configJSON, 4<<20)
	if err != nil {
		return nil, failure
	}
	profileBytes, _ := json.Marshal(profile)
	configBytes, _ := json.Marshal(graph)
	selection := map[string]any{"schema": 1, "exit_id": profile["id"], "protocol": protocol,
		"expected_public_ip": expected, "profile": profile}
	if bootstrap, present := profile["dns_bootstrap"]; present {
		if bootstrap == nil {
			return nil, errors.New("ordinary Tor predecessor DNS bootstrap cannot be null")
		}
		selection["dns_bootstrap"] = bootstrap
	}
	capture, _ := json.Marshal(selection)
	policy, err := mobilemultihop.NewExternalPolicy(string(configBytes), string(capture))
	if err != nil {
		return nil, err
	}
	mtu, err := capturedTorMTUPreferences(profile)
	if err != nil {
		return nil, err
	}
	// Include both original transport input and compiler output. Native adoption
	// can reproduce this owner, not merely trust an ID, endpoint or public IP.
	identity, _ := json.Marshal([]string{"routervpn-tor-external-entry-v1", string(profileBytes), string(configBytes), policy.Config(), policy.SourceSHA256()})
	digest := sha256.Sum256(identity)
	return &ExternalPredecessorProof{id: profileString(profile, "id"), protocol: protocol, expected: expected,
		profile: string(profileBytes), source: string(configBytes), config: policy.Config(), policy: policy,
		fingerprint: hex.EncodeToString(digest[:]), mtu: mtu}, nil
}

func (p *ExternalPredecessorProof) Kind() PredecessorProofKind {
	if p == nil {
		return ""
	}
	return ExternalPredecessorProofKind
}

func (p *ExternalPredecessorProof) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}

func (p *ExternalPredecessorProof) ID() string               { return p.id }
func (p *ExternalPredecessorProof) Protocol() string         { return p.protocol }
func (p *ExternalPredecessorProof) ExpectedPublicIP() string { return p.expected }
func (p *ExternalPredecessorProof) Profile() string          { return p.profile }
func (p *ExternalPredecessorProof) SourceConfig() string     { return p.source }
func (p *ExternalPredecessorProof) Config() string           { return p.config }

// Prove uses only the encrypted lower already captured by the native caller.
// The expected address is the predecessor's, not the later dynamic Tor exit.
// Selected-DNS and Tor Project proofs remain separate mandatory operations.
func (p *ExternalPredecessorProof) Prove(parent context.Context, dial DialContext) error {
	if p == nil || p.policy == nil || parent == nil || dial == nil {
		return errors.New("Tor external predecessor has no captured proof owner")
	}
	return mobilemultihop.ProveExternalPublicIP(parent, func(ctx context.Context, tag, address string) (net.Conn, error) {
		if tag != mobilemultihop.ExternalFinalTag {
			return nil, errors.New("Tor external proof lost its captured predecessor route")
		}
		return dial(ctx, "tcp", address)
	}, mobilemultihop.ExternalFinalTag, p.expected)
}
