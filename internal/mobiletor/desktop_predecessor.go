package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// DesktopBridgePredecessorCapture carries one complete typed entry.
// The assets digest also binds the original mode/Start Layer files retained by
// the desktop controller. It is not evidence that any network path has run.
type DesktopBridgePredecessorCapture struct {
	Schema       int                  `json:"schema"`
	EntryMode    string               `json:"entry_mode"`
	Profile      json.RawMessage      `json:"profile"`
	Config       json.RawMessage      `json:"config"`
	AssetsSHA256 string               `json:"assets_sha256"`
	EntryKind    PredecessorProofKind `json:"entry_kind,omitempty"`
	SourceConfig json.RawMessage      `json:"source_config,omitempty"`
}

// DesktopPredecessor retains only immutable validated source. Its proof owns
// the exact private Router API credentials; no getter exposes a mutable map.
type DesktopPredecessor struct {
	mode, profile, config, assets, tag string
	kind                               PredecessorProofKind
	proof                              *PredecessorProof
	external                           *ExternalPredecessorProof
}

// DesktopBridgeEntryProof preserves the desktop API for the shared entry receipt.
type DesktopBridgeEntryProof = EntryProof

func (m DesktopBridgeMetadata) ValidEntryProof(proof *DesktopBridgeEntryProof, started, now time.Time) bool {
	if m.EntryID == "" {
		return proof == nil && m.EntryProofKind == ""
	}
	if proof == nil {
		return false
	}
	expected, actual := m.EntryProofKind, proof.EntryKind
	// Schema-1 Router receipts predate the typed ordinary-provider authority.
	// Only that existing private proof may use the omitted kind.
	if expected == "" {
		expected = RouterPredecessorProofKind
	}
	if actual == "" {
		actual = RouterPredecessorProofKind
	}
	return (expected == RouterPredecessorProofKind || expected == ExternalPredecessorProofKind) && actual == expected && proof.EntryID == m.EntryID && proof.EntrySHA256 == m.EntrySHA256 &&
		!proof.CheckedAt.IsZero() && !proof.CheckedAt.Before(started.Add(-time.Second)) && !proof.CheckedAt.After(now.Add(time.Second))
}

func NewDesktopPredecessor(mode, profileJSON, configJSON, assetsSHA256 string) (*DesktopPredecessor, error) {
	if !desktopHex(assetsSHA256, 32) {
		return nil, errors.New("desktop Tor entry requires the captured mode and Start Layer asset digest")
	}
	if err := mobilemultihop.ValidateNodePredecessor(mode, profileJSON, configJSON); err != nil {
		return nil, err
	}
	profile, err := profileObject(profileJSON, 256<<10)
	if err != nil {
		return nil, err
	}
	graph, err := profileObject(configJSON, 4<<20)
	if err != nil {
		return nil, err
	}
	// Canonical copies keep the same identity when embedded as JSON objects in
	// the launch capture and reconstructed by the independent native process.
	profileBytes, _ := json.Marshal(profile)
	configBytes, _ := json.Marshal(graph)
	proof, err := NewPredecessorProof(string(profileBytes))
	if err != nil {
		return nil, err
	}
	return &DesktopPredecessor{mode: mode, profile: string(profileBytes), config: string(configBytes), kind: RouterPredecessorProofKind,
		assets: assetsSHA256, tag: profileString(graph["route"].(map[string]any), "final"), proof: proof}, nil
}

func (p *DesktopPredecessor) Mode() string { return p.mode }
func (p *DesktopPredecessor) ID() string {
	if p.IsRouter() {
		return p.proof.id
	}
	if p.IsExternal() {
		return p.external.id
	}
	return ""
}
func (p *DesktopPredecessor) Profile() string          { return p.profile }
func (p *DesktopPredecessor) Config() string           { return p.config }
func (p *DesktopPredecessor) AssetsSHA256() string     { return p.assets }
func (p *DesktopPredecessor) Tag() string              { return p.tag }
func (p *DesktopPredecessor) Proof() *PredecessorProof { return p.proof }

// IsRouter grants only the authority of a validated private Router capture.
// A future external predecessor cannot inherit it from a generic proof pointer.
func (p *DesktopPredecessor) IsRouter() bool {
	return p != nil && p.kind == RouterPredecessorProofKind && p.proof != nil && p.external == nil && p.proof.Kind() == RouterPredecessorProofKind
}
func (p *DesktopPredecessor) IsExternal() bool {
	return p != nil && p.kind == ExternalPredecessorProofKind && p.external != nil && p.proof == nil && p.external.Kind() == ExternalPredecessorProofKind
}
func (p *DesktopPredecessor) entryProof() capturedTorEntryProof {
	if p.IsRouter() {
		return p.proof
	}
	if p.IsExternal() {
		return p.external
	}
	return nil
}
func (p *DesktopPredecessor) Fingerprint() string {
	if proof := p.entryProof(); proof != nil {
		return proof.Fingerprint()
	}
	return ""
}
func (p *DesktopPredecessor) Kind() PredecessorProofKind {
	if p.IsRouter() {
		return RouterPredecessorProofKind
	}
	if p.IsExternal() {
		return ExternalPredecessorProofKind
	}
	return ""
}
func (p *DesktopPredecessor) Prove(ctx context.Context, dial DialContext) error {
	if p.IsRouter() {
		return p.proof.Prove(ctx, dial)
	}
	if p.IsExternal() {
		return p.external.Prove(ctx, dial)
	}
	return errors.New("desktop Tor predecessor has no exact typed proof owner")
}
func (p *DesktopPredecessor) Capture() DesktopBridgePredecessorCapture {
	capture := DesktopBridgePredecessorCapture{Schema: 1, EntryMode: p.mode, Profile: json.RawMessage(p.profile),
		Config: json.RawMessage(p.config), AssetsSHA256: p.assets}
	if p.IsExternal() {
		capture.Schema, capture.EntryKind, capture.SourceConfig = 2, ExternalPredecessorProofKind, json.RawMessage(p.external.source)
	}
	return capture
}

func decodeDesktopPredecessor(raw json.RawMessage) (*DesktopPredecessor, error) {
	object, err := profileObject(string(raw), 8<<20)
	if err != nil {
		return nil, errors.New("desktop Tor entry capture is incomplete or contains unowned fields")
	}
	for _, key := range []string{"schema", "entry_mode", "profile", "config", "assets_sha256"} {
		if object[key] == nil {
			return nil, errors.New("desktop Tor entry capture requires all private owners")
		}
	}
	var captured DesktopBridgePredecessorCapture
	if json.Unmarshal(raw, &captured) != nil {
		return nil, errors.New("desktop Tor entry capture schema or field type is invalid")
	}
	switch captured.Schema {
	case 1:
		if len(object) != 5 {
			return nil, errors.New("Router entry capture contains another proof authority")
		}
		return NewDesktopPredecessor(captured.EntryMode, string(captured.Profile), string(captured.Config), captured.AssetsSHA256)
	case 2:
		if len(object) != 7 || captured.EntryKind != ExternalPredecessorProofKind || object["source_config"] == nil {
			return nil, errors.New("ordinary Tor entry capture requires its exact source and public-address authority")
		}
		entry, err := NewDesktopExternalPredecessor(captured.EntryMode, string(captured.Profile), string(captured.SourceConfig), captured.AssetsSHA256)
		if err != nil {
			return nil, err
		}
		config, err := profileObject(string(captured.Config), 4<<20)
		if err != nil {
			return nil, err
		}
		canonical, _ := json.Marshal(config)
		if string(canonical) != entry.config {
			return nil, errors.New("ordinary Tor entry config differs from its recompiled source")
		}
		return entry, nil
	default:
		return nil, errors.New("desktop Tor entry capture schema is invalid")
	}
}

// NewDesktopBridgePolicyWithPredecessor composes a saved Local selection using
// the complete Router graph. Compare and Server are never silently rewritten.
func NewDesktopBridgePolicyWithPredecessor(source, sessionID, isolationSecret, targetOS string, predecessor *DesktopPredecessor) (*DesktopBridgePolicy, error) {
	if predecessor == nil || predecessor.entryProof() == nil {
		return nil, errors.New("desktop Tor Local composition requires its captured typed entry")
	}
	return newDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS, predecessor)
}

func desktopPredecessorGraph(profile map[string]any, sessionID string, predecessor *DesktopPredecessor) (map[string]any, map[string]any, map[string]any, error) {
	if profileString(profile, "multihop_entry_mode") != predecessor.mode {
		return nil, nil, nil, errors.New("desktop Tor entry graph belongs to another saved mode")
	}
	// The shared compiler supplies only this desktop graph's TUN, DNS and
	// typed predecessor. Its embedded Tor leaf is replaced with the exact
	// isolated standalone SOCKS owner below. The immutable desktop metadata
	// and original source retain the requested padding; its native child lease
	// owns that policy, independently of any predecessor cover service.
	lowered := make(map[string]any, len(profile))
	for key, value := range profile {
		lowered[key] = value
	}
	if lowered["daita_enabled"] == true {
		lowered["daita_enabled"] = false
	}
	normalized, err := json.Marshal(lowered)
	if err != nil {
		return nil, nil, nil, err
	}
	compiled, err := compileProfileWithEntryProof(string(normalized), sessionID, predecessor.config, predecessor.profile, true, predecessor.entryProof())
	if err != nil {
		return nil, nil, nil, err
	}
	graph, err := profileObject(compiled, 4<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	tun, _, _, err := torMTUInterface(graph)
	if err != nil {
		return nil, nil, nil, err
	}
	var selected map[string]any
	for _, row := range graph["dns"].(map[string]any)["servers"].([]any) {
		server := row.(map[string]any)
		if server["tag"] == profileDNS {
			if selected != nil {
				return nil, nil, nil, errors.New("desktop Tor selected resolver is ambiguous")
			}
			selected = server
		}
	}
	if selected == nil {
		return nil, nil, nil, errors.New("desktop Tor Local graph lost its selected resolver")
	}
	return graph, tun, selected, nil
}
