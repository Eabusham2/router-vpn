package mobiletor

import (
	"encoding/json"
	"errors"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// DesktopBridgePredecessorCapture carries the complete private Router entry.
// The assets digest also binds the original mode/Start Layer files retained by
// the desktop controller. It is not evidence that any network path has run.
type DesktopBridgePredecessorCapture struct {
	Schema       int             `json:"schema"`
	EntryMode    string          `json:"entry_mode"`
	Profile      json.RawMessage `json:"profile"`
	Config       json.RawMessage `json:"config"`
	AssetsSHA256 string          `json:"assets_sha256"`
}

// DesktopPredecessor retains only immutable validated source. Its proof owns
// the exact private Router API credentials; no getter exposes a mutable map.
type DesktopPredecessor struct {
	mode, profile, config, assets, tag string
	kind                               PredecessorProofKind
	proof                              *PredecessorProof
}

// DesktopBridgeEntryProof is emitted only after the native owner authenticates
// the captured private Router API through its retained encrypted entry. It
// contains no credential and is separate from the Tor Project exit proof.
type DesktopBridgeEntryProof struct {
	EntryID     string    `json:"entry_id"`
	EntrySHA256 string    `json:"entry_sha256"`
	CheckedAt   time.Time `json:"checked_at"`
}

func (m DesktopBridgeMetadata) ValidEntryProof(proof *DesktopBridgeEntryProof, started, now time.Time) bool {
	if m.EntryID == "" {
		return proof == nil
	}
	return proof != nil && proof.EntryID == m.EntryID && proof.EntrySHA256 == m.EntrySHA256 &&
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

func (p *DesktopPredecessor) Mode() string             { return p.mode }
func (p *DesktopPredecessor) ID() string               { return p.proof.id }
func (p *DesktopPredecessor) Profile() string          { return p.profile }
func (p *DesktopPredecessor) Config() string           { return p.config }
func (p *DesktopPredecessor) AssetsSHA256() string     { return p.assets }
func (p *DesktopPredecessor) Tag() string              { return p.tag }
func (p *DesktopPredecessor) Proof() *PredecessorProof { return p.proof }

// IsRouter grants only the authority of a validated private Router capture.
// A future external predecessor cannot inherit it from a generic proof pointer.
func (p *DesktopPredecessor) IsRouter() bool {
	return p != nil && p.kind == RouterPredecessorProofKind && p.proof != nil && p.proof.Kind() == RouterPredecessorProofKind
}
func (p *DesktopPredecessor) Capture() DesktopBridgePredecessorCapture {
	return DesktopBridgePredecessorCapture{Schema: 1, EntryMode: p.mode, Profile: json.RawMessage(p.profile),
		Config: json.RawMessage(p.config), AssetsSHA256: p.assets}
}

func decodeDesktopPredecessor(raw json.RawMessage) (*DesktopPredecessor, error) {
	object, err := profileObject(string(raw), 8<<20)
	if err != nil || len(object) != 5 {
		return nil, errors.New("desktop Tor entry capture is incomplete or contains unowned fields")
	}
	for _, key := range []string{"schema", "entry_mode", "profile", "config", "assets_sha256"} {
		if object[key] == nil {
			return nil, errors.New("desktop Tor entry capture requires all private owners")
		}
	}
	var captured DesktopBridgePredecessorCapture
	if json.Unmarshal(raw, &captured) != nil || captured.Schema != 1 {
		return nil, errors.New("desktop Tor entry capture schema or field type is invalid")
	}
	return NewDesktopPredecessor(captured.EntryMode, string(captured.Profile), string(captured.Config), captured.AssetsSHA256)
}

// NewDesktopBridgePolicyWithPredecessor composes a saved Local selection using
// the complete Router graph. Compare and Server are never silently rewritten.
func NewDesktopBridgePolicyWithPredecessor(source, sessionID, isolationSecret, targetOS string, predecessor *DesktopPredecessor) (*DesktopBridgePolicy, error) {
	if predecessor == nil {
		return nil, errors.New("desktop Tor Local composition requires its captured Router entry")
	}
	return newDesktopBridgePolicy(source, sessionID, isolationSecret, targetOS, predecessor)
}

func desktopPredecessorGraph(profile map[string]any, sessionID string, predecessor *DesktopPredecessor) (map[string]any, map[string]any, map[string]any, error) {
	if profileString(profile, "multihop_entry_mode") != predecessor.mode {
		return nil, nil, nil, errors.New("desktop Tor entry graph belongs to another saved mode")
	}
	normalized, err := json.Marshal(profile)
	if err != nil {
		return nil, nil, nil, err
	}
	compiled, err := CompileProfileWithPredecessor(string(normalized), sessionID, predecessor.config, predecessor.profile)
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
