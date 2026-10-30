package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// NodeLaunchInputLimit includes both bounded base64 asset maps, the complete
// captured profile, DNS bootstrap and the JSON string escaping of those inputs.
// The envelope is private material, never a log record or public receipt.
const NodeLaunchInputLimit = 40 << 20

type nodeProfileInputs struct {
	Mode         string `json:"mode"`
	Files        string `json:"files"`
	ProfileJSON  string `json:"profile_json"`
	Start        string `json:"start"`
	DNSBootstrap string `json:"dns_bootstrap"`
}

type nodeLaunchInputRecord struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`
	nodeProfileInputs
	SourceSHA256   string `json:"source_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	MetadataSHA256 string `json:"metadata_sha256"`
}

var nodeLaunchInputError = errors.New("native node launch requires its complete canonical private constructor input")

func (p *NodeProfile) nodeDesktopCaptureSeal() (string, error) {
	if p == nil || p.profile == nil || !NodeProfileMode(p.mode) || p.inputs.Mode != p.mode ||
		p.config == "" || len(p.config) > 4<<20 || p.metadata == "" || len(p.metadata) > 64<<10 ||
		!proofID.MatchString(p.source) || p.inputs.Files == "" || len(p.inputs.Files) > 16<<20 ||
		p.inputs.ProfileJSON == "" || len(p.inputs.ProfileJSON) > 256<<10 ||
		len(p.inputs.Start) > 16<<20 || len(p.inputs.DNSBootstrap) > 16384 {
		return "", nodeLaunchInputError
	}
	inputs, err := json.Marshal([]string{"routervpn-node-profile-v1", p.inputs.Mode, p.inputs.Files,
		p.inputs.ProfileJSON, p.inputs.Start, p.inputs.DNSBootstrap})
	if err != nil || externalDigest(inputs) != p.source {
		clear(inputs)
		return "", nodeLaunchInputError
	}
	clear(inputs)
	sealed, err := json.Marshal(struct {
		Domain   string            `json:"domain"`
		Source   string            `json:"source"`
		Config   string            `json:"config"`
		Metadata string            `json:"metadata"`
		Inputs   nodeProfileInputs `json:"inputs"`
		Profile  map[string]any    `json:"profile"`
	}{"routervpn-node-desktop-capture-v1", p.source, p.config, p.metadata, p.inputs, p.profile})
	if err != nil || len(sealed) > NodeLaunchInputLimit+(8<<20) {
		clear(sealed)
		return "", nodeLaunchInputError
	}
	digest := externalDigest(sealed)
	clear(sealed)
	return digest, nil
}

func (p *NodeProfile) sealNodeDesktopCapture() error {
	seal, err := p.nodeDesktopCaptureSeal()
	if err != nil {
		return err
	}
	p.desktopSeal = seal
	return nil
}

func (p *NodeProfile) validateNodeDesktopCapture() error {
	seal, err := p.nodeDesktopCaptureSeal()
	if err != nil || p.desktopSeal == "" || p.desktopSeal != seal {
		return nodeLaunchInputError
	}
	return nil
}

// LaunchInput exports only the exact immutable constructor input retained by
// NewNodeProfile. A native child must open it through its owned private files,
// recompile it with ParseNodeLaunchInput and compare the original and desktop
// graph identities before constructing a native owner. This value by itself
// cannot authorize an OS interface, firewall rule or network socket.
func (p *NodeProfile) LaunchInput() (string, error) {
	if p.validateNodeDesktopCapture() != nil {
		return "", nodeLaunchInputError
	}
	record := nodeLaunchInputRecord{
		Schema: 1, Kind: "routervpn-node-launch-input", nodeProfileInputs: p.inputs,
		SourceSHA256: p.source, ConfigSHA256: externalDigest([]byte(p.config)),
		MetadataSHA256: externalDigest([]byte(p.metadata)),
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > NodeLaunchInputLimit {
		clear(raw)
		return "", nodeLaunchInputError
	}
	result := string(raw)
	clear(raw)
	return result, nil
}

// ParseNodeLaunchInput accepts one bounded canonical envelope and reruns the
// original compiler. Hash labels or a copied compiled graph cannot replace its
// complete selected profile, credentials, Start Layers or DNS bootstrap input.
// Error messages deliberately exclude the private input and compiler contents.
func ParseNodeLaunchInput(raw string) (*NodeProfile, error) {
	var record nodeLaunchInputRecord
	if exactJSON([]byte(raw), &record, NodeLaunchInputLimit) != nil || record.Schema != 1 ||
		record.Kind != "routervpn-node-launch-input" || !proofID.MatchString(record.SourceSHA256) ||
		!proofID.MatchString(record.ConfigSHA256) || !proofID.MatchString(record.MetadataSHA256) {
		return nil, nodeLaunchInputError
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != raw {
		clear(canonical)
		return nil, nodeLaunchInputError
	}
	clear(canonical)
	profile, err := NewNodeProfile(record.Mode, record.Files, record.ProfileJSON, record.Start, record.DNSBootstrap)
	if err != nil || profile == nil || profile.source != record.SourceSHA256 || externalDigest([]byte(profile.config)) != record.ConfigSHA256 ||
		externalDigest([]byte(profile.metadata)) != record.MetadataSHA256 || profile.validateNodeDesktopCapture() != nil {
		return nil, nodeLaunchInputError
	}
	return profile, nil
}
