package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// ImportedLaunchInputLimit includes both original captured transports, bounded
// private final assets/Start Layers and JSON string escaping. The envelope is
// private material; it is never a public receipt, diagnostic or socket grant.
const ImportedLaunchInputLimit = 96 << 20

type importedEntryInputs struct {
	EntryConfig  string `json:"entry_config"`
	EntryCapture string `json:"entry_capture"`
	ExitMode     string `json:"exit_mode"`
	ExitFiles    string `json:"exit_files"`
	ExitProfile  string `json:"exit_profile"`
	ExitStart    string `json:"exit_start"`
	DNSBootstrap string `json:"dns_bootstrap"`
}

type importedLaunchInputRecord struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`

	importedEntryInputs
	SourceSHA256   string `json:"source_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
	MetadataSHA256 string `json:"metadata_sha256"`
}

var importedLaunchInputError = errors.New("native imported launch requires its complete canonical private constructor input")

func (c *Controller) importedDesktopCaptureSeal() (string, error) {
	if c == nil || c.imported == nil || c.generation.Load() != 1 || c.meta.EntryKind != "external" || c.meta.Execution != "local" {
		return "", importedLaunchInputError
	}
	p := c.imported
	if c.config == "" || len(c.config) > 4<<20 || p.metadata == "" || len(p.metadata) > 64<<10 ||
		p.profile == "" || len(p.profile) > 256<<10 || !proofID.MatchString(p.source) ||
		p.inputs.EntryConfig == "" || len(p.inputs.EntryConfig) > 4<<20 ||
		p.inputs.EntryCapture == "" || len(p.inputs.EntryCapture) > 8<<20 ||
		p.inputs.ExitMode != c.meta.ExitMode || !NodeProfileMode(p.inputs.ExitMode) ||
		p.inputs.ExitFiles == "" || len(p.inputs.ExitFiles) > 16<<20 ||
		p.inputs.ExitProfile == "" || len(p.inputs.ExitProfile) > 256<<10 ||
		len(p.inputs.ExitStart) > 16<<20 || len(p.inputs.DNSBootstrap) > 16384 {
		return "", importedLaunchInputError
	}
	metadata, err := json.Marshal(c.meta)
	if err != nil || string(metadata) != p.metadata {
		clear(metadata)
		return "", importedLaunchInputError
	}
	clear(metadata)
	inputs, err := json.Marshal([]string{"routervpn-imported-entry-v1", p.inputs.EntryConfig,
		p.inputs.EntryCapture, p.inputs.ExitMode, p.inputs.ExitFiles, p.inputs.ExitProfile, p.inputs.ExitStart, p.inputs.DNSBootstrap})
	if err != nil || externalDigest(inputs) != p.source {
		clear(inputs)
		return "", importedLaunchInputError
	}
	clear(inputs)
	sealed, err := json.Marshal(struct {
		Domain           string              `json:"domain"`
		Source           string              `json:"source"`
		Config           string              `json:"config"`
		Metadata         string              `json:"metadata"`
		Profile          string              `json:"profile"`
		PublicIP         string              `json:"public_ip"`
		OpenVPNTransport map[string]any      `json:"openvpn_transport"`
		OpenVPNMTU       uint32              `json:"openvpn_mtu"`
		Inputs           importedEntryInputs `json:"inputs"`
	}{"routervpn-imported-desktop-capture-v1", p.source, c.config, p.metadata, p.profile,
		p.publicIP, p.openvpnTransport, p.openvpnMTU, p.inputs})
	if err != nil || len(sealed) > ImportedLaunchInputLimit+(8<<20) {
		clear(sealed)
		return "", importedLaunchInputError
	}
	digest := externalDigest(sealed)
	clear(sealed)
	return digest, nil
}

func (c *Controller) sealImportedDesktopCapture() error {
	seal, err := c.importedDesktopCaptureSeal()
	if err != nil {
		return err
	}
	c.imported.desktopSeal = seal
	return nil
}

func (c *Controller) validateImportedDesktopCapture() error {
	seal, err := c.importedDesktopCaptureSeal()
	if err != nil || c.imported.desktopSeal == "" || seal != c.imported.desktopSeal || c.generation.Load() != 1 {
		return importedLaunchInputError
	}
	return nil
}

// ImportedLaunchInput exports the exact private sources retained by the live,
// immutable NewImportedEntry constructor. The native child must independently
// recompile these sources before deriving a protected desktop policy. Neither
// this envelope nor its hashes authorize a socket, TUN, firewall or live proof.
func (c *Controller) ImportedLaunchInput() (string, error) {
	if c.validateImportedDesktopCapture() != nil {
		return "", importedLaunchInputError
	}
	record := importedLaunchInputRecord{
		Schema: 1, Kind: "routervpn-imported-launch-input", importedEntryInputs: c.imported.inputs,
		SourceSHA256: c.imported.source, ConfigSHA256: externalDigest([]byte(c.config)),
		MetadataSHA256: externalDigest([]byte(c.imported.metadata)),
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > ImportedLaunchInputLimit || c.generation.Load() != 1 {
		clear(raw)
		return "", importedLaunchInputError
	}
	result := string(raw)
	clear(raw)
	return result, nil
}

// ParseImportedLaunchInput admits one bounded canonical record and reruns the
// original imported-entry compiler. A copied executable graph or metadata does
// not replace the independent entry and final sources. Errors never include
// private credentials or compiler diagnostics containing those source values.
func ParseImportedLaunchInput(raw string) (*Controller, error) {
	var record importedLaunchInputRecord
	if exactJSON([]byte(raw), &record, ImportedLaunchInputLimit) != nil || record.Schema != 1 ||
		record.Kind != "routervpn-imported-launch-input" || !proofID.MatchString(record.SourceSHA256) ||
		!proofID.MatchString(record.ConfigSHA256) || !proofID.MatchString(record.MetadataSHA256) {
		return nil, importedLaunchInputError
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != raw {
		clear(canonical)
		return nil, importedLaunchInputError
	}
	clear(canonical)
	compiled, err := NewImportedEntry(record.EntryConfig, record.EntryCapture, record.ExitMode,
		record.ExitFiles, record.ExitProfile, record.ExitStart, record.DNSBootstrap)
	if err != nil || compiled == nil {
		return nil, importedLaunchInputError
	}
	if compiled.SourceSHA256() != record.SourceSHA256 || externalDigest([]byte(compiled.Config())) != record.ConfigSHA256 ||
		externalDigest([]byte(compiled.Metadata())) != record.MetadataSHA256 || compiled.validateImportedDesktopCapture() != nil {
		_ = compiled.Close()
		return nil, importedLaunchInputError
	}
	return compiled, nil
}
