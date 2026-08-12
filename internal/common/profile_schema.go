package common

import (
	"encoding/json"
	"fmt"
	"strings"
)

type routerProfileWire RouterProfile
type routerProfileStoreWire RouterProfileStore

// NormalizeRouterProfile upgrades policy defaults and validates configuration
// intent. Runtime capability remains a separate live-tested concern: a valid
// multihop selection does not make an unsupported platform claim multihop.
func NormalizeRouterProfile(p *RouterProfile) error {
	if p.SchemaVersion > RouterProfileSchemaVersion {
		return fmt.Errorf("router profile schema %d is newer than supported schema %d", p.SchemaVersion, RouterProfileSchemaVersion)
	}
	p.SchemaVersion = RouterProfileSchemaVersion

	p.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(p.KillSwitchPolicy))
	if p.KillSwitchPolicy == "" {
		if p.KillSwitch {
			p.KillSwitchPolicy = "on-connect"
		} else {
			p.KillSwitchPolicy = "off"
		}
	}
	switch p.KillSwitchPolicy {
	case "off", "on-connect", "always":
	default:
		return fmt.Errorf("invalid kill switch policy %q", p.KillSwitchPolicy)
	}
	p.KillSwitch = p.KillSwitchPolicy != "off"

	p.StartupMode = strings.ToLower(strings.TrimSpace(p.StartupMode))
	if p.StartupMode == "" {
		p.StartupMode = "manual"
	}
	switch p.StartupMode {
	case "manual", "auto", "smart-auto", "last":
	default:
		return fmt.Errorf("invalid startup mode %q", p.StartupMode)
	}

	p.IPv6Mode = strings.ToLower(strings.TrimSpace(p.IPv6Mode))
	if p.IPv6Mode == "" {
		p.IPv6Mode = "auto"
	}
	switch p.IPv6Mode {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("invalid IPv6 mode %q", p.IPv6Mode)
	}

	p.MTUPolicy = strings.ToLower(strings.TrimSpace(p.MTUPolicy))
	if p.MTUPolicy == "" {
		p.MTUPolicy = "default"
	}
	switch p.MTUPolicy {
	case "default", "auto":
		p.ManualMTU = 0
	case "manual":
		if p.ManualMTU < 576 || p.ManualMTU > 9000 {
			return fmt.Errorf("manual MTU %d is outside 576..9000", p.ManualMTU)
		}
	default:
		return fmt.Errorf("invalid MTU policy %q", p.MTUPolicy)
	}

	if p.DiagnosticsRetentionDays == 0 {
		p.DiagnosticsRetentionDays = 7
	}
	if p.DiagnosticsRetentionDays < 1 || p.DiagnosticsRetentionDays > 365 {
		return fmt.Errorf("diagnostics retention must be between 1 and 365 days")
	}

	p.MultihopEntryID = strings.TrimSpace(p.MultihopEntryID)
	p.MultihopExitID = strings.TrimSpace(p.MultihopExitID)
	if p.MultihopEnabled {
		if p.MultihopEntryID == "" || p.MultihopExitID == "" {
			return fmt.Errorf("multihop requires both an entry node and an exit node")
		}
		if p.MultihopEntryID == p.MultihopExitID {
			return fmt.Errorf("multihop entry and exit nodes must be different")
		}
	}
	return nil
}

func NormalizeRouterProfileStore(s *RouterProfileStore) error {
	if s.SchemaVersion > RouterProfileStoreVersion {
		return fmt.Errorf("router profile store schema %d is newer than supported schema %d", s.SchemaVersion, RouterProfileStoreVersion)
	}
	s.SchemaVersion = RouterProfileStoreVersion
	for i := range s.Profiles {
		if err := NormalizeRouterProfile(&s.Profiles[i]); err != nil {
			return fmt.Errorf("profile %q: %w", s.Profiles[i].ID, err)
		}
	}
	if s.SelectedID == "" && len(s.Profiles) > 0 {
		s.SelectedID = s.Profiles[0].ID
	}
	return nil
}

func (p *RouterProfile) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded routerProfileWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = RouterProfile(decoded)
	if _, present := raw["home_lan_access"]; !present {
		// Old profiles predate the explicit LAN-access switch. Preserve their
		// historical reachable-LAN behavior while allowing an explicit false to
		// round-trip in the versioned schema.
		p.HomeLANAccess = true
	}
	return NormalizeRouterProfile(p)
}

func (p RouterProfile) MarshalJSON() ([]byte, error) {
	clone := p
	if err := NormalizeRouterProfile(&clone); err != nil {
		return nil, err
	}
	base, err := json.Marshal(routerProfileWire(clone))
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(base, &raw); err != nil {
		return nil, err
	}
	// home_lan_access must be explicit because false is a meaningful policy, not
	// the same thing as a legacy profile that omitted the field.
	raw["home_lan_access"], _ = json.Marshal(clone.HomeLANAccess)
	raw["schema_version"], _ = json.Marshal(RouterProfileSchemaVersion)
	return json.Marshal(raw)
}

func (s *RouterProfileStore) UnmarshalJSON(data []byte) error {
	var decoded routerProfileStoreWire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = RouterProfileStore(decoded)
	return NormalizeRouterProfileStore(s)
}

func (s RouterProfileStore) MarshalJSON() ([]byte, error) {
	clone := s
	if err := NormalizeRouterProfileStore(&clone); err != nil {
		return nil, err
	}
	return json.Marshal(routerProfileStoreWire(clone))
}
