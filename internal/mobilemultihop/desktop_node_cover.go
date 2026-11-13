package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/mobileperf"
)

// DesktopNodeCoverService is the complete captured native service policy. It
// describes immutable constructor input, not an activated worker or proof.
type DesktopNodeCoverService struct {
	Tag     string                  `json:"tag"`
	Options mobileperf.CoverOptions `json:"options"`
}

// CoverPolicy reads only the sealed desktop graph. The ordinary Node graph
// has one exit and therefore at most one cover service. A returned empty
// digest means the source requested no cover; it cannot stand in for a failed
// or missing requested worker. Each call returns an independent slice.
func (p *DesktopNodePolicy) CoverPolicy() ([]DesktopNodeCoverService, string, error) {
	failure := errors.New("desktop Router cover lost its complete sealed native policy")
	if p == nil || p.Validate() != nil {
		return nil, "", failure
	}
	return desktopPhysicalCoverPolicy(p.config, p.metadata.NodeID)
}

// Imported cover belongs to the independently paired final, never the external
// entry. It is read from the sealed complete imported graph without rebuilding
// that final as an ordinary NodeProfile.
func (p *DesktopImportedPolicy) CoverPolicy() ([]DesktopNodeCoverService, string, error) {
	if p == nil || p.Validate() != nil {
		return nil, "", errors.New("desktop imported cover lost its sealed final")
	}
	return desktopPhysicalCoverPolicy(p.config, p.metadata.ExitNodeID)
}

func ReadDesktopPhysicalCoverPolicy(policy DesktopPhysicalPolicy) ([]DesktopNodeCoverService, string, error) {
	if _, _, _, err := ReadDesktopPhysicalPolicy(policy); err != nil {
		return nil, "", err
	}
	switch original := policy.(type) {
	case *DesktopNodePolicy:
		return original.CoverPolicy()
	case *DesktopImportedPolicy:
		return original.CoverPolicy()
	case *DesktopNodeChainPolicy:
		config, meta, _, err := original.ReadValidated()
		if err != nil {
			return nil, "", err
		}
		return desktopPhysicalCoverPolicy(config, meta.NodeID)
	case *DesktopNodeChainExecutionPhysicalPolicy:
		config, meta, _, err := original.PhysicalReadValidated()
		if err != nil {
			return nil, "", err
		}
		return desktopPhysicalCoverPolicy(config, meta.NodeID)
	case *DesktopNodeCandidatePreparationPolicy:
		config, meta, _, err := original.PhysicalReadValidated()
		if err != nil {
			return nil, "", err
		}
		return desktopPhysicalCoverPolicy(config, meta.NodeID)
	default:
		return nil, "", errors.New("cover requires an original sealed physical policy")
	}
}

func desktopPhysicalCoverPolicy(config, nodeID string) ([]DesktopNodeCoverService, string, error) {
	failure := errors.New("desktop Router cover lost its complete sealed native policy")
	var graph struct {
		Services []json.RawMessage `json:"services"`
	}
	if json.Unmarshal([]byte(config), &graph) != nil {
		return nil, "", failure
	}
	var result []DesktopNodeCoverService
	for _, raw := range graph.Services {
		var service struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			mobileperf.CoverOptions
		}
		if json.Unmarshal(raw, &service) != nil {
			return nil, "", failure
		}
		if service.Type != mobileperf.CoverType {
			continue
		}
		if len(result) != 0 || service.Tag != "routervpn-cover-exit" || service.NodeID != nodeID || service.CoverOptions.Validate() != nil {
			return nil, "", failure
		}
		result = append(result, DesktopNodeCoverService{Tag: service.Tag, Options: service.CoverOptions})
	}
	if len(result) == 0 {
		return nil, "", nil
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return nil, "", failure
	}
	return result, externalDigest(canonical), nil
}
