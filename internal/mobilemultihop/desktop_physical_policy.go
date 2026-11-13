package mobilemultihop

import "errors"

// DesktopPhysicalPolicy is the sealed native lower-transport boundary shared
// by the independently compiled Router-node, imported-entry and ordered-chain
// policy types. Its private method prevents caller-created metadata adapters.
// Native paths retain their exact concrete policy pointer through admission,
// activation and retirement; a fresh identical policy is a different owner.
type DesktopPhysicalPolicy interface {
	Validate() error
	Config() string
	PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error)
	desktopPhysicalPolicy()
}

type DesktopPhysicalMetadata struct {
	Kind, SessionID, TargetOS, SourceSHA256, ConfigSHA256 string
	ProfileID, NodeID, Mode, StartLayer                   string
	KillSwitchPolicy, IPv6Mode                            string
	HomeLANAccess                                         bool
	RestoredMTU                                           int
}

type DesktopPhysicalCapture struct {
	TUNTag, IPv6Mode    string
	ConfiguredMTU       int
	SelectedDNS         ExternalDesktopDNS
	BootstrapDNS        []ExternalDesktopDNS
	PhysicalRoots       []ExternalDesktopPhysicalRoot
	PrivateDestinations []PhysicalEgress
}

// ReadDesktopPhysicalPolicy additionally checks the concrete constructor type.
// Embedding this interface in a caller-defined wrapper cannot substitute its
// own validation or projected fields for an original sealed authority.
func ReadDesktopPhysicalPolicy(policy DesktopPhysicalPolicy) (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	switch policy := policy.(type) {
	case *DesktopNodePolicy:
		return policy.PhysicalReadValidated()
	case *DesktopImportedPolicy:
		return policy.PhysicalReadValidated()
	case *DesktopNodeChainPolicy:
		return policy.PhysicalReadValidated()
	case *DesktopNodeChainExecutionPhysicalPolicy:
		return policy.PhysicalReadValidated()
	case *DesktopNodeCandidatePreparationPolicy:
		return policy.PhysicalReadValidated()
	default:
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, errors.New("native physical policy has no admitted sealed constructor")
	}
}

func (*DesktopNodePolicy) desktopPhysicalPolicy() {}

func (p *DesktopNodePolicy) PhysicalReadValidated() (string, DesktopPhysicalMetadata, DesktopPhysicalCapture, error) {
	config, meta, capture, err := p.ReadValidated()
	if err != nil {
		return "", DesktopPhysicalMetadata{}, DesktopPhysicalCapture{}, err
	}
	return config, DesktopPhysicalMetadata{
			Kind: "node", SessionID: meta.SessionID, TargetOS: meta.TargetOS,
			SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, ProfileID: meta.ProfileID,
			NodeID: meta.NodeID, Mode: meta.Mode, StartLayer: meta.StartLayer,
			KillSwitchPolicy: meta.KillSwitchPolicy, IPv6Mode: meta.IPv6Mode, HomeLANAccess: meta.HomeLANAccess,
			RestoredMTU: meta.RestoredMTU,
		}, DesktopPhysicalCapture{
			TUNTag: capture.TUNTag, IPv6Mode: capture.IPv6Mode, ConfiguredMTU: capture.ConfiguredMTU,
			SelectedDNS: capture.SelectedDNS, BootstrapDNS: capture.BootstrapDNS, PhysicalRoots: capture.PhysicalRoots,
			PrivateDestinations: capture.PrivateDestinations,
		}, nil
}
