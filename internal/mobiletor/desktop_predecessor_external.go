package mobiletor

import (
	"errors"

	"router-vpn/internal/mobilemultihop"
)

// NewDesktopExternalPredecessor recompiles the ordinary provider's complete
// native policy. The original graph is retained separately so the child can
// repeat that validation instead of accepting a host-supplied transformed graph.
func NewDesktopExternalPredecessor(mode, profileJSON, sourceConfigJSON, assetsSHA256 string) (*DesktopPredecessor, error) {
	if !desktopHex(assetsSHA256, 32) {
		return nil, errors.New("desktop Tor external entry requires its captured source asset digest")
	}
	proof, err := NewExternalPredecessorProof(profileJSON, sourceConfigJSON)
	if err != nil {
		return nil, err
	}
	if mode != proof.protocol {
		return nil, errors.New("desktop Tor external entry mode differs from its captured protocol")
	}
	return &DesktopPredecessor{mode: mode, profile: proof.profile, config: proof.config, assets: assetsSHA256,
		tag: mobilemultihop.ExternalFinalTag, kind: ExternalPredecessorProofKind, external: proof}, nil
}
