package main

import (
	"errors"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// The inherited execution command requires this exact schema-five preparation
// and sealed physical owner. The provider transport is never a host permit.
func desktopMacOSOpenVPNExecutionProcessArguments(scope macosprocess.Scope,
	preparation *mobilemultihop.NodeChainExecutionPreparation,
	physical *mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy) ([]string, error) {
	refused := errors.New("macOS OpenVPN execution child lost its original typed preparation")
	if scope.Family != macosprocess.NodeChainExecutionFamily || preparation == nil || physical == nil {
		return nil, refused
	}
	retained, err := preparation.OpenVPNDesktopPhysicalPolicy()
	if err != nil || retained != physical {
		return nil, refused
	}
	config, metadata, _, err := physical.PhysicalReadValidated()
	if err != nil || metadata.Kind != "node-chain-openvpn-execution" || metadata.TargetOS != "darwin" ||
		metadata.SessionID != scope.Session || metadata.SourceSHA256 != scope.Source ||
		metadata.ConfigSHA256 != scope.Config || scope.Config != preparation.ConfigSHA256() ||
		config != preparation.Config() || preparation.SourceSHA256() == "" {
		return nil, refused
	}
	return []string{"routervpn-node-chain-execution", "--runtime-dir", scope.Workspace,
		"--session", scope.Session, "--physical-source-sha256", scope.Source,
		"--config-sha256", scope.Config, "--execution-source-sha256", preparation.SourceSHA256(),
		"--darwin-control", "inherited-v1"}, nil
}
