package main

import (
	"errors"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// The inherited execution command requires this exact schema-six preparation
// and sealed physical owner. Each imported transport remains behind the original paired entry.
func desktopMacOSMultipleImportedExecutionProcessArguments(scope macosprocess.Scope,
	preparation *mobilemultihop.NodeChainExecutionPreparation,
	physical *mobilemultihop.DesktopNodeChainMultipleImportedExecutionPhysicalPolicy) ([]string, error) {
	refused := errors.New("macOS MultipleImported execution child lost its original typed preparation")
	if scope.Family != macosprocess.NodeChainExecutionFamily || preparation == nil || physical == nil {
		return nil, refused
	}
	retained, err := preparation.MultipleImportedDesktopPhysicalPolicy()
	if err != nil || retained != physical {
		return nil, refused
	}
	config, metadata, _, err := physical.PhysicalReadValidated()
	if err != nil || metadata.Kind != "node-chain-multiple-imported-execution" || metadata.TargetOS != "darwin" ||
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
