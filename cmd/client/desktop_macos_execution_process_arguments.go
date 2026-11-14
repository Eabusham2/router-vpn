package main

import (
	"errors"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// Execution has two different source identities: the original physical policy
// and the complete Server/Compare preparation. A family label or an ordinary
// Local command cannot replace either captured typed owner.
func desktopMacOSExecutionProcessArguments(scope macosprocess.Scope,
	preparation *mobilemultihop.NodeChainExecutionPreparation,
	physical *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy) ([]string, error) {
	refused := errors.New("macOS execution child lost its exact typed physical preparation")
	if scope.Family != macosprocess.NodeChainExecutionFamily || preparation == nil || physical == nil {
		return nil, refused
	}
	retained, err := preparation.DesktopPhysicalPolicy()
	if err != nil || retained != physical {
		return nil, refused
	}
	config, metadata, _, err := physical.PhysicalReadValidated()
	if err != nil || metadata.Kind != "node-chain-execution" || metadata.TargetOS != "darwin" ||
		metadata.SessionID != scope.Session || metadata.SourceSHA256 != scope.Source ||
		metadata.ConfigSHA256 != scope.Config || scope.Config != preparation.ConfigSHA256() ||
		config != preparation.Config() || preparation.SourceSHA256() == "" {
		return nil, refused
	}
	return []string{
		"routervpn-node-chain-execution",
		"--runtime-dir", scope.Workspace,
		"--session", scope.Session,
		"--physical-source-sha256", scope.Source,
		"--config-sha256", scope.Config,
		"--execution-source-sha256", preparation.SourceSHA256(),
		"--darwin-control", "inherited-v1",
	}, nil
}
