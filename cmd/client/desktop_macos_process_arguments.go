package main

import (
	"errors"

	"router-vpn/internal/macosprocess"
)

// The concrete family chooses only its fixed child command. This does not
// confer process, workspace or runtime authority: the Darwin caller must still
// complete OpenCapture, retain the original descriptors and BindCreated.
func desktopMacOSProcessArguments(scope macosprocess.Scope) ([]string, error) {
	var command string
	switch scope.Family {
	case macosprocess.ExternalFamily:
		command = "routervpn-external"
	case macosprocess.NodeChainFamily:
		command = "routervpn-node-chain"
	default:
		return nil, errors.New("macOS child scope has an unsupported concrete policy family")
	}
	return []string{
		command,
		"--runtime-dir", scope.Workspace,
		"--session", scope.Session,
		"--physical-source-sha256", scope.Source,
		"--config-sha256", scope.Config,
		"--darwin-control", "inherited-v1",
	}, nil
}
