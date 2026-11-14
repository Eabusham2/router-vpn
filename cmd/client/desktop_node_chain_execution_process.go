package main

import (
	"errors"
	"strconv"
)

func validateDesktopNodeChainExecutionProcessArguments(arguments []string, directory string) ([]string, error) {
	bad := errors.New("ordered execution process lost its exact authenticated preparation")
	if (len(arguments) != 13 && len(arguments) != 15) || arguments[0] != "routervpn-node-chain-execution" {
		return nil, bad
	}
	without := []string{arguments[0]}
	source := ""
	for i := 1; i < len(arguments); i += 2 {
		if arguments[i] == "--execution-source-sha256" {
			if source != "" || !desktopNodeProcessHex(arguments[i+1], 32) {
				return nil, bad
			}
			source = arguments[i+1]
		} else {
			without = append(without, arguments[i], arguments[i+1])
		}
	}
	if source == "" {
		return nil, bad
	}
	if _, err := validateDesktopOrderedProcessArguments(without, directory, "routervpn-node-chain-execution"); err != nil {
		return nil, err
	}
	return append([]string(nil), arguments...), nil
}

func (e *desktopNodeChainExecutionLaunch) processArguments(launch *desktopNodeLaunch, arguments []string) ([]string, error) {
	if e.bound(launch) != nil || len(arguments) == 0 || arguments[0] != e.original.commandName() {
		return nil, errors.New("execution command belongs to another retained native launch")
	}
	result := append(append([]string(nil), arguments...), "--execution-source-sha256", e.preparation.SourceSHA256())
	return e.validateProcessArguments(launch, result)
}

func (e *desktopNodeChainExecutionLaunch) validateProcessArguments(launch *desktopNodeLaunch, arguments []string) ([]string, error) {
	if e.bound(launch) != nil {
		return nil, errors.New("execution argv lost its original launch")
	}
	validated, err := validateDesktopNodeChainExecutionProcessArguments(arguments, launch.directory)
	if err != nil {
		return nil, err
	}
	_, meta, _, err := e.readPolicy()
	if err != nil {
		return nil, err
	}
	wanted := map[string]string{"--runtime-dir": launch.directory, "--session": meta.SessionID,
		"--config-sha256": e.preparation.ConfigSHA256(), "--physical-source-sha256": meta.SourceSHA256,
		"--execution-source-sha256": e.preparation.SourceSHA256()}
	if meta.RestoredMTU != 0 {
		wanted["--physical-mtu"] = strconv.Itoa(meta.RestoredMTU)
	}
	for i := 1; i < len(validated); i += 2 {
		if validated[i] == "--physical-transfer-sha256" {
			continue
		}
		if wanted[validated[i]] != validated[i+1] {
			return nil, errors.New("execution argv replaced captured source, session, config or MTU")
		}
		delete(wanted, validated[i])
	}
	if len(wanted) != 0 {
		return nil, errors.New("execution argv omitted captured native authority")
	}
	return validated, nil
}
