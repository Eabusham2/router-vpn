package main

import "errors"

func desktopNodeChainExecutionProtectionSelection(execution *desktopNodeChainExecutionLaunch) (desktopProtectionSelection, error) {
	_, meta, _, err := execution.readPolicy()
	if err != nil || meta.TargetOS != "windows" || !validProfileID(meta.ProfileID) ||
		(meta.KillSwitchPolicy != "on-connect" && meta.KillSwitchPolicy != "always") {
		return desktopProtectionSelection{}, errors.Join(err, errors.New("execution protection lost its original sealed native policy"))
	}
	return desktopProtectionSelection{meta.ProfileID, meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.KillSwitchPolicy}, nil
}
