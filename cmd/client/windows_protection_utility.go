package main

import "errors"

const windowsProtectionUtilityFlag = "--windows-physical-protection"

func parseWindowsProtectionUtility(args []string) (operation string, handled bool, err error) {
	if len(args) == 0 || args[0] != windowsProtectionUtilityFlag {
		return "", false, nil
	}
	if len(args) != 2 || args[1] != "status" && args[1] != "release" && args[1] != "force-off" && args[1] != "probe" {
		return "", true, errors.New("--windows-physical-protection requires exactly probe, status, release or force-off")
	}
	return args[1], true, nil
}
