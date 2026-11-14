package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

func nativeMultihopRuntimeDirFromCommand(cmd *exec.Cmd) (string, error) {
	if cmd == nil || len(cmd.Args) < 2 {
		return "", errors.New("native multihop command has no runtime arguments")
	}
	if cmd.Args[1] == "routervpn-node-chain-socks" {
		if _, err := validateDesktopNodeChainSOCKSProcessArguments(cmd.Args[1:], cmd.Dir); err != nil {
			return "", err
		}
		return cmd.Dir, nil
	}
	if cmd.Args[1] == "routervpn-node-chain" {
		if _, err := validateDesktopNodeChainProcessArguments(cmd.Args[1:], cmd.Dir); err != nil {
			return "", err
		}
		return cmd.Dir, nil
	}
	if cmd.Args[1] == "routervpn-node" {
		// The typed child descriptor already owns this directory. An edited
		// --runtime-dir must not authenticate itself as a new DNS workspace.
		if _, err := validateDesktopNodeProcessArguments(cmd.Args[1:], cmd.Dir); err != nil {
			return "", err
		}
		return cmd.Dir, nil
	}
	for i := 0; i+1 < len(cmd.Args); i++ {
		if strings.EqualFold(strings.TrimSpace(cmd.Args[i]), "-RuntimeDir") {
			dir := strings.TrimSpace(cmd.Args[i+1])
			if dir == "" || strings.ContainsAny(dir, "\r\n\x00") {
				return "", errors.New("native multihop Windows RuntimeDir argument is empty or unsafe")
			}
			return dir, nil
		}
	}
	for i := 0; i+1 < len(cmd.Args); i++ {
		if strings.TrimSpace(cmd.Args[i]) == "up" {
			dir := strings.TrimSpace(cmd.Args[i+1])
			if dir == "" || strings.ContainsAny(dir, "\r\n\x00") {
				return "", errors.New("native multihop Unix runtime directory argument is empty or unsafe")
			}
			return dir, nil
		}
	}
	return "", errors.New("native multihop command does not expose an owned runtime directory")
}

func registerNativeMultihopDNSRuntime(a *app, sel multihopSelection, cmd *exec.Cmd) error {
	dir, err := nativeMultihopRuntimeDirFromCommand(cmd)
	if err != nil {
		return err
	}
	return registerActiveDNSRuntimeConfigKind(a, sel.Exit.ID, sel.ExitMode, filepath.Join(dir, "sing-box.json"), sel.Native != nil && (sel.Native.imported || sel.Native.chain != nil))
}
