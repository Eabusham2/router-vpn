package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"router-vpn/internal/common"
)

var ownedWindowsModeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// captureOwnedWindowsModes compares writable generated catalogs with the
// retained package source and its existing native adapter mapping. Only the
// captured system interpreter and immutable helper paths reach the controller's
// in-memory table. A Data filename alone never grants command authority.
func captureOwnedWindowsModes(source, selected []common.Mode, powerShell, helperRoot string, samePath func(string, string) bool) ([]common.Mode, error) {
	if len(source) == 0 || len(source) > 128 || len(source) != len(selected) || powerShell == "" || helperRoot == "" || samePath == nil {
		return nil, errors.New("the owned Windows mode catalog has no bounded captured source")
	}
	result := make([]common.Mode, len(source))
	seen := make(map[string]bool, len(source))
	for index, original := range source {
		if !ownedWindowsModeID.MatchString(original.ID) || seen[original.ID] {
			return nil, errors.New("the owned Windows mode source has an invalid or duplicate identity")
		}
		seen[original.ID] = true
		want, got := original, selected[index]
		want.Command, want.CheckCommand, want.StopCommand = nil, nil, nil
		got.Command, got.CheckCommand, got.StopCommand = nil, nil, nil
		if !reflect.DeepEqual(want, got) {
			return nil, errors.New("the selected Windows catalog differs from its retained package metadata")
		}
		result[index] = original
		for _, operation := range []struct {
			action        string
			before, given []string
			output        *[]string
		}{
			{"up", original.Command, selected[index].Command, &result[index].Command},
			{"check", original.CheckCommand, selected[index].CheckCommand, &result[index].CheckCommand},
			{"down", original.StopCommand, selected[index].StopCommand, &result[index].StopCommand},
		} {
			generated, canonical := ownedWindowsModeCommand(original.ID, operation.action, operation.before, powerShell, helperRoot)
			if !reflect.DeepEqual(operation.given, operation.before) && !ownedWindowsGeneratedCommand(operation.given, generated, powerShell, samePath) {
				return nil, fmt.Errorf("the Windows %s %s command escaped its retained adapter", original.ID, operation.action)
			}
			*operation.output = append([]string(nil), canonical...)
		}
	}
	return result, nil
}

func ownedWindowsModeCommand(id, action string, original []string, powerShell, helperRoot string) ([]string, []string) {
	var generated []string
	switch id {
	case "wg":
		generated = []string{"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(helperRoot, "native-wireguard-windows.ps1"), action}
	case "hysteria2", "shadowsocks", "naive-h2", "naive-h3", "reality-vision", "reality-pq-vision", "split", "max":
		generated = []string{"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(helperRoot, "native-windows-mode.ps1"), "-Mode", id, "-Action", action}
	default:
		if len(original) == 0 {
			return nil, nil
		}
		message := fmt.Sprintf("Mode '%s' has no native Windows adapter yet. Router VPN will not pretend this mode is ready through a compatibility layer.", id)
		generated = append([]string(nil), original...)
		if strings.HasPrefix(original[0], "./") {
			generated = []string{"cmd.exe", "/d", "/c", "echo " + message + " 1>&2 & exit /b 127"}
		}
		// Go's native graph and strategy paths run before these legacy catalog
		// fallbacks. An unsupported fallback must not discover Python, cmd, WSL
		// or another executable through a mutable process environment.
		quoted := strings.ReplaceAll(message, "'", "''")
		return generated, []string{powerShell, "-NoProfile", "-NonInteractive", "-Command", "Write-Error '" + quoted + "'; exit 127"}
	}
	canonical := append([]string(nil), generated...)
	canonical[0] = powerShell
	return generated, canonical
}

func ownedWindowsGeneratedCommand(given, expected []string, powerShell string, samePath func(string, string) bool) bool {
	if len(given) != len(expected) {
		return false
	}
	for index, value := range expected {
		if given[index] == value {
			continue
		}
		if len(expected) >= 6 && expected[0] == "powershell.exe" {
			if index == 0 && samePath(given[index], powerShell) || index == 5 && samePath(given[index], value) {
				continue
			}
		}
		return false
	}
	return true
}
