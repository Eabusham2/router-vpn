package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func ownedWindowsCatalogFixture(t *testing.T) ([]common.Mode, string, string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source []common.Mode
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	return source, filepath.Join("captured-system", "powershell.exe"), filepath.Join("captured-package", "client")
}

func TestOwnedWindowsCatalogUsesImmutableSourceAndCapturedCommands(t *testing.T) {
	source, powerShell, helpers := ownedWindowsCatalogFixture(t)
	same := func(left, right string) bool { return left == right }
	result, err := captureOwnedWindowsModes(source, source, powerShell, helpers, same)
	if err != nil || len(result) != len(source) {
		t.Fatal("the actual packaged mode source did not retain its complete catalog", err)
	}
	for index, mode := range result {
		original := source[index]
		want, got := original, mode
		want.Command, want.CheckCommand, want.StopCommand = nil, nil, nil
		got.Command, got.CheckCommand, got.StopCommand = nil, nil, nil
		if !reflect.DeepEqual(want, got) {
			t.Fatal("native command capture changed the source mode metadata", mode.ID)
		}
		for _, command := range [][]string{mode.Command, mode.CheckCommand, mode.StopCommand} {
			if len(command) > 0 && command[0] != powerShell {
				t.Fatal("owned catalog retained an ambient interpreter", mode.ID, command)
			}
		}
		if mode.ID == "wg" && mode.Command[5] != filepath.Join(helpers, "native-wireguard-windows.ps1") {
			t.Fatal("WireGuard lost its exact native package helper")
		}
		if mode.ID == "max" && !reflect.DeepEqual(mode.Command[5:], []string{filepath.Join(helpers, "native-windows-mode.ps1"), "-Mode", "max", "-Action", "up"}) {
			t.Fatal("MAX lost its selected native adapter arguments")
		}
	}
	if !strings.HasPrefix(source[0].Command[0], "./") {
		t.Fatal("capturing a native catalog modified its retained source")
	}
	// Existing generated catalogs may use the unqualified system interpreter;
	// it is accepted as syntax only and replaced by the retained system image.
	generated := append([]common.Mode(nil), source...)
	for index := range generated {
		m := &generated[index]
		m.Command, _ = ownedWindowsModeCommand(m.ID, "up", m.Command, powerShell, helpers)
		m.CheckCommand, _ = ownedWindowsModeCommand(m.ID, "check", m.CheckCommand, powerShell, helpers)
		m.StopCommand, _ = ownedWindowsModeCommand(m.ID, "down", m.StopCommand, powerShell, helpers)
	}
	if actual, err := captureOwnedWindowsModes(source, generated, powerShell, helpers, same); err != nil || !reflect.DeepEqual(result, actual) {
		t.Fatal("the existing generated Windows catalog changed captured behavior", err)
	}
}

func TestOwnedWindowsCatalogRejectsMutableCommandAuthority(t *testing.T) {
	source, powerShell, helpers := ownedWindowsCatalogFixture(t)
	for _, change := range []string{"up", "check", "down", "metadata", "reorder", "foreign-helper", "foreign-interpreter", "extra-argument"} {
		t.Run(change, func(t *testing.T) {
			selected := append([]common.Mode(nil), source...)
			m := &selected[0]
			switch change {
			case "up":
				m.Command = []string{"unselected.exe"}
			case "check":
				m.CheckCommand = []string{"unselected.exe"}
			case "down":
				m.StopCommand = []string{"unselected.exe"}
			case "metadata":
				m.MTU++
			case "reorder":
				selected[0], selected[1] = selected[1], selected[0]
			default:
				m.Command, _ = ownedWindowsModeCommand(m.ID, "up", m.Command, powerShell, helpers)
				switch change {
				case "foreign-helper":
					m.Command[5] = filepath.Join("unselected", "native-wireguard-windows.ps1")
				case "foreign-interpreter":
					m.Command[0] = filepath.Join("unselected", "powershell.exe")
				case "extra-argument":
					m.Command = append(m.Command, "-Command", "unselected")
				}
			}
			if _, err := captureOwnedWindowsModes(source, selected, powerShell, helpers, func(left, right string) bool { return left == right }); err == nil {
				t.Fatal("writable catalog acquired elevated command or policy authority")
			}
		})
	}
}

func TestOwnedWindowsCatalogRejectsUnboundedOrAmbiguousSource(t *testing.T) {
	source, powerShell, helpers := ownedWindowsCatalogFixture(t)
	for _, change := range []string{"empty", "duplicate", "invalid-id", "oversized", "missing-interpreter", "missing-helper-root", "missing-identity-proof"} {
		t.Run(change, func(t *testing.T) {
			value := append([]common.Mode(nil), source...)
			interpreter, root := powerShell, helpers
			same := func(left, right string) bool { return left == right }
			switch change {
			case "empty":
				value = nil
			case "duplicate":
				value[1].ID = value[0].ID
			case "invalid-id":
				value[0].ID = "mode'; unselected"
			case "oversized":
				value = make([]common.Mode, 129)
			case "missing-interpreter":
				interpreter = ""
			case "missing-helper-root":
				root = ""
			case "missing-identity-proof":
				same = nil
			}
			if _, err := captureOwnedWindowsModes(value, value, interpreter, root, same); err == nil {
				t.Fatal("invalid Windows source acquired native command authority")
			}
		})
	}
}
