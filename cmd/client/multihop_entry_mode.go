package main

import (
	"errors"
	"runtime"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopMultihopEntryModes() []string {
	if runtime.GOOS == "linux" && !retainedNativeMultihopSelected() {
		return []string{"wg"} // The legacy AWG script chooses its variant by base.
	}
	return mobilemultihop.NodeMultihopEntryModes()
}

// Resolve only the selection contract here. An empty raw result deliberately
// leaves WG/AWG variant discovery to the immutable source capture, whose
// existing Fast/Strong file precedence is shared by Connect and Compare.
func resolveNativeMultihopEntryMode(control, entry common.RouterProfile, requested, base string) (string, string, error) {
	if base != "" && base != "auto" && base != "wg" && base != "awg" {
		return "", "", errors.New("native multihop entry base must be Auto, WireGuard or AmneziaWG")
	}
	mode := requested
	if mode == "" {
		mode = control.MultihopEntryMode
	}
	if _, err := normalizeConnectionProfileEntryMode(mode); err != nil {
		return "", "", err
	}
	if mode == "" {
		return "", resolveMultihopEntryBase(control, entry, base), nil
	}
	return mode, desktopExternalEntryBase(mode), nil
}

// Empty is the legacy base/variant selection. It is kept distinct from every
// explicit raw transport; malformed nonempty values never grant that fallback.
func normalizeConnectionProfileEntryMode(value string) (string, error) {
	if value == "" || mobilemultihop.NodeMultihopEntryMode(value) {
		return value, nil
	}
	return "", errors.New("multihop_entry_mode must identify an exact supported native entry transport")
}

// Setup's optional metadata is a mirror of the transactional profile record.
// A stale or hand-edited mirror cannot replace the source mode during Load.
func validateConnectionProfileSetupEntryMeta(store connectionProfileStore, id, mode string) error {
	for _, saved := range store.Profiles {
		if saved.ID != id {
			continue
		}
		if saved.Prefs != nil && saved.Prefs.MultihopEnabled && saved.Prefs.MultihopEntryMode == mode {
			return nil
		}
		if saved.External != nil && saved.External.MultihopEnabled && saved.External.MultihopEntryMode == mode {
			return nil
		}
		return errors.New("saved setup entry transport does not match its captured profile")
	}
	return errors.New("saved setup entry transport has no captured connection profile")
}
