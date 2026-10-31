//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"strings"
)

// ReadDesktopLinuxProtectionAbsence independently reads the kernel. A missing
// state file, an nft command error, a closed source or a decoded empty record
// cannot establish initial absence. This function mutates no native policy.
func ReadDesktopLinuxProtectionAbsence(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux protection absence requires a live native readback")
	}
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTRows(raw)
	if err != nil {
		return err
	}
	if err := desktopLinuxTableListAbsent(rows, func(name string) bool {
		return name == desktopLinuxNFTTable || strings.HasPrefix(name, desktopLinuxNodeTablePrefix)
	}); err != nil {
		return err
	}
	return ctx.Err()
}

// A malformed or unknown reserved table cannot be converted into absence.
// The complete native table listing is required, even when a direct table
// read failed. Unrelated families/names remain outside this application's
// cleanup authority and are never mutated here.
func desktopLinuxTableListAbsent(rows []map[string]any, selected func(string) bool) error {
	metadata := 0
	seen := make(map[string]bool)
	for _, row := range rows {
		if len(row) != 1 {
			return errors.New("Linux protection table listing contains an ambiguous object")
		}
		for kind, raw := range row {
			value, ok := raw.(map[string]any)
			if !ok || value == nil {
				return errors.New("Linux protection table listing contains a malformed object")
			}
			if kind == "metainfo" {
				metadata++
				if metadata > 1 {
					return errors.New("Linux protection table listing duplicated metadata")
				}
				continue
			}
			family, familyOK := value["family"].(string)
			name, nameOK := value["name"].(string)
			key := family + "\x00" + name
			if kind != "table" || !desktopLinuxProtectionKeys(value, "family", "name", "handle", "flags") || !familyOK || family == "" ||
				!nameOK || name == "" || seen[key] || desktopLinuxNumber(value["handle"]) == 0 || desktopLinuxNumber(value["handle"]) > 1<<53-1 {
				return errors.New("Linux protection table listing lost a complete native identity")
			}
			seen[key] = true
			if selected(name) {
				return errors.New("Linux protection still has an existing native table")
			}
		}
	}
	if metadata != 1 {
		return errors.New("Linux protection table listing omitted native metadata")
	}
	return nil
}
