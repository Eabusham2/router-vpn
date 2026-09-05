package main

import (
	"errors"
	"fmt"
	"strings"
)

// validateConnectionProfileModeForSave keeps reusable connection profiles on
// the product's real logical-mode surface. External nodes are normalized by
// writeConnectionProfile before this validator is called.
func (a *app) validateConnectionProfileModeForSave(mode string, customLayers []string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "smart-auto", "auto":
		return nil
	case "custom":
		if len(customLayers) == 0 {
			return errors.New("CUSTOM connection profile requires at least one validated layer")
		}
		return nil
	}
	if strings.HasPrefix(mode, "custom:") {
		if len(customLayers) == 0 {
			return errors.New("saved CUSTOM preset requires its validated layer set")
		}
		return nil
	}
	if _, ok := a.logicalModeByID(mode); ok {
		return nil
	}
	return fmt.Errorf("connection profile mode %q is not a current logical mode", mode)
}
