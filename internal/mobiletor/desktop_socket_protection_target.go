package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// DesktopWindowsProtectionTarget constrains a native protection operation to
// one previously captured baseline. Its public fields are identifiers, not
// authority: every native consumer independently verifies the actual BFE
// record, complete rules and session lock before changing anything.
type DesktopWindowsProtectionTarget struct {
	Capture        DesktopSocketCapture `json:"capture"`
	Policy         string               `json:"policy"`
	BaselineSHA256 string               `json:"baseline_sha256"`
}

func (t DesktopWindowsProtectionTarget) Validate() error {
	if !t.Capture.valid() || t.Policy != "on-connect" && t.Policy != "always" || !desktopSocketHex(t.BaselineSHA256, 64) {
		return errors.New("Windows protection target requires its complete captured identity")
	}
	return nil
}

func desktopWindowsProtectionTarget(capture DesktopSocketCapture, policy string, metadata []byte) DesktopWindowsProtectionTarget {
	digest := sha256.Sum256(metadata)
	return DesktopWindowsProtectionTarget{Capture: capture, Policy: policy, BaselineSHA256: hex.EncodeToString(digest[:])}
}

func (t DesktopWindowsProtectionTarget) matches(capture DesktopSocketCapture, policy string, metadata []byte) bool {
	return t.Validate() == nil && t == desktopWindowsProtectionTarget(capture, policy, metadata)
}

// A nonnil expectation is distinct from the older recovery constructor. A nil
// target within it explicitly requires initial absence; it never adopts an
// arbitrary stale baseline. Copying the value prevents a caller from changing
// its selected predecessor while a bounded native operation is still joining.
type desktopWindowsProtectionExpected struct {
	target *DesktopWindowsProtectionTarget
}

func newDesktopWindowsProtectionExpected(target *DesktopWindowsProtectionTarget) (*desktopWindowsProtectionExpected, error) {
	expected := &desktopWindowsProtectionExpected{}
	if target != nil {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		captured := *target
		expected.target = &captured
	}
	return expected, nil
}
