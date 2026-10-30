package mobiletor

import (
	"strings"
	"testing"
)

func TestDesktopWindowsProtectionTargetRejectsSubstitution(t *testing.T) {
	capture := DesktopSocketCapture{SessionID: strings.Repeat("1", 32), SourceSHA256: strings.Repeat("2", 64), NetworkID: strings.Repeat("3", 32)}
	metadata := []byte("canonical native baseline including LAN and DHCP")
	target := desktopWindowsProtectionTarget(capture, "always", metadata)
	if err := target.Validate(); err != nil || !target.matches(capture, "always", metadata) {
		t.Fatal("captured native target did not match", err)
	}
	for _, name := range []string{"session", "source", "network", "policy", "metadata"} {
		t.Run(name, func(t *testing.T) {
			actual, policy, record := capture, "always", append([]byte(nil), metadata...)
			switch name {
			case "session":
				actual.SessionID = strings.Repeat("4", 32)
			case "source":
				actual.SourceSHA256 = strings.Repeat("4", 64)
			case "network":
				actual.NetworkID = strings.Repeat("4", 32)
			case "policy":
				policy = "on-connect"
			case "metadata":
				record[len(record)-1] ^= 1
			}
			if target.matches(actual, policy, record) {
				t.Fatal("changed baseline acquired exact-target authority")
			}
		})
	}
	for _, name := range []string{"empty", "session", "source", "network", "policy", "digest", "uppercase"} {
		t.Run("invalid-"+name, func(t *testing.T) {
			invalid := target
			switch name {
			case "empty":
				invalid = DesktopWindowsProtectionTarget{}
			case "session":
				invalid.Capture.SessionID = "1"
			case "source":
				invalid.Capture.SourceSHA256 = "2"
			case "network":
				invalid.Capture.NetworkID = "3"
			case "policy":
				invalid.Policy = "off"
			case "digest":
				invalid.BaselineSHA256 = "0"
			case "uppercase":
				invalid.BaselineSHA256 = strings.Repeat("A", 64)
			}
			if invalid.Validate() == nil || invalid.matches(capture, "always", metadata) {
				t.Fatal("malformed target acquired baseline authority")
			}
			if expected, err := newDesktopWindowsProtectionExpected(&invalid); err == nil || expected != nil {
				t.Fatal("malformed predecessor entered a native operation", err)
			}
		})
	}
}

func TestDesktopWindowsProtectionTargetCapturesBeforeNativeWait(t *testing.T) {
	target := desktopWindowsProtectionTarget(DesktopSocketCapture{strings.Repeat("1", 32), strings.Repeat("2", 64), strings.Repeat("3", 32)}, "always", []byte("exact baseline"))
	original := target
	expected, err := newDesktopWindowsProtectionExpected(&target)
	if err != nil || expected == nil || expected.target == nil {
		t.Fatal(err)
	}
	target.Capture.NetworkID, target.BaselineSHA256, target.Policy = strings.Repeat("4", 32), strings.Repeat("5", 64), "on-connect"
	if *expected.target != original {
		t.Fatal("caller mutation changed a pending native predecessor")
	}
	absent, err := newDesktopWindowsProtectionExpected(nil)
	if err != nil || absent == nil || absent.target != nil {
		t.Fatal("initial absence became unbounded recovery authority", err)
	}
}
