package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func TestDesktopCONNECTDerivationRetainsConstructorOwners(t *testing.T) {
	for _, fault := range []string{
		"copied-policy", "missing-receipt", "borrowed-receipt", "original-owner",
		"native-owner", "binding-owner", "inputs", "resealed-policy",
		"native-config", "original-source", "capture-bytes", "capture-digest",
	} {
		t.Run(fault, func(t *testing.T) {
			_, policy := desktopCONNECTPolicyFixture(t, "wg", "", "linux", 0)
			if policy.Validate() != nil {
				t.Fatal("original constructor was not current")
			}
			switch fault {
			case "copied-policy":
				copied := *policy
				policy = &copied
			case "missing-receipt":
				policy.derivation = nil
			case "borrowed-receipt", "native-owner":
				other, err := NewDesktopNodeChainCONNECTPolicy(policy.original, policy.inputs.sessionID, policy.inputs.targetOS, policy.inputs.restoredMTU)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "borrowed-receipt" {
					policy.derivation = other.derivation
				} else {
					policy.native = other.native
				}
			case "original-owner":
				other, err := NewNodeChainCONNECTSource(policy.original.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				policy.original = other
			case "binding-owner":
				copied := *policy.native.desktop
				policy.native.desktop = &copied
			case "inputs":
				policy.inputs.restoredMTU = 1300
			case "resealed-policy":
				policy.metadata.HomeLANAccess = !policy.metadata.HomeLANAccess
				policy.seal = policy.currentSeal()
			case "native-config":
				policy.native.config += "\n"
			case "original-source":
				policy.original.sourceJSON += "\n"
			case "capture-bytes":
				policy.derivation.captureJSON += "\n"
			case "capture-digest":
				policy.derivation.captureSHA256 = strings.Repeat("0", 64)
			}
			if policy.Validate() == nil {
				t.Fatal("retained derivation admitted replaced constructor authority")
			}
			if _, err := policy.OriginalSource(); err == nil {
				t.Fatal("original source accessor admitted changed derivation")
			}
			if _, err := policy.NativeSource(); err == nil {
				t.Fatal("native source accessor admitted changed derivation")
			}
			if _, err := policy.ReadValidatedLaunch(); err == nil {
				t.Fatal("launch accessor admitted changed derivation")
			}
			if _, _, _, err := ReadDesktopPhysicalPolicy(policy); err == nil {
				t.Fatal("physical reader admitted changed derivation")
			}
		})
	}
}

func TestDesktopCONNECTDerivationReturnsDetachedCapture(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			_, policy := desktopCONNECTPolicyFixture(t, "awg2-fast", "", target, 0)
			config, metadata, capture, err := policy.ReadValidated()
			if err != nil || len(capture.PhysicalRoots) == 0 || len(capture.PhysicalRoots[0].Destinations) == 0 || len(capture.PhysicalRoots[0].Networks) == 0 {
				t.Fatal("original physical capture missing", err)
			}
			_, wantedMetadata, wantedCapture, err := policy.ReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			metadata.Prefixes[1].Tag = "foreign-middle"
			metadata.Roots[0].Tag = "foreign-root"
			capture.SelectedDNS.Host = "203.0.113.99"
			capture.PhysicalRoots[0].Destinations[0].Port = 1
			capture.PhysicalRoots[0].Networks[0] = "tcp"
			freshConfig, freshMetadata, freshCapture, err := policy.ReadValidated()
			if err != nil || freshConfig != config || !reflect.DeepEqual(freshMetadata, wantedMetadata) || !reflect.DeepEqual(freshCapture, wantedCapture) {
				t.Fatal("returned physical capture aliases constructor or another reader", err)
			}
		})
	}
}
