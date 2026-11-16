package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestDesktopExecutionObservationRetainsOriginalAndFreshValues(t *testing.T) {
	for _, fault := range []string{"original", "nil-preparation", "equal-preparation", "copied-preparation", "copied-physical", "copied-policy", "copied-original", "changed-source", "changed-native-config", "changed-derived-config", "changed-policy", "changed-physical"} {
		t.Run(fault, func(t *testing.T) {
			source := desktopExecutionSource(t, "auto", "", false)
			original, prep, _ := desktopExecutionProjection(t, source, "linux", desktopNodeTestSession, 0)
			physical, err := prep.DesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			requested := prep
			switch fault {
			case "nil-preparation":
				requested = nil
			case "equal-preparation":
				requested, err = NewDesktopNodeChainExecutionPreparation(original, "auto")
				if err != nil {
					t.Fatal(err)
				}
			case "copied-preparation":
				copy := *prep
				requested = &copy
			case "copied-physical":
				copy := *physical
				physical = &copy
			case "copied-policy":
				copy := *original
				physical.original = &copy
			case "copied-original":
				copy := *original.original
				original.original = &copy
			case "changed-source":
				original.original.sourceJSON += " "
			case "changed-native-config":
				prep.config += " "
			case "changed-derived-config":
				original.chain.config += " "
			case "changed-policy":
				original.inputs.restoredMTU = 1300
			case "changed-physical":
				physical.capture.SelectedDNS.Detour = "foreign"
			}
			owner, chain, metadata, config, native, capture, err := physical.ReadExecutionValidated(requested)
			if fault != "original" {
				if err == nil || owner != nil || chain != nil || !reflect.DeepEqual(metadata, DesktopNodeChainMetadata{}) || config != "" || !reflect.DeepEqual(native, DesktopPhysicalMetadata{}) || !reflect.DeepEqual(capture, DesktopPhysicalCapture{}) {
					t.Fatal("combined observation accepted changed original ownership or source", fault)
				}
				_, _, _, sourceErr := physical.ReadOriginalSourceValidated(requested)
				if sourceErr == nil {
					t.Fatal("source observation accepted changed original ownership or source", fault)
				}
				return
			}
			if err != nil || owner != original || chain != original.original || config != prep.config || native.ConfigSHA256 != prep.configSHA || capture.SelectedDNS.Detour != SelectorTag || !reflect.DeepEqual(metadata, original.metadata) {
				t.Fatal("combined observation lost exact original source", err)
			}
			metadata.Prefixes[0].ProfileID = "foreign"
			metadata.Roots[0].Tag = "foreign"
			capture.PhysicalRoots[0].Tag = "foreign"
			_, _, again, _, _, againCapture, err := physical.ReadExecutionValidated(prep)
			if err != nil || !reflect.DeepEqual(again, original.metadata) || againCapture.PhysicalRoots[0].Tag == "foreign" {
				t.Fatal("combined observation lent mutable output authority", err)
			}
		})
	}
}
