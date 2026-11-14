package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestDesktopNodeChainValidatedLaunchKeepsCanonicalSource(t *testing.T) {
	original := desktopChainFixture(t, 3, "", nil)
	policy := desktopChainPolicy(t, original, "windows", 0)
	capture, err := policy.ReadValidatedLaunch()
	config, metadata, physical, readErr := policy.ReadValidated()
	input, inputErr := policy.NodeChain().LaunchInput()
	if err != nil || readErr != nil || inputErr != nil || capture.Original != original || capture.Config != config || capture.Input != input || !reflect.DeepEqual(capture.Metadata, metadata) || !reflect.DeepEqual(capture.Physical, physical) {
		t.Fatal("validated launch lost complete original fields", err, readErr, inputErr)
	}
	capture.Metadata.Prefixes[0].Tag = "foreign-prefix"
	capture.Metadata.Roots[0].Tag = "foreign-root"
	capture.Physical.PhysicalRoots[0].Destinations[0].Host = "203.0.113.99"
	again, err := policy.ReadValidatedLaunch()
	if err != nil || !reflect.DeepEqual(again.Metadata, metadata) || !reflect.DeepEqual(again.Physical, physical) {
		t.Fatal("returned launch fields alias retained policy", err)
	}
	// Copy only the inert compiler capture; the fresh runtime owns its own mutex.
	copied := NodeChain{
		sourceJSON:        original.sourceJSON,
		sourceSHA:         original.sourceSHA,
		config:            original.config,
		metadata:          original.metadata,
		seal:              original.seal,
		nodes:             original.nodes,
		importedMiddle:    original.importedMiddle,
		socksSource:       original.socksSource,
		connectSource:     original.connectSource,
		proofs:            original.proofs,
		dns:               original.dns,
		physical:          original.physical,
		originalConfigSHA: original.originalConfigSHA,
		projection:        original.projection,
	}
	if !reflect.DeepEqual(original, &copied) {
		t.Fatal("launch identity fixture must preserve every inert compiler field")
	}
	copiedPolicy, err := NewDesktopNodeChainPolicy(&copied, desktopNodeTestSession, "windows", 0)
	if err != nil {
		t.Fatal(err)
	}
	copiedCapture, err := copiedPolicy.ReadValidatedLaunch()
	if err != nil || copiedCapture.Original != &copied || copiedCapture.Original == original || copiedCapture.Input != input {
		t.Fatal("equal source bytes concealed different constructor identity", err)
	}
	for _, fault := range []string{"nil", "seal", "metadata", "config", "source", "member"} {
		t.Run(fault, func(t *testing.T) {
			source := desktopChainFixture(t, 3, "", nil)
			value := desktopChainPolicy(t, source, "windows", 0)
			switch fault {
			case "nil":
				value = nil
			case "seal":
				value.seal = "foreign"
			case "metadata":
				value.metadata.SessionID += "foreign"
			case "config":
				value.chain.config += " "
			case "source":
				source.sourceJSON += " "
			case "member":
				source.nodes[1].inputs.ProfileJSON += " "
			}
			result, err := value.ReadValidatedLaunch()
			if err == nil || !reflect.DeepEqual(result, DesktopNodeChainLaunchCapture{}) {
				t.Fatal("malformed original source leaked a validated launch")
			}
		})
	}
}

func TestDesktopSOCKSValidatedLaunchKeepsCanonicalSource(t *testing.T) {
	original, policy := desktopSOCKSPolicyFixture(t, "awg2-strong", "", "windows", 0)
	capture, err := policy.ReadValidatedLaunch()
	config, metadata, physical, readErr := policy.ReadValidated()
	input, inputErr := policy.LaunchInput()
	if err != nil || readErr != nil || inputErr != nil || capture.Original != original || capture.Config != config || capture.Input != input || !reflect.DeepEqual(capture.Metadata, metadata) || !reflect.DeepEqual(capture.Physical, physical) {
		t.Fatal("typed validated launch lost complete original fields", err, readErr, inputErr)
	}
	capture.Metadata.Prefixes[0].Tag = "foreign-prefix"
	capture.Metadata.Roots[0].Tag = "foreign-root"
	capture.Physical.PhysicalRoots[0].Destinations[0].Host = "203.0.113.99"
	again, err := policy.ReadValidatedLaunch()
	if err != nil || !reflect.DeepEqual(again.Metadata, metadata) || !reflect.DeepEqual(again.Physical, physical) {
		t.Fatal("typed returned launch fields alias retained policy", err)
	}
	copied := *original
	copiedPolicy := *policy
	copiedPolicy.original = &copied
	copiedCapture, err := copiedPolicy.ReadValidatedLaunch()
	if err == nil || !reflect.DeepEqual(copiedCapture, DesktopNodeChainSOCKSLaunchCapture{}) {
		t.Fatal("copied typed source replaced its original self-bound constructor")
	}
	for _, fault := range []string{"nil", "seal", "metadata", "config", "source", "native-source"} {
		t.Run(fault, func(t *testing.T) {
			source, value := desktopSOCKSPolicyFixture(t, "wg", "", "windows", 0)
			switch fault {
			case "nil":
				value = nil
			case "seal":
				value.seal = "foreign"
			case "metadata":
				value.metadata.SessionID += "foreign"
			case "config":
				value.native.config += " "
			case "source":
				source.sourceJSON += " "
			case "native-source":
				value.native.sourceJSON += " "
			}
			result, err := value.ReadValidatedLaunch()
			if err == nil || !reflect.DeepEqual(result, DesktopNodeChainSOCKSLaunchCapture{}) {
				t.Fatal("malformed typed source leaked a validated launch")
			}
		})
	}
}
