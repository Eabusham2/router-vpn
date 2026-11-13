package main

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
)

func macOSArgumentScope() macosprocess.Scope {
	return macosprocess.Scope{
		Workspace: "/Library/Application Support/RouterVPN/run/native-node/session-original",
		Session:   strings.Repeat("1", 32),
		Source:    strings.Repeat("2", 64),
		Config:    strings.Repeat("3", 64),
	}
}

// These portable tests exercise the shipping argv selector, not native process
// admission. OpenCapture/BindCreated and actual child retirement stay Darwin
// responsibilities and retain their separate installed-controller fixtures.
func TestMacOSProcessArgumentsRetainExactConcreteFamily(t *testing.T) {
	for _, test := range []struct {
		name    string
		family  macosprocess.Family
		command string
	}{
		{"original-default", "", "routervpn-external"},
		{"explicit-external", macosprocess.ExternalFamily, "routervpn-external"},
		{"ordered-node-chain", macosprocess.NodeChainFamily, "routervpn-node-chain"},
		{"candidate-prefix", macosprocess.CandidatePrefixFamily, "routervpn-node-candidate-prefix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := macOSArgumentScope()
			scope.Family = test.family
			before := scope
			arguments, err := desktopMacOSProcessArguments(scope)
			want := []string{
				test.command,
				"--runtime-dir", before.Workspace,
				"--session", before.Session,
				"--physical-source-sha256", before.Source,
				"--config-sha256", before.Config,
				"--darwin-control", "inherited-v1",
			}
			if err != nil || !reflect.DeepEqual(arguments, want) {
				t.Fatalf("concrete family changed captured argv: %v, %v", arguments, err)
			}
			if scope != before {
				t.Fatal("command selection mutated its original captured scope")
			}
			// A caller cannot replace another invocation's retained command or
			// redirect its original workspace through a shared argument slice.
			arguments[0], arguments[2], arguments[10] = "foreign-command", "/replacement", "foreign-control"
			next, err := desktopMacOSProcessArguments(scope)
			if err != nil || !reflect.DeepEqual(next, want) || scope != before {
				t.Fatal("caller-owned argv mutation relinked the captured family or scope", err)
			}
		})
	}
}

func TestMacOSProcessArgumentsRejectUnknownConcreteFamily(t *testing.T) {
	for _, family := range []macosprocess.Family{
		"external", "node-chain", "ordered-node-chain", "ordered-node-chain-v2",
		"Ordered-node-chain-v1", "ORDERED-NODE-CHAIN-V1",
		" ordered-node-chain-v1", "ordered-node-chain-v1 ",
		"ordered-node-chain-v1\n", "ordered-node-chain-v1\x00",
		"routervpn-external", "routervpn-node-chain", "--darwin-control",
		"candidate-prefix", "node-candidate-prefix-v2", "Node-candidate-prefix-v1", "node-candidate-prefix-v1\n", "routervpn-node-candidate-prefix",
	} {
		t.Run(string(family), func(t *testing.T) {
			scope := macOSArgumentScope()
			scope.Family = family
			before := scope
			arguments, err := desktopMacOSProcessArguments(scope)
			if err == nil || arguments != nil {
				t.Fatal("unsupported family acquired an external or generic child invocation")
			}
			if scope != before {
				t.Fatal("rejected family modified its original scope")
			}
			for _, private := range []string{scope.Workspace, scope.Session, scope.Source, scope.Config} {
				if strings.Contains(err.Error(), private) {
					t.Fatal("family refusal exposed unrelated captured input")
				}
			}
		})
	}
}

func TestMacOSProcessArgumentsDoNotRelinkAnEarlierCapture(t *testing.T) {
	original := macOSArgumentScope()
	original.Family = macosprocess.NodeChainFamily
	first, err := desktopMacOSProcessArguments(original)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]string(nil), first...)
	replacement := macosprocess.Scope{
		Workspace: "/Library/Application Support/RouterVPN/run/native-node/session-replacement",
		Session:   strings.Repeat("4", 32),
		Source:    strings.Repeat("5", 64),
		Config:    strings.Repeat("6", 64),
		Family:    macosprocess.ExternalFamily,
	}
	second, err := desktopMacOSProcessArguments(replacement)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"routervpn-external",
		"--runtime-dir", replacement.Workspace,
		"--session", replacement.Session,
		"--physical-source-sha256", replacement.Source,
		"--config-sha256", replacement.Config,
		"--darwin-control", "inherited-v1",
	}
	if !reflect.DeepEqual(second, want) || !reflect.DeepEqual(first, before) {
		t.Fatal("another concrete family relinked original command values")
	}
	replacement.Family = "unknown"
	if rejected, err := desktopMacOSProcessArguments(replacement); err == nil || rejected != nil {
		t.Fatal("retired family reused a previous accepted command")
	}
	if !reflect.DeepEqual(first, before) || !reflect.DeepEqual(second, want) {
		t.Fatal("rejected family changed previously captured arguments")
	}
}
