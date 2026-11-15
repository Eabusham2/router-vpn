package main

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

func macOSCONNECTExecutionArgumentFixture(t *testing.T, target, execution string) (macosprocess.Scope,
	*mobilemultihop.NodeChainExecutionPreparation, *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy) {
	t.Helper()
	_, launch := desktopCONNECTExecutionLaunchFixture(t, "awg2-fast", "https-connect", target, execution)
	preparation, physical := launch.preparation, launch.connectPhysical
	_, meta, _, err := physical.PhysicalReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	return macosprocess.Scope{Family: macosprocess.NodeChainExecutionFamily, Session: meta.SessionID,
		Source: meta.SourceSHA256, Config: meta.ConfigSHA256, Workspace: "/original-private-runtime"}, preparation, physical
}

func TestMacOSCONNECTExecutionProcessArgumentsRetainTypedPreparation(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			scope, preparation, physical := macOSCONNECTExecutionArgumentFixture(t, "darwin", execution)
			before, source, config := scope, preparation.Source(), preparation.Config()
			arguments, err := desktopMacOSCONNECTExecutionProcessArguments(scope, preparation, physical)
			want := []string{"routervpn-node-chain-execution", "--runtime-dir", scope.Workspace,
				"--session", scope.Session, "--physical-source-sha256", scope.Source,
				"--config-sha256", scope.Config, "--execution-source-sha256", preparation.SourceSHA256(),
				"--darwin-control", "inherited-v1"}
			if err != nil || !reflect.DeepEqual(arguments, want) || scope.Source == preparation.SourceSHA256() {
				t.Fatal("execution command lost its distinct captured identities", arguments, err)
			}
			arguments[0], arguments[2], arguments[10] = "replacement", "/replacement", strings.Repeat("e", 64)
			again, err := desktopMacOSCONNECTExecutionProcessArguments(scope, preparation, physical)
			if err != nil || !reflect.DeepEqual(again, want) || scope != before || preparation.Source() != source || preparation.Config() != config {
				t.Fatal("caller-owned argv mutation replaced retained source authority", err)
			}
			if ordinary, err := desktopMacOSProcessArguments(scope); err == nil || ordinary != nil {
				t.Fatal("family label alone acquired execution command authority")
			}
		})
	}
}

func TestMacOSCONNECTExecutionProcessArgumentsRefuseSourceAndOwnerSubstitution(t *testing.T) {
	scope, preparation, physical := macOSCONNECTExecutionArgumentFixture(t, "darwin", "auto")
	copyPreparation, err := mobilemultihop.ParseDesktopNodeChainCONNECTExecutionPreparation(preparation.Source())
	if err != nil {
		t.Fatal(err)
	}
	copyPhysical, err := copyPreparation.CONNECTDesktopPhysicalPolicy()
	if err != nil || copyPhysical == physical || copyPreparation == preparation {
		t.Fatal("copied preparation fixture did not create independent owners", err)
	}
	_, generic, _ := macOSExecutionArgumentFixture(t, "darwin", "auto")
	for name, change := range map[string]func(*macosprocess.Scope){
		"session":               func(s *macosprocess.Scope) { s.Session = strings.Repeat("e", 32) },
		"source":                func(s *macosprocess.Scope) { s.Source = strings.Repeat("e", 64) },
		"execution-as-physical": func(s *macosprocess.Scope) { s.Source = preparation.SourceSHA256() },
		"config":                func(s *macosprocess.Scope) { s.Config = strings.Repeat("e", 64) },
		"ordinary":              func(s *macosprocess.Scope) { s.Family = macosprocess.NodeChainFamily },
		"SOCKS":                 func(s *macosprocess.Scope) { s.Family = macosprocess.NodeChainSOCKSFamily },
		"CONNECT":               func(s *macosprocess.Scope) { s.Family = macosprocess.NodeChainCONNECTFamily },
		"prefix":                func(s *macosprocess.Scope) { s.Family = macosprocess.CandidatePrefixFamily },
		"unknown":               func(s *macosprocess.Scope) { s.Family = "ordered-node-chain-execution-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := scope
			change(&changed)
			if got, err := desktopMacOSCONNECTExecutionProcessArguments(changed, preparation, physical); err == nil || got != nil {
				t.Fatal("changed typed execution source acquired a native invocation")
			}
		})
	}
	for _, test := range []struct {
		name        string
		preparation *mobilemultihop.NodeChainExecutionPreparation
		physical    *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy
	}{
		{"nil-preparation", nil, physical}, {"nil-physical", preparation, nil},
		{"equal-copy-physical", preparation, copyPhysical}, {"equal-copy-preparation", copyPreparation, physical},
		{"generic-preparation", generic, physical},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := desktopMacOSCONNECTExecutionProcessArguments(scope, test.preparation, test.physical); err == nil || got != nil {
				t.Fatal("another preparation or physical owner acquired native invocation")
			}
		})
	}
	for _, target := range []string{"linux", "windows"} {
		t.Run(target, func(t *testing.T) {
			otherScope, otherPreparation, otherPhysical := macOSCONNECTExecutionArgumentFixture(t, target, "server")
			if got, err := desktopMacOSCONNECTExecutionProcessArguments(otherScope, otherPreparation, otherPhysical); err == nil || got != nil {
				t.Fatal("foreign native target acquired macOS invocation")
			}
		})
	}
}
