package main

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

func desktopOpenVPNMacOSArgumentFixture(t *testing.T, target, choice string) (macosprocess.Scope, *mobilemultihop.NodeChainExecutionPreparation, *mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy) {
	t.Helper()
	_, _, _, execution, _ := desktopOpenVPNExecutionLaunchFixture(t, 4, target, choice)
	_, meta, _, err := execution.openvpnPhysical.PhysicalReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	return macosprocess.Scope{Family: macosprocess.NodeChainExecutionFamily, Session: meta.SessionID, Source: meta.SourceSHA256, Config: meta.ConfigSHA256, Workspace: "/original-private-runtime"}, execution.preparation, execution.openvpnPhysical
}

func TestMacOSOpenVPNExecutionArgumentsRetainOriginalPreparation(t *testing.T) {
	for _, choice := range []string{"server", "auto"} {
		t.Run(choice, func(t *testing.T) {
			scope, prep, physical := desktopOpenVPNMacOSArgumentFixture(t, "darwin", choice)
			before, source, config := scope, prep.Source(), prep.Config()
			want := []string{"routervpn-node-chain-execution", "--runtime-dir", scope.Workspace,
				"--session", scope.Session, "--physical-source-sha256", scope.Source, "--config-sha256", scope.Config,
				"--execution-source-sha256", prep.SourceSHA256(), "--darwin-control", "inherited-v1"}
			args, err := desktopMacOSOpenVPNExecutionProcessArguments(scope, prep, physical)
			if err != nil || !reflect.DeepEqual(args, want) || scope.Source == prep.SourceSHA256() {
				t.Fatal("OpenVPN invocation lost its distinct captured identities", err)
			}
			args[0], args[2], args[10] = "replacement", "/replacement", strings.Repeat("e", 64)
			again, err := desktopMacOSOpenVPNExecutionProcessArguments(scope, prep, physical)
			if err != nil || !reflect.DeepEqual(again, want) || scope != before || prep.Source() != source || prep.Config() != config {
				t.Fatal("caller argv mutation changed the original OpenVPN source")
			}
		})
	}
}

func TestMacOSOpenVPNExecutionArgumentsRejectForeignOwner(t *testing.T) {
	scope, prep, physical := desktopOpenVPNMacOSArgumentFixture(t, "darwin", "auto")
	other, err := mobilemultihop.ParseDesktopNodeChainOpenVPNExecutionPreparation(prep.Source())
	if err != nil {
		t.Fatal(err)
	}
	copyPhysical, err := other.OpenVPNDesktopPhysicalPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"session", "source", "config", "execution-as-physical", "local-family", "CONNECT-family", "missing-preparation", "missing-physical", "copied-preparation", "copied-physical", "CONNECT-preparation", "linux", "windows"} {
		t.Run(fault, func(t *testing.T) {
			s, p, owner := scope, prep, physical
			switch fault {
			case "session":
				s.Session = strings.Repeat("e", 32)
			case "source":
				s.Source = strings.Repeat("e", 64)
			case "config":
				s.Config = strings.Repeat("e", 64)
			case "execution-as-physical":
				s.Source = prep.SourceSHA256()
			case "local-family":
				s.Family = macosprocess.NodeChainFamily
			case "CONNECT-family":
				s.Family = macosprocess.NodeChainCONNECTFamily
			case "missing-preparation":
				p = nil
			case "missing-physical":
				owner = nil
			case "copied-preparation":
				p = other
			case "copied-physical":
				owner = copyPhysical
			case "CONNECT-preparation":
				_, connect := desktopCONNECTExecutionLaunchFixture(t, "wg", "https-connect", "darwin", "auto")
				p = connect.preparation
			case "linux", "windows":
				s, p, owner = desktopOpenVPNMacOSArgumentFixture(t, fault, "server")
			}
			if args, err := desktopMacOSOpenVPNExecutionProcessArguments(s, p, owner); err == nil || args != nil {
				t.Fatal("foreign OpenVPN preparation or physical scope acquired native invocation")
			}
		})
	}
}
