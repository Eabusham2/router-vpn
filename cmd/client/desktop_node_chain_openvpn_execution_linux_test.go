//go:build linux

package main

import (
	"testing"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

// Native process and kernel observations are explicit models; the original
// Linux transaction, physical selection and private-source checks execute.
func desktopLinuxOpenVPNExecutionFixture(t *testing.T, choice string) (*desktopLinuxNodeHost, *desktopLinuxNodeTransaction) {
	t.Helper()
	_, _, launch, execution, _ := desktopOpenVPNExecutionLaunchFixture(t, 4, "linux", choice)
	if err := execution.attach(launch); err != nil {
		t.Fatal(err)
	}
	_, meta, _, err := execution.readPolicy()
	if err != nil {
		t.Fatal(err)
	}
	sources := &desktopNodeChainSources{selection: launch.chain.selection}
	capture := &desktopNodeChainHostCapture{sources: sources}
	process := &desktopLinuxNodeProcess{}
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	host := &desktopLinuxNodeHost{chain: launch.chain.policy, launch: launch, process: process, source: []byte(launch.chain.input), selection: selection}
	launch.chain.capture = capture
	launch.chain.selection.Native.chain.host = capture
	launch.chain.platform = &desktopNodeChainPlatformRuntime{capture: capture, host: host}
	transaction := &desktopLinuxNodeTransaction{chain: host.chain, execution: execution, chainSources: sources, process: process,
		selection: selection, profileID: meta.ProfileID, mode: meta.Mode}
	return host, transaction
}

func TestDesktopLinuxOpenVPNExecutionKeepsExactTransaction(t *testing.T) {
	for _, fault := range []string{"server", "auto", "omitted-execution", "foreign-execution", "foreign-source", "foreign-process", "local-config", "missing-adjunct", "equal-policy", "missing-policy", "socks-policy", "connect-policy"} {
		t.Run(fault, func(t *testing.T) {
			choice := "auto"
			if fault == "server" {
				choice = "server"
			}
			host, transaction := desktopLinuxOpenVPNExecutionFixture(t, choice)
			switch fault {
			case "omitted-execution":
				transaction.execution = nil
			case "foreign-execution":
				_, other := desktopLinuxOpenVPNExecutionFixture(t, choice)
				transaction.execution = other.execution
			case "foreign-source":
				transaction.chainSources = &desktopNodeChainSources{selection: transaction.chainSources.selection}
			case "foreign-process":
				transaction.process = &desktopLinuxNodeProcess{}
			case "local-config":
				_, meta, _, err := host.chain.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				transaction.selection.ConfigSHA256 = meta.ConfigSHA256
			case "missing-adjunct":
				host.launch.chain.execution = nil
			case "equal-policy":
				input, err := host.chain.NodeChain().LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				transaction.chain, err = mobilemultihop.ParseDesktopNodeChainLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				transaction.chain = nil
			case "socks-policy":
				transaction.socksChain = &mobilemultihop.DesktopNodeChainSOCKSPolicy{}
			case "connect-policy":
				transaction.connectChain = &mobilemultihop.DesktopNodeChainCONNECTPolicy{}
			}
			err := transaction.validatePolicy()
			if fault != "server" && fault != "auto" {
				if err == nil {
					t.Fatal("OpenVPN execution borrowed a foreign Linux transaction")
				}
				return
			}
			physical, physicalErr := host.readyPolicy()
			inputs := host.privateInputs()
			if err != nil || physicalErr != nil || physical != transaction.execution.openvpnPhysical || len(inputs) != 2 ||
				inputs[1].name != "node-chain-execution-source.json" || string(inputs[1].body) != transaction.execution.preparation.Source() {
				t.Fatal("OpenVPN Linux transaction lost original physical owner or private preparation", err, physicalErr)
			}
			profile, err := host.capturedProofProfile()
			if err != nil || profile.ID != host.launch.chain.selection.Exit.ID || profile.APIToken != host.launch.chain.selection.Exit.APIToken {
				t.Fatal("OpenVPN Linux proof lost original paired final", err)
			}
		})
	}
}
