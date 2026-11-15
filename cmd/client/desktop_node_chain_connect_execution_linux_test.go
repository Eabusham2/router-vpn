//go:build linux

package main

import (
	"testing"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

// The process and controller are explicit models. These assertions exercise the
// shipping transaction's original source boundary, not native nftables or TUN.
func desktopLinuxCONNECTExecutionPolicyFixture(t *testing.T, protocol, choice string) (*desktopLinuxNodeHost, *desktopLinuxNodeTransaction) {
	t.Helper()
	launch, execution := desktopCONNECTExecutionLaunchFixture(t, "awg2-strong", protocol, "linux", choice)
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
	host := &desktopLinuxNodeHost{connectChain: launch.chain.connectPolicy, launch: launch, process: process, source: []byte(launch.chain.input), selection: selection}
	launch.chain.capture = capture
	launch.chain.selection.Native.chain.host = capture
	launch.chain.platform = &desktopNodeChainPlatformRuntime{capture: capture, host: host}
	transaction := &desktopLinuxNodeTransaction{connectChain: host.connectChain, execution: execution, chainSources: sources, process: process,
		selection: selection, profileID: meta.ProfileID, mode: meta.Mode}
	return host, transaction
}

func TestDesktopLinuxCONNECTExecutionTransactionPinsOriginalPreparation(t *testing.T) {
	for _, fault := range []string{"http-server", "https-compare", "omitted-execution", "foreign-execution", "foreign-source", "foreign-process", "local-config", "missing-adjunct", "equal-policy", "missing-policy", "mixed-policy", "mixed-socks"} {
		t.Run(fault, func(t *testing.T) {
			protocol, choice := "https-connect", "auto"
			if fault == "http-server" {
				protocol, choice = "http-connect", "server"
			}
			host, transaction := desktopLinuxCONNECTExecutionPolicyFixture(t, protocol, choice)
			switch fault {
			case "omitted-execution":
				transaction.execution = nil
			case "foreign-execution":
				_, other := desktopLinuxCONNECTExecutionPolicyFixture(t, protocol, choice)
				transaction.execution = other.execution
			case "foreign-source":
				transaction.chainSources = &desktopNodeChainSources{selection: transaction.chainSources.selection}
			case "foreign-process":
				transaction.process = &desktopLinuxNodeProcess{}
			case "local-config":
				_, meta, _, err := host.connectChain.ReadValidated()
				if err != nil {
					t.Fatal(err)
				}
				transaction.selection.ConfigSHA256 = meta.ConfigSHA256
			case "missing-adjunct":
				host.launch.chain.execution = nil
			case "equal-policy":
				input, err := host.connectChain.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				transaction.connectChain, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(input)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				transaction.connectChain = nil
			case "mixed-policy":
				transaction.chain = &mobilemultihop.DesktopNodeChainPolicy{}
			case "mixed-socks":
				transaction.socksChain = &mobilemultihop.DesktopNodeChainSOCKSPolicy{}
			}
			err := transaction.validatePolicy()
			if fault != "http-server" && fault != "https-compare" {
				if err == nil {
					t.Fatal("CONNECT execution transaction borrowed another source, process or physical graph")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			physical, err := host.readyPolicy()
			if err != nil || physical != transaction.execution.connectPhysical {
				t.Fatal("CONNECT execution readiness borrowed Local physical authority", err)
			}
			inputs := host.privateInputs()
			if len(inputs) != 2 || inputs[1].name != "node-chain-execution-source.json" || string(inputs[1].body) != transaction.execution.preparation.Source() {
				t.Fatal("CONNECT execution staging lost exact private preparation")
			}
			profile, err := host.capturedProofProfile()
			if err != nil || profile.ID != host.launch.chain.selection.Exit.ID || profile.APIToken != host.launch.chain.selection.Exit.APIToken {
				t.Fatal("CONNECT execution proof lost original final authority", err)
			}
		})
	}
}
