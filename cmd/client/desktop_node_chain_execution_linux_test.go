//go:build linux

package main

import (
	"strings"
	"testing"

	"router-vpn/internal/linuxprotection"
)

// This is the original transaction's policy/capability boundary, with explicit
// process/controller models. It does not assert nftables, routes or TUN proof.
func desktopLinuxExecutionPolicyFixture(t *testing.T) (*desktopLinuxNodeHost, *desktopLinuxNodeTransaction) {
	t.Helper()
	launch, execution := desktopExecutionAttachedFixture(t, "linux")
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

func TestDesktopLinuxExecutionTransactionPinsOriginalPreparation(t *testing.T) {
	for _, fault := range []string{"original", "omitted-execution", "foreign-execution", "foreign-source", "foreign-process", "local-config", "missing-adjunct"} {
		t.Run(fault, func(t *testing.T) {
			host, transaction := desktopLinuxExecutionPolicyFixture(t)
			switch fault {
			case "omitted-execution":
				transaction.execution = nil
			case "foreign-execution":
				_, other := desktopLinuxExecutionPolicyFixture(t)
				transaction.execution = other.execution
			case "foreign-source":
				transaction.chainSources = &desktopNodeChainSources{selection: transaction.chainSources.selection}
			case "foreign-process":
				transaction.process = &desktopLinuxNodeProcess{}
			case "local-config":
				transaction.selection.ConfigSHA256 = host.chain.Metadata().ConfigSHA256
			case "missing-adjunct":
				host.launch.chain.execution = nil
			}
			err := transaction.validatePolicy()
			if fault != "original" {
				if err == nil {
					t.Fatal("Linux transaction borrowed another source, process or physical graph")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			physical, err := host.readyPolicy()
			if err != nil || physical != transaction.execution.physical {
				t.Fatal("Linux readiness borrowed Local physical authority", err)
			}
			inputs := host.privateInputs()
			if len(inputs) != 2 || inputs[1].name != "node-chain-execution-source.json" || string(inputs[1].body) != transaction.execution.preparation.Source() {
				t.Fatal("Linux staging lost exact execution preparation")
			}
			profile, err := host.capturedProofProfile()
			if err != nil || profile.ID != host.launch.chain.selection.Exit.ID || profile.APIToken != host.launch.chain.selection.Exit.APIToken {
				t.Fatal("Linux proof lost original final authority", err)
			}
		})
	}
}

func TestDesktopLinuxExecutionArgumentAdmissionKeepsSeparateCommand(t *testing.T) {
	launch, execution := desktopExecutionAttachedFixture(t, "linux")
	launch.directory = t.TempDir()
	_, meta, _, _ := execution.readPolicy()
	args := []string{launch.chain.commandName(), "--runtime-dir", launch.directory, "--session", meta.SessionID,
		"--config-sha256", meta.ConfigSHA256, "--physical-source-sha256", meta.SourceSHA256, "--physical-transfer-sha256", strings.Repeat("f", 64)}
	args, err := execution.processArguments(launch, args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateDesktopLinuxProtectedArguments(args, launch.directory); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"routervpn-node-chain", "routervpn-node-chain-socks", "routervpn-node-chain-connect", "routervpn-node"} {
		changed := append([]string(nil), args...)
		changed[0] = command
		if _, err := validateDesktopLinuxProtectedArguments(changed, launch.directory); err == nil {
			t.Fatal("execution argv borrowed another protected family", command)
		}
	}
}
