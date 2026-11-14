package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopCONNECTPlatformFixture(t *testing.T, mode, target string) (*app, multihopSelection, *desktopNodeLaunch) {
	t.Helper()
	a, selection, _ := desktopCONNECTParentFixture(t, mode)
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection, launch
}

func TestDesktopCONNECTOwnedParentRetainsStartProofAndJoinedRetirement(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, selected, _ := desktopCONNECTPlatformFixture(t, mode, "windows")
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selected)
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			owned := f.launch.ownedNode
			if f.starts != 1 || f.launch.chain.policy != nil || owned.attempt.chain != nil || owned.attempt.connectChain != f.launch.chain.connectPolicy || !owned.attempt.matchesOwned(owned) || !f.kernel.locked || owned.ready == nil || f.launch.chain.ready == nil {
				t.Fatal("typed parent did not retain actual modeled lifecycle owners")
			}
			if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopNodeChainRestore(f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			assertMTUNodeChainProvedCapture(t, f)
			cause := errors.New("original typed child still joining")
			f.processes[0].closeErr = cause
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); !errors.Is(err, cause) || owned.retired || !f.kernel.locked {
				t.Fatal("failed typed child join released original protection", err)
			}
			f.processes[0].closeErr = nil
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil || !owned.retired || f.kernel.locked || !f.processes[0].closed {
				t.Fatal("typed child did not settle original retirement", err)
			}
			<-f.pulseDone
			if err := cleanupDesktopNodeLaunch(f.launch); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopCONNECTProtectionRejectsForeignAndMixedOwners(t *testing.T) {
	for _, fault := range []string{"foreign-policy", "equal-policy", "ordinary-policy", "socks-policy", "all-policies", "foreign-source", "foreign-attempt", "equal-attempt", "foreign-launch", "wrong-command"} {
		t.Run(fault, func(t *testing.T) {
			a, selected, _ := desktopCONNECTPlatformFixture(t, "wg", "windows")
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selected)
			launch := f.launch
			original := launch.chain.connectPolicy
			originalAttempt := &desktopNodeProtectionAttempt{launch: launch, connectChain: original}
			if !originalAttempt.matchesOwned(launch.ownedNode) {
				t.Fatal("exact original CONNECT protection fixture lost its retained owner")
			}
			_, _, foreign := desktopCONNECTPlatformFixture(t, "wg", "windows")
			switch fault {
			case "foreign-policy":
				launch.chain.connectPolicy = foreign.chain.connectPolicy
			case "equal-policy", "equal-attempt":
				replay, err := mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(launch.chain.input)
				if err != nil || replay == original || replay.Config() != original.Config() {
					t.Fatal("equal-byte foreign policy fixture changed source bytes", err)
				}
				if fault == "equal-attempt" {
					attempt := &desktopNodeProtectionAttempt{launch: launch, connectChain: replay}
					if attempt.matchesOwned(launch.ownedNode) {
						t.Fatal("replayed equal-byte policy replaced original protection owner")
					}
					return
				}
				launch.chain.connectPolicy = replay
			case "ordinary-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "windows")
				launch.chain.policy = ordinary.chain.policy
			case "socks-policy", "all-policies":
				_, _, socks := desktopSOCKSPlatformFixture(t, "wg", "windows")
				launch.chain.socksPolicy = socks.chain.socksPolicy
				if fault == "all-policies" {
					_, ordinary := desktopNodeChainLaunchFixture(t, 3, "windows")
					launch.chain.policy = ordinary.chain.policy
				}
				if launch.chain.hasPolicy() || launch.chain.commandName() != "" || launch.chain.sourceName() != "" || launch.chain.readyName() != "" || launch.chain.macOSFamily() != "" {
					t.Fatal("mixed typed policies selected a child family")
				}
			case "foreign-source":
				launch.chain.selection.Native.chain.connect.source = foreign.chain.selection.Native.chain.connect.source
			case "foreign-attempt":
				attempt := &desktopNodeProtectionAttempt{launch: launch, connectChain: foreign.chain.connectPolicy}
				if attempt.matchesOwned(launch.ownedNode) {
					t.Fatal("foreign typed attempt adopted original owner")
				}
				return
			case "foreign-launch":
				attempt := &desktopNodeProtectionAttempt{launch: foreign, connectChain: original}
				if attempt.matchesOwned(launch.ownedNode) {
					t.Fatal("foreign typed launch adopted original owner")
				}
				return
			case "wrong-command":
				if _, err := validateDesktopNodeChainProcessArguments([]string{"routervpn-node-chain-connect"}, t.TempDir()); err == nil {
					t.Fatal("ordinary child accepted typed command")
				}
				if _, err := validateDesktopNodeChainCONNECTProcessArguments([]string{"routervpn-node-chain"}, t.TempDir()); err == nil {
					t.Fatal("typed child accepted ordinary command")
				}
				directory := t.TempDir()
				arguments := []string{"routervpn-node-chain-connect", "--runtime-dir", directory, "--session", strings.Repeat("a", 32),
					"--config-sha256", strings.Repeat("b", 64), "--physical-source-sha256", strings.Repeat("c", 64), "--physical-transfer-sha256", strings.Repeat("d", 64)}
				command := exec.Command("unused-native-image", arguments...)
				command.Dir = directory
				if actual, err := nativeMultihopRuntimeDirFromCommand(command); err != nil || actual != directory {
					t.Fatal("typed DNS runtime lost exact validated child directory", err)
				}
				command.Args[3] = t.TempDir()
				if _, err := nativeMultihopRuntimeDirFromCommand(command); err == nil {
					t.Fatal("typed DNS runtime adopted foreign directory flag")
				}
				command.Args[3] = directory
				command.Args[8] = "--imported-source-sha256"
				if _, err := nativeMultihopRuntimeDirFromCommand(command); err == nil {
					t.Fatal("typed DNS runtime borrowed imported source authority")
				}
				return
			}
			if _, _, _, err := launch.chain.readLaunchPolicy(); err == nil {
				t.Fatal("validated launch adopted a mixed or foreign original source")
			}
			if _, err := launch.ownedNode.physicalPolicy(); err == nil {
				t.Fatal("mixed or foreign physical source accepted")
			}
			if _, err := f.a.nodeProtection.beginNodeChainCONNECT(context.Background(), launch, original); err == nil || f.kernel.reads != 0 {
				t.Fatal("foreign typed source reached protection backend", err)
			}
		})
	}
}

func TestDesktopCONNECTPhysicalPolicyKeepsConcreteFamily(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			_, _, launch := desktopCONNECTPlatformFixture(t, "awg2-strong", target)
			physical, err := launch.chain.physicalPolicy()
			if err != nil || physical != launch.chain.connectPolicy {
				t.Fatal("physical projection replaced sealed typed owner", err)
			}
			_, _, capture, err := mobilemultihop.ReadDesktopPhysicalPolicy(physical)
			if err != nil || len(capture.PhysicalRoots) != 1 {
				t.Fatal("typed platform expanded physical roots", err)
			}
			copiedSource := *launch.chain.selection.Native.chain.connect.source
			launch.chain.selection.Native.chain.connect.source = &copiedSource
			if _, _, _, err := launch.chain.readLaunchPolicy(); err == nil {
				t.Fatal("equal copied typed source replaced original launch authority")
			}
		})
	}
}
