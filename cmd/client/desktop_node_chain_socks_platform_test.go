package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopSOCKSPlatformFixture(t *testing.T, mode, target string) (*app, multihopSelection, *desktopNodeLaunch) {
	t.Helper()
	a, selection, _ := desktopSOCKSParentFixture(t, mode)
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection, launch
}

func TestDesktopSOCKSOwnedParentRetainsStartProofAndJoinedRetirement(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, selected, _ := desktopSOCKSPlatformFixture(t, mode, "windows")
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selected)
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			owned := f.launch.ownedNode
			if f.starts != 1 || f.launch.chain.policy != nil || owned.attempt.chain != nil || owned.attempt.socksChain != f.launch.chain.socksPolicy || !owned.attempt.matchesOwned(owned) || !f.kernel.locked || owned.ready == nil || f.launch.chain.ready == nil {
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

func TestDesktopSOCKSProtectionRejectsForeignAndMixedOwners(t *testing.T) {
	for _, fault := range []string{"foreign-policy", "ordinary-policy", "foreign-source", "foreign-attempt", "foreign-launch", "wrong-command"} {
		t.Run(fault, func(t *testing.T) {
			a, selected, _ := desktopSOCKSPlatformFixture(t, "wg", "windows")
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selected)
			launch := f.launch
			original := launch.chain.socksPolicy
			_, _, foreign := desktopSOCKSPlatformFixture(t, "wg", "windows")
			switch fault {
			case "foreign-policy":
				launch.chain.socksPolicy = foreign.chain.socksPolicy
			case "ordinary-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "windows")
				launch.chain.policy = ordinary.chain.policy
			case "foreign-source":
				launch.chain.selection.Native.chain.socks.source = foreign.chain.selection.Native.chain.socks.source
			case "foreign-attempt":
				attempt := &desktopNodeProtectionAttempt{launch: launch, socksChain: foreign.chain.socksPolicy}
				if attempt.matchesOwned(launch.ownedNode) {
					t.Fatal("foreign typed attempt adopted original owner")
				}
				return
			case "foreign-launch":
				attempt := &desktopNodeProtectionAttempt{launch: foreign, socksChain: original}
				if attempt.matchesOwned(launch.ownedNode) {
					t.Fatal("foreign typed launch adopted original owner")
				}
				return
			case "wrong-command":
				if _, err := validateDesktopNodeChainProcessArguments([]string{"routervpn-node-chain-socks"}, t.TempDir()); err == nil {
					t.Fatal("ordinary child accepted typed command")
				}
				if _, err := validateDesktopNodeChainSOCKSProcessArguments([]string{"routervpn-node-chain"}, t.TempDir()); err == nil {
					t.Fatal("typed child accepted ordinary command")
				}
				directory := t.TempDir()
				arguments := []string{"routervpn-node-chain-socks", "--runtime-dir", directory, "--session", strings.Repeat("a", 32),
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
			if _, err := f.a.nodeProtection.beginNodeChainSOCKS(context.Background(), launch, original); err == nil || f.kernel.reads != 0 {
				t.Fatal("foreign typed source reached protection backend", err)
			}
		})
	}
}

func TestDesktopSOCKSPhysicalPolicyKeepsConcreteFamily(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			_, _, launch := desktopSOCKSPlatformFixture(t, "awg2-strong", target)
			physical, err := launch.chain.physicalPolicy()
			if err != nil || physical != launch.chain.socksPolicy {
				t.Fatal("physical projection replaced sealed typed owner", err)
			}
			_, _, capture, err := mobilemultihop.ReadDesktopPhysicalPolicy(physical)
			if err != nil || len(capture.PhysicalRoots) != 1 {
				t.Fatal("typed platform expanded physical roots", err)
			}
			copiedSource := *launch.chain.selection.Native.chain.socks.source
			launch.chain.selection.Native.chain.socks.source = &copiedSource
			if _, _, _, err := launch.chain.readLaunchPolicy(); err == nil {
				t.Fatal("equal copied typed source replaced original launch authority")
			}
		})
	}
}
