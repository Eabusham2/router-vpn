package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopExecutionAttachedFixture(t *testing.T, target string) (*desktopNodeLaunch, *desktopNodeChainExecutionLaunch) {
	t.Helper()
	_, launch := desktopNodeChainLaunchFixture(t, 2, target)
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.attach(launch); err != nil {
		t.Fatal(err)
	}
	return launch, execution
}

func TestDesktopNodeChainExecutionAttachmentKeepsOriginalPhysicalAuthority(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		t.Run(target, func(t *testing.T) {
			launch, execution := desktopExecutionAttachedFixture(t, target)
			original := execution.original.policy
			if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
				t.Fatal(err)
			}
			physical, err := launch.chain.physicalPolicy()
			if err != nil || physical != execution.physical || physical == nil || original.Config() == string(launch.config) ||
				launch.chain.commandName() != "routervpn-node-chain-execution" || launch.chain.sourceName() != "node-chain-execution-source.json" ||
				launch.chain.ready != nil || launch.chain.execution != execution {
				t.Fatal("execution borrowed Local construction/readiness or another physical owner", err)
			}
			if _, err := launch.chain.parseReady([]byte(`{}`), strings.Repeat("f", 64)); err == nil {
				t.Fatal("execution entered ordinary Local readiness parser")
			}
			if err := execution.attach(launch); err == nil {
				t.Fatal("execution replaced already attached launch")
			}
			launch.chain.execution = nil
			if err := validateDesktopNodeChainLaunch(context.Background(), launch); err == nil || execution.bound(launch) == nil {
				t.Fatal("execution config survived removal of original typed authority")
			}
		})
	}
}

func TestDesktopNodeChainExecutionCommandPinsCapturedDigests(t *testing.T) {
	launch, execution := desktopExecutionAttachedFixture(t, "windows")
	launch.directory = filepath.Join(t.TempDir(), "original")
	_, meta, _, _ := execution.readPolicy()
	base := []string{launch.chain.commandName(), "--runtime-dir", launch.directory, "--session", meta.SessionID,
		"--config-sha256", meta.ConfigSHA256, "--physical-source-sha256", meta.SourceSHA256, "--physical-transfer-sha256", strings.Repeat("e", 64)}
	valid, err := execution.processArguments(launch, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"command", "session", "config", "physical", "execution", "duplicate", "missing", "imported", "mtu"} {
		t.Run(fault, func(t *testing.T) {
			args := append([]string(nil), valid...)
			switch fault {
			case "command":
				args[0] = "routervpn-node-chain"
			case "session":
				args[4] = strings.Repeat("b", 32)
			case "config":
				args[6] = strings.Repeat("b", 64)
			case "physical":
				args[8] = strings.Repeat("b", 64)
			case "execution":
				args[12] = strings.Repeat("b", 64)
			case "duplicate":
				args = append(args, "--execution-source-sha256", args[12])
			case "missing":
				args = args[:11]
			case "imported":
				args[7] = "--imported-source-sha256"
			case "mtu":
				args = append(args, "--physical-mtu", "1400")
			}
			if _, err := execution.validateProcessArguments(launch, args); err == nil {
				t.Fatal("foreign native execution argv admitted")
			}
		})
	}
}

// These exercise original protection-source retention, not Windows BFE/TUN.
func TestDesktopNodeChainExecutionProtectionPinsPreparation(t *testing.T) {
	for _, fault := range []string{"original", "omitted", "different-preparation", "foreign-launch", "local-config", "mixed-source"} {
		t.Run(fault, func(t *testing.T) {
			launch, execution := desktopExecutionAttachedFixture(t, "windows")
			owned := &desktopOwnedNodeRuntime{chain: launch.chain}
			attempt := &desktopNodeProtectionAttempt{launch: launch, chain: launch.chain.policy, execution: execution}
			_, other := desktopExecutionAttachedFixture(t, "windows")
			switch fault {
			case "omitted":
				attempt.execution = nil
			case "different-preparation":
				attempt.execution = other
			case "foreign-launch":
				attempt.launch = &desktopNodeLaunch{chain: launch.chain}
			case "local-config":
				launch.configSHA256 = launch.chain.policy.Metadata().ConfigSHA256
			case "mixed-source":
				attempt.policy = &mobilemultihop.DesktopNodePolicy{}
			}
			selected, err := attempt.selection()
			if fault == "original" {
				if err != nil || selected.config != execution.preparation.ConfigSHA256() || !attempt.matchesOwned(owned) {
					t.Fatal("original execution protection lost exact preparation", err)
				}
			} else if err == nil {
				t.Fatal("foreign execution protection source accepted")
			}
		})
	}
}
