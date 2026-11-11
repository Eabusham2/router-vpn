package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

func desktopNodeChainLaunchFixture(t *testing.T, count int, target string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, selection := desktopNodeChainHostSelectionFixture(t, count)
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}

func desktopNodeChainHostSelectionFixture(t *testing.T, count int) (*app, multihopSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection
}

func TestDesktopNodeChainLaunchSealsFullSourceAndPlatform(t *testing.T) {
	for _, count := range []int{3, 4, 8} {
		for _, target := range []string{"windows", "linux", "darwin"} {
			t.Run(fmt.Sprintf("%s/%d", target, count), func(t *testing.T) {
				_, launch := desktopNodeChainLaunchFixture(t, count, target)
				if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
					t.Fatal(err)
				}
				policy, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.chain.input)
				if err != nil || policy.Config() != string(launch.config) || !reflect.DeepEqual(policy.Metadata(), launch.chain.policy.Metadata()) ||
					len(policy.NodeChain().ProofInventory()) != count || policy.Metadata().TargetOS != target {
					t.Fatal("child replay changed the full source or exact platform projection", err)
				}
				budget, err := desktopNodeReadyBudget(launch)
				if err != nil || budget != time.Duration(35+10*count)*time.Second {
					t.Fatal("readiness did not retain the bounded complete proof inventory", budget, err)
				}
			})
		}
	}
	if budget, err := desktopNodeReadyBudget(&desktopNodeLaunch{}); err != nil || budget != 25*time.Second {
		t.Fatal("ordinary native readiness budget changed")
	}
}

func TestDesktopNodeChainLaunchRejectsCrossFamilyAndSourceSubstitution(t *testing.T) {
	for _, fault := range []string{"config", "session", "middle", "source", "profile", "imported", "truncated", "platform"} {
		t.Run(fault, func(t *testing.T) {
			_, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
			switch fault {
			case "config":
				launch.config = append(launch.config, '\n')
			case "session":
				launch.mtuSession = strings.Repeat("f", 32)
			case "middle":
				launch.chain.selection.Nodes[1].Profile.APIToken = "replacement-middle-credential"
			case "source":
				launch.chain.input += "\n"
			case "profile":
				launch.profileID = launch.chain.selection.Entry.ID
			case "imported":
				launch.importedEntry = true
			case "truncated":
				launch.chain.selection.Nodes = launch.chain.selection.Nodes[:2]
			case "platform":
				other, err := mobilemultihop.NewDesktopNodeChainPolicy(launch.chain.selection.Native.chain.chain, launch.mtuSession, "linux", 0)
				if err != nil {
					t.Fatal(err)
				}
				launch.chain.policy = other
			}
			if validateDesktopNodeChainLaunch(context.Background(), launch) == nil {
				t.Fatal("altered ordered native source remained valid")
			}
		})
	}
}

func desktopNodeChainReadyFixture(t *testing.T, launch *desktopNodeLaunch) (mobilemultihop.DesktopNodeChainReadyRecord, desktopNodeMTURecord, time.Time) {
	t.Helper()
	_, meta, capture, err := launch.chain.policy.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record := mobilemultihop.DesktopNodeChainReadyRecord{Schema: 1, Kind: "routervpn-node-chain-ready-v1",
		SourceSHA256: meta.SourceSHA256, TransferSHA256: strings.Repeat("b", 64), DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
		Identity: mobilemultihop.NodeChainIdentity{EngineID: "original-engine", SessionID: meta.SessionID, NetworkID: "original-network",
			SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256}, Generation: 1, Reader: 1,
		InterfaceName: "router-vpn", InterfaceIndex: 91, MTU: capture.ConfiguredMTU, ObservedAt: now.UnixMilli()}
	if meta.RestoredMTU != 0 {
		record.MTU = meta.RestoredMTU
	}
	live := desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256, Path: strings.Repeat("c", 64),
		Reader: record.Reader, Interface: record.InterfaceName, Index: int(record.InterfaceIndex), MTU: record.MTU, Heartbeat: now.UnixMilli()}
	return record, live, now
}

func TestDesktopNodeChainReadyPinsProofGenerationAndActualReader(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	record, live, now := desktopNodeChainReadyFixture(t, launch)
	started := now.Add(-time.Second)
	if err := validateDesktopNodeChainReady(record, live, started, now, nil, true); err != nil {
		t.Fatal(err)
	}
	next, changed := record, live
	next.Generation, next.Reader, next.InterfaceIndex, next.MTU = 2, 2, 92, 1300
	changed.Reader, changed.Index, changed.MTU, changed.Generation, changed.Active = 2, 92, 1300, 2, true
	if err := validateDesktopNodeChainReady(next, changed, started, now, &record, false); err != nil {
		t.Fatal("fresh proof could not follow exact original native reader replacement:", err)
	}
	for _, fault := range []string{"engine", "network", "source", "config", "session", "dns", "transfer", "generation", "generation-jump", "reader", "index", "mtu", "old-proof", "future", "stale", "before-start", "fresh-after-replacement", "initial-active", "failure"} {
		t.Run(fault, func(t *testing.T) {
			r, m, fresh, captured := next, changed, false, &record
			switch fault {
			case "engine":
				r.Identity.EngineID = "replacement-engine"
			case "network":
				r.Identity.NetworkID = "replacement-network"
			case "source":
				r.Identity.SourceSHA256 = strings.Repeat("e", 64)
			case "config":
				r.Identity.ConfigSHA256 = strings.Repeat("e", 64)
			case "session":
				r.Identity.SessionID = strings.Repeat("e", 32)
			case "dns":
				r.DNSConfigSHA256 = strings.Repeat("e", 64)
			case "transfer":
				r.TransferSHA256 = strings.Repeat("e", 64)
			case "generation":
				r.Generation = 1
			case "generation-jump":
				r.Generation = 3
			case "reader":
				r.Reader = 1
			case "index":
				r.InterfaceIndex++
			case "mtu":
				r.MTU++
			case "old-proof":
				r, m, captured = record, live, &next
			case "future":
				r.ObservedAt = now.Add(time.Second).UnixMilli()
			case "stale":
				r.ObservedAt = now.Add(-3 * time.Second).UnixMilli()
			case "before-start":
				r.ObservedAt = started.Add(-time.Millisecond).UnixMilli()
			case "fresh-after-replacement":
				fresh = true
			case "initial-active":
				r, m, captured, fresh = record, live, nil, true
				m.Active = true
			case "failure":
				m.Failure = "captured TUN operation rejected"
			}
			if validateDesktopNodeChainReady(r, m, started, now, captured, fresh) == nil {
				t.Fatal("stale or substituted proof/reader was accepted")
			}
		})
	}
}

func TestDesktopNodeChainReadyRequiresCanonicalPrivateHeartbeat(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	record, live, now := desktopNodeChainReadyFixture(t, launch)
	started := now.Add(-time.Second)
	if _, err := readDesktopNodeChainReadyContext(context.Background(), launch, record.TransferSHA256, started, true, live); !os.IsNotExist(err) {
		t.Fatal("missing actual heartbeat supplied readiness", err)
	}
	body, err := mobilemultihop.CanonicalDesktopNodeChainReadyRecord(record, launch.chain.policy, record.TransferSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "node-chain-ready.json", body, false); err != nil {
		t.Fatal(err)
	}
	if _, err := readDesktopNodeChainReadyContext(context.Background(), launch, record.TransferSHA256, started, true, live); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readDesktopNodeChainReadyContext(canceled, launch, record.TransferSHA256, started, false, live); err == nil {
		t.Fatal("canceled reader published readiness")
	}
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	object["replacement"] = true
	foreign, _ := json.Marshal(object)
	if err := launch.directoryRoot.Remove("node-chain-ready.json"); err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "node-chain-ready.json", foreign, false); err != nil {
		t.Fatal(err)
	}
	if _, err := readDesktopNodeChainReadyContext(context.Background(), launch, record.TransferSHA256, started, false, live); err == nil {
		t.Fatal("noncanonical heartbeat remained ready")
	}
}

func TestDesktopNodeChainProtectionAndCommandKeepExactFamily(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 3, "windows")
	policy := launch.chain.policy
	selection, err := desktopProtectionSelectionForAllCaptured(nil, nil, nil, policy)
	if err != nil || selection.source != policy.Metadata().SourceSHA256 || selection.policy != policy.Metadata().KillSwitchPolicy {
		t.Fatal(err)
	}
	if _, err := desktopProtectionSelectionForAllCaptured(&mobilemultihop.DesktopNodePolicy{}, nil, nil, policy); err == nil {
		t.Fatal("mixed concrete policy families accepted")
	}
	owned := &desktopOwnedNodeRuntime{chain: launch.chain}
	launch.ownedNode = owned
	attempt := &desktopNodeProtectionAttempt{launch: launch, chain: policy}
	if !attempt.matchesOwned(owned) {
		t.Fatal("exact chain protection was rejected")
	}
	attempt.imported = &mobilemultihop.DesktopImportedPolicy{}
	if attempt.matchesOwned(owned) {
		t.Fatal("chain borrowed imported protection")
	}
	args := []string{"routervpn-node-chain", "--runtime-dir", t.TempDir(), "--session", launch.mtuSession,
		"--config-sha256", launch.configSHA256, "--physical-source-sha256", policy.Metadata().SourceSHA256,
		"--physical-transfer-sha256", strings.Repeat("b", 64)}
	if _, err := validateDesktopNodeChainProcessArguments(args, args[2]); err != nil {
		t.Fatal(err)
	}
	args[7] = "--imported-source-sha256"
	if _, err := validateDesktopNodeChainProcessArguments(args, args[2]); err == nil {
		t.Fatal("ordered command borrowed imported source flag")
	}
}

func TestDesktopNodeChainWorkspaceRetainsFullBoundAndJoinedFiles(t *testing.T) {
	launch := &desktopNodeLaunch{}
	directory := filepath.Join(t.TempDir(), "original-chain")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if launch.directoryRoot != nil {
			_ = launch.directoryRoot.Close()
		}
	})
	oversized := make([]byte, mobilemultihop.NodeChainInputLimit+1)
	if err := writeDesktopRuntimeFileContext(context.Background(), launch, "node-chain-source.json", oversized, false); err == nil {
		t.Fatal("ordered source exceeded its aggregate forty MiB bound")
	}
	if _, err := os.Stat(filepath.Join(directory, "node-chain-source.json")); !os.IsNotExist(err) {
		t.Fatal("oversized source entered private publication", err)
	}
	// This source is intentionally above the ordinary eight MiB file limit;
	// source parsing remains the sealed launch constructor's separate guard.
	if err := writeDesktopRuntimeFileContext(context.Background(), launch, "node-chain-source.json", oversized[:8<<20+1], false); err != nil {
		t.Fatal("complete ordered input was truncated to the ordinary file bound", err)
	}
	for _, name := range []string{"node-chain-ready.json", ".node-chain-ready.json.pending"} {
		if err := writeDesktopRuntimeFile(launch, name, []byte(`{}`), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupDesktopNodeLaunch(launch); err != nil {
		t.Fatal("original joined files were retained as foreign", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("original private directory remained after cleanup", err)
	}
}

func TestDesktopNodeChainDarwinReadyAllowsOnlyAdvancedUTUNReader(t *testing.T) {
	_, launch := desktopNodeChainLaunchFixture(t, 3, "darwin")
	original, live, now := desktopNodeChainReadyFixture(t, launch)
	original.InterfaceName, live.Interface = "utun991", "utun991"
	started := now.Add(-time.Second)
	if err := validateDesktopNodeChainReadyForTarget("darwin", original, live, started, now, nil, true); err != nil {
		t.Fatal("fresh original Darwin reader was rejected", err)
	}
	next, changed := original, live
	next.Generation, next.Reader, next.InterfaceName, next.InterfaceIndex, next.MTU = 2, 2, "utun992", 92, 1392
	changed.Reader, changed.Interface, changed.Index, changed.MTU, changed.Generation, changed.Active = 2, "utun992", 92, 1392, 1, true
	if err := validateDesktopNodeChainReadyForTarget("darwin", next, changed, started, now, &original, false); err != nil {
		t.Fatal("proved Darwin replacement was forced to reuse a retired utun name", err)
	}
	rollback, restored := next, changed
	rollback.Generation, rollback.Reader, rollback.InterfaceName, rollback.InterfaceIndex, rollback.MTU = 3, 3, "utun993", 93, original.MTU
	restored.Reader, restored.Interface, restored.Index, restored.MTU, restored.Active, restored.Restored = 3, "utun993", 93, original.MTU, false, true
	if err := validateDesktopNodeChainReadyForTarget("darwin", rollback, restored, started, now, &next, false); err != nil {
		t.Fatal("proved rollback lost its actual replacement utun", err)
	}
	for _, target := range []string{"windows", "linux", ""} {
		if validateDesktopNodeChainReadyForTarget(target, next, changed, started, now, &original, false) == nil {
			t.Fatal("Darwin name succession weakened the fixed-interface target", target)
		}
	}
	for _, fault := range []string{"same-reader", "same-generation", "wrong-generation", "live-name", "non-utun", "empty-suffix", "invalid-suffix", "transfer", "identity", "dns", "fresh"} {
		t.Run(fault, func(t *testing.T) {
			r, m, fresh := next, changed, false
			switch fault {
			case "same-reader":
				r.Reader, m.Reader, r.Generation = original.Reader, original.Reader, original.Generation
			case "same-generation":
				r.Generation = original.Generation
			case "wrong-generation":
				r.Generation++
			case "live-name":
				m.Interface = "utun994"
			case "non-utun":
				r.InterfaceName, m.Interface = "en7", "en7"
			case "empty-suffix":
				r.InterfaceName, m.Interface = "utun", "utun"
			case "invalid-suffix":
				r.InterfaceName, m.Interface = "utunX", "utunX"
			case "transfer":
				r.TransferSHA256 = strings.Repeat("e", 64)
			case "identity":
				r.Identity.EngineID = "replacement-engine"
			case "dns":
				r.DNSConfigSHA256 = strings.Repeat("e", 64)
			case "fresh":
				fresh = true
			}
			if validateDesktopNodeChainReadyForTarget("darwin", r, m, started, now, &original, fresh) == nil {
				t.Fatal("Darwin reader succession accepted missing original proof authority")
			}
		})
	}
}
