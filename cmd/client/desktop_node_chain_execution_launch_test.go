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
	"router-vpn/internal/routechoice"
)

func TestDesktopNodeChainExecutionOwnedFreshSourceObservation(t *testing.T) {
	for _, fault := range []string{"original", "raw-packet-asset", "member-token", "config", "session", "profile", "private-input", "mixed-policy", "host-pointer", "network", "nil-preparation", "copied-physical"} {
		t.Run(fault, func(t *testing.T) {
			f, session := prepareDesktopImportedPrefixExecutionModel(t, 8, "server", "server")
			launch := session.launch
			before, err := readValidatedDesktopOwnedNodeChainSourceContext(context.Background(), launch)
			if err != nil || before.policy != session.execution.physical || len(before.metadata.Prefixes) != 8 || before.physical.ConfigSHA256 != launch.configSHA256 {
				t.Fatal("fresh execution observation lost exact full source or physical owner", err)
			}
			switch fault {
			case "raw-packet-asset":
				path := filepath.Join(clientRoot(f.a), "generated", f.selection.Nodes[5].Profile.ID, "wg", "wg.conf")
				raw, err := os.ReadFile(path)
				if err != nil || os.WriteFile(path, append(raw, '\n'), 0600) != nil {
					t.Fatal("changed-asset fixture failed", err)
				}
			case "member-token":
				launch.chain.selection.Nodes[5].Profile.APIToken += "-replacement"
			case "config":
				launch.config = append(launch.config, '\n')
			case "session":
				launch.mtuSession = strings.Repeat("e", 32)
			case "profile":
				launch.policyProfileID = launch.chain.selection.Entry.ID
			case "private-input":
				launch.ownedNode.source = append(launch.ownedNode.source, '\n')
			case "mixed-policy":
				launch.ownedNode.policy = &mobilemultihop.DesktopNodePolicy{}
			case "host-pointer":
				copy := *launch.chain.capture
				launch.chain.capture = &copy
			case "network":
				launch.ownedNode.network += "-replacement"
			case "nil-preparation":
				session.execution.preparation = nil
			case "copied-physical":
				copy := *session.execution.physical
				session.execution.physical = &copy
			}
			after, err := readValidatedDesktopOwnedNodeChainSourceContext(context.Background(), launch)
			if fault != "original" {
				if err == nil || !reflect.DeepEqual(after, desktopExecutionSourceObservation{}) {
					t.Fatal("earlier observation authorized changed raw source, launch or physical owner", fault, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("same captured source changed between fresh observations", err)
			}
			before.metadata.Prefixes[0].ProfileID = "caller-replacement"
			before.capture.PhysicalRoots[0].Tag = "caller-replacement"
			again, err := readValidatedDesktopOwnedNodeChainSourceContext(context.Background(), launch)
			if err != nil || !reflect.DeepEqual(again, after) {
				t.Fatal("caller changed original source or another fresh physical observation", err)
			}
		})
	}
}

func TestDesktopNodeChainExecutionSourceKeepsCapturedPairedGraph(t *testing.T) {
	for count := 2; count <= 8; count++ {
		for _, target := range []string{"linux", "windows", "darwin"} {
			for _, requested := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%s/%s/%d", target, requested, count), func(t *testing.T) {
					_, launch := desktopNodeChainLaunchFixture(t, count, target)
					execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
					if err != nil {
						t.Fatal(err)
					}
					config, meta, capture, err := execution.readPolicy()
					if err != nil || config != execution.preparation.Config() || meta.ConfigSHA256 != execution.preparation.ConfigSHA256() || meta.SourceSHA256 != launch.chain.policy.Metadata().SourceSHA256 || len(meta.Prefixes) != count || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || capture.SelectedDNS.Physical {
						t.Fatal("execution replanned original source or selected DNS", err)
					}
					original, err := execution.physical.OriginalDesktopPolicy()
					if err != nil || original != launch.chain.policy || original.OriginalChain() != launch.chain.selection.Native.chain.chain {
						t.Fatal("execution borrowed another physical owner", err)
					}
					if execution.preparation.Execution() != requested || execution.preparation.LocalSource() == "" || config == launch.chain.policy.Config() {
						t.Fatal("execution failed to retain distinct gated construction")
					}
				})
			}
		}
	}
}

func TestDesktopNodeChainExecutionSourceRejectsReplacementAuthority(t *testing.T) {
	for _, fault := range []string{"policy", "preparation", "copied-preparation", "copied-physical", "member", "local"} {
		t.Run(fault, func(t *testing.T) {
			target := "linux"
			_, launch := desktopNodeChainLaunchFixture(t, 3, target)
			requested := "auto"
			if fault == "local" {
				requested = "local"
			}
			execution, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
			if fault == "local" {
				if err == nil {
					t.Fatal("unimplemented execution family admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "policy":
				launch.chain.policy, err = mobilemultihop.NewDesktopNodeChainPolicy(launch.chain.policy.OriginalChain(), launch.mtuSession, target, 0)
			case "preparation":
				execution.preparation, err = mobilemultihop.NewDesktopNodeChainExecutionPreparation(launch.chain.policy, "auto")
			case "copied-preparation":
				copy := *execution.preparation
				execution.preparation = &copy
			case "copied-physical":
				copy := *execution.physical
				execution.physical = &copy
			case "member":
				launch.chain.selection.Nodes[1].Profile.APIToken = "replacement-secret"
			}
			if err != nil {
				t.Fatal(err)
			}
			if execution.validateSource() == nil {
				t.Fatal("equal bytes or changed member replaced original execution authority")
			}
			if policy, err := execution.physicalPolicy(); err == nil || policy != nil {
				t.Fatal("failed source read exposed a physical owner", err)
			}
			if config, _, _, err := execution.readPolicy(); err == nil || config != "" {
				t.Fatal("failed source read exposed executable policy", err)
			}
		})
	}
}

func TestDesktopNodeChainExecutionReadyPinsAdoptionAndPreparationMTU(t *testing.T) {
	now := time.Now()
	candidate := routechoice.Candidate{Execution: routechoice.Server, Transport: "ordered-node-chain", EntryID: "entry", ExitID: "exit"}
	record := mobilemultihop.DesktopNodeChainExecutionReadyRecord{SourceSHA256: strings.Repeat("a", 64), PreparationSourceSHA256: strings.Repeat("b", 64), PreparationConfigSHA256: strings.Repeat("c", 64), TransferSHA256: strings.Repeat("d", 64), DNSConfigSHA256: strings.Repeat("e", 64), Identity: mobilemultihop.NodeChainIdentity{EngineID: "original", SessionID: strings.Repeat("a", 32), NetworkID: "original-network", SourceSHA256: strings.Repeat("f", 64), ConfigSHA256: strings.Repeat("1", 64)}, SelectionEpoch: 7, Generation: 1, Reader: 1, InterfaceName: "router-vpn", InterfaceIndex: 19, MTU: 1420, ObservedAt: now.UnixMilli(), Progress: mobilemultihop.NodeChainExecutionProgress{NodeChainProgress: mobilemultihop.NodeChainProgress{Execution: "server"}, Comparison: routechoice.Result{Target: mobilemultihop.Targets[0], Winner: &candidate}}}
	live := desktopNodeMTURecord{Session: record.Identity.SessionID, Config: record.PreparationConfigSHA256, Reader: 1, Interface: record.InterfaceName, Index: 19, MTU: 1420}
	started := now.Add(-time.Second)
	if err := validateDesktopNodeChainExecutionReady(record, live, started, now, nil, true, "linux"); err != nil {
		t.Fatal(err)
	}
	next, changed := record, live
	next.Generation, next.Reader, next.SelectionEpoch, next.MTU, next.InterfaceIndex = 2, 2, 8, 1300, 20
	changed.Reader, changed.Index, changed.MTU = 2, 20, 1300
	if err := validateDesktopNodeChainExecutionReady(next, changed, started, now, &record, false, "linux"); err != nil {
		t.Fatal("exact original MTU successor rejected", err)
	}
	faults := map[string]func(*mobilemultihop.DesktopNodeChainExecutionReadyRecord, *desktopNodeMTURecord){
		"projected-config-as-mtu": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, l *desktopNodeMTURecord) {
			l.Config = r.Identity.ConfigSHA256
		},
		"engine": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.Identity.EngineID = "replacement"
		},
		"network": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.Identity.NetworkID = "replacement"
		},
		"session": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.Identity.SessionID = strings.Repeat("b", 32)
		},
		"epoch-away-back": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.SelectionEpoch++
		},
		"new-winner": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.Progress.Comparison.Winner.Execution = routechoice.Local
		},
		"new-target": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.Progress.Comparison.Target = mobilemultihop.Targets[1]
		},
		"stale": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.ObservedAt = now.Add(-3 * time.Second).UnixMilli()
		},
		"future": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, _ *desktopNodeMTURecord) {
			r.ObservedAt = now.Add(time.Second).UnixMilli()
		},
		"unproved-reader": func(r *mobilemultihop.DesktopNodeChainExecutionReadyRecord, l *desktopNodeMTURecord) {
			r.Reader++
			l.Reader++
		},
	}
	for name, mutate := range faults {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(record)
			var changed mobilemultihop.DesktopNodeChainExecutionReadyRecord
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			readback := live
			mutate(&changed, &readback)
			if validateDesktopNodeChainExecutionReady(changed, readback, started, now, &record, false, "linux") == nil {
				t.Fatal("replacement observation admitted")
			}
		})
	}
}

func TestDesktopNodeChainExecutionReadyAllowsOnlyCapturedDarwinSuccessor(t *testing.T) {
	now := time.Now()
	candidate := routechoice.Candidate{Execution: routechoice.Server, Transport: "ordered-node-chain", EntryID: "entry", ExitID: "exit"}
	previous := mobilemultihop.DesktopNodeChainExecutionReadyRecord{Identity: mobilemultihop.NodeChainIdentity{SessionID: "session"},
		PreparationConfigSHA256: "config", SelectionEpoch: 1, Generation: 1, Reader: 1, InterfaceName: "utun7", InterfaceIndex: 7, MTU: 1280, ObservedAt: now.UnixMilli(),
		Progress: mobilemultihop.NodeChainExecutionProgress{NodeChainProgress: mobilemultihop.NodeChainProgress{Execution: "server"}, Comparison: routechoice.Result{Target: mobilemultihop.Targets[0], Winner: &candidate}}}
	for _, fault := range []string{"original", "linux", "windows", "unknown", "same-reader", "unproved-generation", "bad-name", "same-reader-renamed"} {
		t.Run(fault, func(t *testing.T) {
			next := previous
			next.Generation, next.Reader, next.SelectionEpoch, next.InterfaceName, next.InterfaceIndex = 2, 2, 2, "utun8", 8
			target := "darwin"
			switch fault {
			case "linux", "windows", "unknown":
				target = fault
			case "same-reader":
				next.Reader = 1
			case "unproved-generation":
				next.Generation = 1
			case "bad-name":
				next.InterfaceName = "utun８"
			case "same-reader-renamed":
				next.Reader, next.Generation, next.SelectionEpoch = 1, 1, 1
			}
			live := desktopNodeMTURecord{Session: next.Identity.SessionID, Config: next.PreparationConfigSHA256, Reader: next.Reader, Interface: next.InterfaceName, Index: int(next.InterfaceIndex), MTU: next.MTU}
			err := validateDesktopNodeChainExecutionReady(next, live, now.Add(-time.Second), now, &previous, false, target)
			if (err == nil) != (fault == "original") {
				t.Fatal("wrong captured target/reader admission", err)
			}
		})
	}
}
