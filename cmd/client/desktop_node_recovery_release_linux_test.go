//go:build linux

package main

import (
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// Comparison values only. The privileged fixture separately creates and joins
// an actual engine/guardian, removes its actual baseline and crashes its parent.
func linuxReleaseRecoveryComparison() (linuxprotection.ParentRecord, linuxprotection.ParentRecord, linuxprotection.JournalSelection) {
	old, current := linuxEmptyRecoveryComparison()
	guardian := linuxprotection.ProcessRecord{BootID: old.BootID, ProcessID: 110, ProcProcessID: 310,
		ParentProcessID: 109, StartTicks: 350, Image: old.Image, NetworkNamespace: old.NetworkNamespace, PIDNamespace: old.PIDNamespace}
	session := strings.Repeat("3", 32)
	target := &linuxprotection.ProtectionTarget{Policy: "on-connect", ConfigSHA256: strings.Repeat("a", 64), Guardian: guardian,
		Native: mobiletor.DesktopLinuxProtectionRecord{Capture: mobiletor.DesktopSocketCapture{SessionID: session,
			SourceSHA256: strings.Repeat("4", 64), NetworkID: strings.Repeat("5", 32)},
			Owner: mobiletor.DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("6", 64), Generation: 1, ProcessID: uint32(guardian.ProcessID)},
			UID:   55001, PermitPrefix: "rvpn_" + strings.Repeat("7", 20), TableName: "router_vpn_node_" + session,
			TableHandle: 10, ChainHandle: 11, BaselineSHA256: strings.Repeat("8", 64)}}
	revision := strings.Repeat("9", 64)
	record := linuxprotection.JournalRecord{Schema: linuxprotection.JournalRecordSchema, Kind: linuxprotection.JournalRecordKind,
		JournalID: strings.Repeat("2", 32), Sequence: 7, PreviousSHA256: strings.Repeat("b", 64), Controller: old, Phase: "intent",
		Committed: linuxprotection.JournalState{Target: target, ProfileID: "home-router", ProfileRevision: revision},
		Intent:    &linuxprotection.JournalIntent{Action: "release", RequestID: session, ProfileID: "home-router", ProfileRevision: revision, ResultProfileRevision: revision}}
	body, _ := linuxprotection.CanonicalJournalRecord(record)
	digest, _ := linuxprotection.JournalRecordSHA256(body)
	return old, current, linuxprotection.JournalSelection{Record: record, SHA256: digest, Slot: 0}
}

func TestDesktopLinuxReleaseRecoveryCheckpointComparison(t *testing.T) {
	for name, change := range map[string]func(*linuxprotection.ParentRecord, *linuxprotection.ParentRecord, *linuxprotection.JournalSelection){
		"complete-release": func(_, _ *linuxprotection.ParentRecord, _ *linuxprotection.JournalSelection) {},
		"package-upgrade": func(_, next *linuxprotection.ParentRecord, _ *linuxprotection.JournalSelection) {
			next.Root.Inode += 20
			next.Image.Inode += 20
		},
		"settled-empty": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Phase, s.Record.Intent, s.Record.Committed = "settled", nil, linuxprotection.JournalState{}
		},
		"incomplete":     func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) { s.Incomplete = true },
		"invalid-record": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) { s.Record.Schema++ },
		"controller": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Controller.Generation = strings.Repeat("d", 32)
		},
		"always-release": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Policy = "always"
			s.Record.Intent.Candidate = linuxprotection.CloneState(s.Record.Committed)
		},
		"saved-off": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.Action = "off"
			s.Record.Intent.ResultProfileRevision = strings.Repeat("e", 64)
		},
		"legacy-target": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Native.TableName = ""
		},
		"settled-target": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Phase, s.Record.Intent = "settled", nil
		},
		"missing-intent": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) { s.Record.Intent = nil },
		"missing-target": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target = nil
		},
		"engine-not-joined": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			engine := s.Record.Committed.Target.Guardian
			s.Record.Committed.Engine = &engine
		},
		"prepare": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.Action = "prepare"
		},
		"successor": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.Action = "successor"
		},
		"preparation": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.Preparation = &linuxprotection.JournalPreparation{}
		},
		"nonempty-candidate": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.Candidate = linuxprotection.CloneState(s.Record.Committed)
		},
		"request": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.RequestID = strings.Repeat("f", 32)
		},
		"profile": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.ProfileID = "another-router"
		},
		"revision": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.ProfileRevision = strings.Repeat("f", 64)
		},
		"result-revision": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Intent.ResultProfileRevision = strings.Repeat("f", 64)
		},
		"guardian-boot": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.BootID = "21111111-2222-4333-8444-555555555555"
		},
		"guardian-network": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.NetworkNamespace.Inode++
		},
		"guardian-pid-namespace": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.PIDNamespace.Inode++
		},
		"guardian-before-parent": func(old, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.StartTicks = old.StartTicks - 1
		},
		"guardian-after-restart": func(_, next *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.StartTicks = next.StartTicks + 1
		},
		"guardian-is-old-controller": func(old, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ProcessID = old.ProcessID
			s.Record.Committed.Target.Native.Owner.ProcessID = uint32(old.ProcessID)
		},
		"guardian-is-current-controller": func(_, next *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ProcessID = next.ProcessID
			s.Record.Committed.Target.Native.Owner.ProcessID = uint32(next.ProcessID)
		},
		"guardian-proc-alias-old": func(old, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ProcProcessID = old.ProcProcessID
		},
		"guardian-proc-alias-current": func(_, next *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ProcProcessID = next.ProcProcessID
		},
		"engine-is-old-controller": func(old, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ParentProcessID = old.ProcessID
		},
		"engine-is-current-controller": func(_, next *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ParentProcessID = next.ProcessID
		},
		"engine-is-guardian": func(_, _ *linuxprotection.ParentRecord, s *linuxprotection.JournalSelection) {
			s.Record.Committed.Target.Guardian.ParentProcessID = s.Record.Committed.Target.Guardian.ProcessID
		},
	} {
		t.Run(name, func(t *testing.T) {
			old, current, selected := linuxReleaseRecoveryComparison()
			change(&old, &current, &selected)
			pids, err := checkDesktopLinuxEmptyRecoveryCheckpoint(old, current, selected)
			valid := name == "complete-release" || name == "package-upgrade" || name == "settled-empty"
			if (err == nil) != valid {
				t.Fatal("release comparison changed its complete original-state boundary", err)
			}
			if valid {
				want := []int{old.ProcessID, 109, 110}
				if name == "settled-empty" {
					want = want[:1]
				}
				if !reflect.DeepEqual(pids, want) {
					t.Fatal("recovery omitted or substituted an independently absent process", pids)
				}
			} else if len(pids) != 0 {
				t.Fatal("rejected checkpoint retained a partial process identity")
			}
		})
	}
}
