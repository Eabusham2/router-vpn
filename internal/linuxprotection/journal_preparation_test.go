package linuxprotection

import (
	"bytes"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

func scopedCandidate(policy string) JournalState {
	s := testState(policy)
	s.Target.Native.TableName = "router_vpn_node_" + s.Target.Native.Capture.SessionID
	return s
}

func preparationIntent(t *testing.T, previous JournalRecord, candidate JournalState, lan bool) JournalRecord {
	t.Helper()
	next := nextRecord(t, previous)
	next.Phase = "intent"
	next.Intent = &JournalIntent{Action: "prepare", RequestID: strings.Repeat("e", 32), ProfileID: candidate.ProfileID,
		ProfileRevision: candidate.ProfileRevision, ResultProfileRevision: candidate.ProfileRevision,
		Preparation: &JournalPreparation{Capture: candidate.Target.Native.Capture, HomeLAN: lan,
			ConfigSHA256: candidate.Target.ConfigSHA256, Policy: candidate.Target.Policy, Engine: *candidate.Engine}}
	if err := CheckJournalTransition(previous, next); err != nil {
		t.Fatal(err)
	}
	return next
}

func preparationReceipt(t *testing.T, previous JournalRecord, candidate JournalState) JournalRecord {
	t.Helper()
	next := nextRecord(t, previous)
	n := candidate.Target.Native
	next.Intent.Preparation.Created = &mobiletor.DesktopLinuxNodeCreationRecord{Capture: n.Capture, HomeLAN: next.Intent.Preparation.HomeLAN,
		TableName: n.TableName, TableHandle: n.TableHandle, ChainHandle: n.ChainHandle, BaselineSHA256: n.BaselineSHA256}
	if err := CheckJournalTransition(previous, next); err != nil {
		t.Fatal(err)
	}
	return next
}

func preparationSuccessor(t *testing.T, previous JournalRecord, candidate JournalState) JournalRecord {
	t.Helper()
	next := nextRecord(t, previous)
	next.Intent.Action = "successor"
	next.Intent.Candidate = CloneState(candidate)
	if err := CheckJournalTransition(previous, next); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestLinuxJournalPreparationRequiresCreationBeforeSuccessor(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		for _, lan := range []bool{false, true} {
			state := scopedCandidate(policy)
			initial := testInitial()
			intent := preparationIntent(t, initial, state, lan)
			created := preparationReceipt(t, intent, state)
			successor := preparationSuccessor(t, created, state)
			committed := testSettled(t, successor, state)
			joined := CloneState(state)
			joined.Engine = nil
			retained := testSettled(t, committed, joined)
			sequence := []JournalRecord{initial, intent, created, successor, committed, retained}
			for index, record := range sequence {
				body, err := CanonicalJournalRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := ParseJournalRecord(body)
				if err != nil || parsed.Sequence != record.Sequence {
					t.Fatal("durable preparation could not round trip", err)
				}
				if index > 0 {
					prior, _ := CanonicalJournalRecord(sequence[index-1])
					var slots [2][]byte
					slots[(record.Sequence-1)%2] = body
					slots[(record.Sequence-2)%2] = prior
					selected, err := SelectJournalRecord(record.JournalID, slots)
					if err != nil || selected.Incomplete || selected.Record.Sequence != record.Sequence {
						t.Fatal("fixed durable slots lost a complete preparation phase", err)
					}
				}
			}
			// A failed new preparation may retain the original Always/on-connect
			// baseline only after its native caller has proved candidate cleanup.
			nextState := CloneState(state)
			nextState.Target.Native.Capture.SessionID = strings.Repeat("f", 32)
			nextState.Target.Native.TableName = "router_vpn_node_" + nextState.Target.Native.Capture.SessionID
			nextState.Engine.ProcessID += 10
			nextState.Engine.ProcProcessID += 10
			nextState.Engine.StartTicks += 10
			nextState.Target.Guardian.ProcessID += 10
			nextState.Target.Guardian.ProcProcessID += 10
			nextState.Target.Guardian.ParentProcessID = nextState.Engine.ProcessID
			nextState.Target.Guardian.StartTicks += 10
			nextState.Target.Native.Owner.ProcessID = uint32(nextState.Target.Guardian.ProcessID)
			prepared := preparationIntent(t, retained, nextState, lan)
			_ = testSettled(t, prepared, joined)
			createdNext := preparationReceipt(t, prepared, nextState)
			_ = testSettled(t, createdNext, joined)
		}
	}
}

func TestLinuxJournalPreparationRejectsSkippedAndChangedOwnership(t *testing.T) {
	state, initial := scopedCandidate("always"), testInitial()
	intent := preparationIntent(t, initial, state, true)
	created := preparationReceipt(t, intent, state)
	successor := preparationSuccessor(t, created, state)
	for label, pair := range map[string][2]JournalRecord{
		"skip-prepare": {initial, func() JournalRecord {
			n := nextRecord(t, initial)
			n.Phase, n.Intent = "intent", CloneRecord(created).Intent
			return n
		}()},
		"skip-create": {intent, func() JournalRecord { n := nextRecord(t, intent); n.Intent = CloneRecord(successor).Intent; return n }()},
		"direct-scoped-successor": {initial, func() JournalRecord {
			n := nextRecord(t, initial)
			n.Phase, n.Intent = "intent", CloneRecord(successor).Intent
			return n
		}()},
		"repeat-create":  {created, nextRecord(t, created)},
		"repeat-prepare": {intent, nextRecord(t, intent)},
	} {
		t.Run(label, func(t *testing.T) {
			if err := CheckJournalTransition(pair[0], pair[1]); err == nil {
				t.Fatal("scoped Node journal skipped or replayed the original preparation boundary")
			}
		})
	}
	for label, mutate := range map[string]func(*JournalRecord){
		"request": func(r *JournalRecord) { r.Intent.RequestID = strings.Repeat("b", 32) },
		"profile": func(r *JournalRecord) { r.Intent.ProfileID += "-replacement" },
		"revision": func(r *JournalRecord) {
			r.Intent.ProfileRevision = strings.Repeat("a", 64)
			r.Intent.ResultProfileRevision = r.Intent.ProfileRevision
		},
		"engine-birth":     func(r *JournalRecord) { r.Intent.Preparation.Engine.StartTicks++ },
		"engine-parent":    func(r *JournalRecord) { r.Intent.Preparation.Engine.ParentProcessID++ },
		"engine-namespace": func(r *JournalRecord) { r.Intent.Preparation.Engine.NetworkNamespace.Inode++ },
		"network": func(r *JournalRecord) {
			r.Intent.Preparation.Capture.NetworkID = strings.Repeat("c", 32)
			r.Intent.Preparation.Created.Capture = r.Intent.Preparation.Capture
		},
		"source": func(r *JournalRecord) {
			r.Intent.Preparation.Capture.SourceSHA256 = strings.Repeat("c", 64)
			r.Intent.Preparation.Created.Capture = r.Intent.Preparation.Capture
		},
		"selected-LAN": func(r *JournalRecord) {
			r.Intent.Preparation.HomeLAN = false
			r.Intent.Preparation.Created.HomeLAN = false
		},
		"policy":           func(r *JournalRecord) { r.Intent.Preparation.Policy = "on-connect" },
		"config":           func(r *JournalRecord) { r.Intent.Preparation.ConfigSHA256 = strings.Repeat("c", 64) },
		"creation-capture": func(r *JournalRecord) { r.Intent.Preparation.Created.Capture.NetworkID = strings.Repeat("c", 32) },
		"creation-table":   func(r *JournalRecord) { r.Intent.Preparation.Created.TableName = "router_vpn_killswitch" },
	} {
		t.Run(label, func(t *testing.T) {
			next := CloneRecord(created)
			mutate(&next)
			if err := CheckJournalTransition(intent, next); err == nil {
				t.Fatal("creation receipt replaced a captured accepted request or native owner")
			}
		})
	}
	for label, mutate := range map[string]func(*JournalRecord){
		"missing-creation": func(r *JournalRecord) { r.Intent.Preparation.Created = nil },
		"table-handle":     func(r *JournalRecord) { r.Intent.Candidate.Target.Native.TableHandle++ },
		"chain-handle":     func(r *JournalRecord) { r.Intent.Candidate.Target.Native.ChainHandle++ },
		"baseline":         func(r *JournalRecord) { r.Intent.Candidate.Target.Native.BaselineSHA256 = strings.Repeat("a", 64) },
		"engine":           func(r *JournalRecord) { r.Intent.Candidate.Engine.StartTicks-- },
		"config":           func(r *JournalRecord) { r.Intent.Candidate.Target.ConfigSHA256 = strings.Repeat("a", 64) },
		"policy":           func(r *JournalRecord) { r.Intent.Candidate.Target.Policy = "on-connect" },
		"changed-receipt": func(r *JournalRecord) {
			r.Intent.Preparation.Created.TableHandle++
			r.Intent.Candidate.Target.Native.TableHandle++
		},
		"drop-predecessor": func(r *JournalRecord) { r.Committed = CloneState(state); r.Committed.Engine = nil },
	} {
		t.Run("successor-"+label, func(t *testing.T) {
			next := CloneRecord(successor)
			mutate(&next)
			if err := CheckJournalTransition(created, next); err == nil {
				t.Fatal("successor adopted another native creation, engine or selected policy")
			}
		})
	}
}

func TestLinuxJournalPreparationPreservesLegacyAndDeepCopy(t *testing.T) {
	legacy := testIntent(t, testInitial(), "successor", testState("always"))
	body, err := CanonicalJournalRecord(legacy)
	if err != nil || bytes.Contains(body, []byte("preparation")) {
		t.Fatal("legacy fixed-table journal changed its canonical wire fields", err)
	}
	state := scopedCandidate("always")
	intent := preparationIntent(t, testInitial(), state, true)
	created := preparationReceipt(t, intent, state)
	copy := CloneRecord(created)
	copy.Intent.Preparation.ConfigSHA256 = strings.Repeat("f", 64)
	copy.Intent.Preparation.Created.TableHandle++
	if created.Intent.Preparation.ConfigSHA256 == copy.Intent.Preparation.ConfigSHA256 ||
		created.Intent.Preparation.Created.TableHandle == copy.Intent.Preparation.Created.TableHandle {
		t.Fatal("a cloned append replaced the original pending preparation receipt")
	}
	before, _ := CanonicalJournalRecord(intent)
	after, _ := CanonicalJournalRecord(created)
	var slots [2][]byte
	slots[(intent.Sequence-1)%2] = before
	slots[(created.Sequence-1)%2] = after[:len(after)/2]
	selected, err := SelectJournalRecord(intent.JournalID, slots)
	if err != nil || !selected.Incomplete || selected.Record.Sequence != intent.Sequence || selected.Record.Intent.Preparation.Created != nil {
		t.Fatal("torn receipt advanced or erased the unresolved preparation intent", err)
	}
}

func TestLinuxJournalPreparationRollbackCannotEraseRetainedAlways(t *testing.T) {
	old := testState("always")
	legacy := testIntent(t, testInitial(), "successor", old)
	old.Engine = nil
	retained := testSettled(t, legacy, old)
	nextState := scopedCandidate("on-connect")
	nextState.Target.Native.Capture.SessionID = strings.Repeat("f", 32)
	nextState.Target.Native.TableName = "router_vpn_node_" + nextState.Target.Native.Capture.SessionID
	intent := preparationIntent(t, retained, nextState, false)
	created := preparationReceipt(t, intent, nextState)
	for _, previous := range []JournalRecord{intent, created} {
		next := nextRecord(t, previous)
		next.Phase, next.Intent, next.Committed = "settled", nil, JournalState{}
		if err := CheckJournalTransition(previous, next); err == nil {
			t.Fatal("failed preparation erased the retained Always baseline without a release intent")
		}
	}
}
