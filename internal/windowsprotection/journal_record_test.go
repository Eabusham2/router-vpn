package windowsprotection

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

func journalTestController() Controller {
	return Controller{PID: 101, StartTimeUTCTicks: 638000000000000000, SID: "S-1-5-21-100-200-300-1001", AuthenticationID: 1<<63 + 123, SessionID: 2}
}

func journalTestInitial() JournalRecord {
	return JournalRecord{Schema: JournalRecordSchema, Kind: JournalRecordKind, JournalID: strings.Repeat("a", 32),
		Sequence: 1, Controller: journalTestController(), Phase: "settled"}
}

func journalTestState(seed string, live bool) JournalState {
	state := JournalState{ProfileID: "node \"quoted\"", ProfileRevision: strings.Repeat("f", 64), Target: &mobiletor.DesktopWindowsProtectionTarget{
		Capture: mobiletor.DesktopSocketCapture{SessionID: strings.Repeat(seed, 32), SourceSHA256: strings.Repeat(seed, 64), NetworkID: strings.Repeat("e", 32)},
		Policy:  "always", BaselineSHA256: strings.Repeat(seed, 64)}}
	if live {
		engine := journalTestController()
		engine.PID, engine.StartTimeUTCTicks = 102, engine.StartTimeUTCTicks+100
		state.Engine = &engine
	}
	return state
}

func journalTestBody(t *testing.T, record JournalRecord) []byte {
	t.Helper()
	raw, err := CanonicalJournalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func journalTestNext(t *testing.T, previous JournalRecord) JournalRecord {
	t.Helper()
	next := cloneJournalRecord(previous)
	next.Sequence++
	digest, err := JournalRecordSHA256(journalTestBody(t, previous))
	if err != nil {
		t.Fatal(err)
	}
	next.PreviousSHA256 = digest
	return next
}

func journalTestSuccessor(t *testing.T, previous JournalRecord, seed string) JournalRecord {
	t.Helper()
	next := journalTestNext(t, previous)
	next.Phase = "intent"
	next.Intent = &JournalIntent{Action: "successor", RequestID: strings.Repeat(seed, 32), ProfileID: "node \"quoted\"",
		ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("f", 64), Candidate: journalTestState(seed, true)}
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	return next
}

func journalTestSettled(t *testing.T, previous JournalRecord, state JournalState) JournalRecord {
	t.Helper()
	next := journalTestNext(t, previous)
	next.Phase, next.Intent, next.Committed = "settled", nil, cloneJournalState(state)
	return next
}

func journalTestRetained(t *testing.T) JournalRecord {
	t.Helper()
	intent := journalTestSuccessor(t, journalTestInitial(), "b")
	state := cloneJournalState(intent.Intent.Candidate)
	state.Engine = nil
	return journalTestSettled(t, intent, state)
}

func journalTestOff(t *testing.T) JournalRecord {
	t.Helper()
	next := journalTestNext(t, journalTestRetained(t))
	next.Phase = "intent"
	next.Intent = &JournalIntent{Action: "off", RequestID: strings.Repeat("c", 32), ProfileID: next.Committed.ProfileID,
		ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("d", 64)}
	return next
}

func TestWindowsProtectionJournalCanonicalLifecycle(t *testing.T) {
	initial := journalTestInitial()
	intent := journalTestSuccessor(t, initial, "b")
	installed := journalTestSettled(t, intent, intent.Intent.Candidate)
	retiredState := cloneJournalState(installed.Committed)
	retiredState.Engine = nil
	retired := journalTestSettled(t, installed, retiredState)
	off := journalTestNext(t, retired)
	off.Phase = "intent"
	off.Intent = &JournalIntent{Action: "off", RequestID: strings.Repeat("c", 32), ProfileID: retired.Committed.ProfileID,
		ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("d", 64)}
	absent := journalTestSettled(t, off, JournalState{})
	steps := []JournalRecord{initial, intent, installed, retired, off, absent}
	for index, record := range steps {
		raw := journalTestBody(t, record)
		parsed, err := ParseJournalRecord(raw)
		if err != nil || !reflect.DeepEqual(parsed, record) || parsed.Controller.AuthenticationID != 1<<63+123 {
			t.Fatal("canonical journal lost exact private state or uint64 creation identity", err)
		}
		if index > 0 {
			if err := CheckJournalTransition(steps[index-1], record); err != nil {
				t.Fatal("valid captured journal lifecycle was rejected", err)
			}
		}
	}
	states, err := JournalRecoveryCandidates(off)
	if err != nil || len(states) != 2 || !sameJournalState(states[0], retired.Committed) || states[1].Target != nil ||
		off.Intent.ProfileRevision == off.Intent.ResultProfileRevision {
		t.Fatal("Off intent lost unchanged protection, exact absence, or distinct save revision", err)
	}
}

func TestWindowsProtectionJournalRejectsChangedIdentity(t *testing.T) {
	base := journalTestSuccessor(t, journalTestInitial(), "b")
	changes := map[string]func(*JournalRecord){
		"schema":       func(r *JournalRecord) { r.Schema++ },
		"kind":         func(r *JournalRecord) { r.Kind = "unrelated" },
		"journal-case": func(r *JournalRecord) { r.JournalID = strings.Repeat("A", 32) },
		"sequence":     func(r *JournalRecord) { r.Sequence = 0 },
		"previous":     func(r *JournalRecord) { r.PreviousSHA256 = "" },
		"controller":   func(r *JournalRecord) { r.Controller.AuthenticationID = 0 },
		"phase":        func(r *JournalRecord) { r.Phase = "committed-maybe" },
		"intent":       func(r *JournalRecord) { r.Intent = nil },
		"request":      func(r *JournalRecord) { r.Intent.RequestID = strings.Repeat("f", 31) },
		"profile":      func(r *JournalRecord) { r.Intent.ProfileID = "another-profile" },
		"profile-rev":  func(r *JournalRecord) { r.Intent.ProfileRevision = "" },
		"result-rev":   func(r *JournalRecord) { r.Intent.ResultProfileRevision = strings.Repeat("c", 64) },
		"policy":       func(r *JournalRecord) { r.Intent.Candidate.Target.Policy = "off" },
		"source":       func(r *JournalRecord) { r.Intent.Candidate.Target.Capture.SourceSHA256 = "" },
		"baseline":     func(r *JournalRecord) { r.Intent.Candidate.Target.BaselineSHA256 = "" },
		"native-owner": func(r *JournalRecord) { r.Intent.Candidate.Engine = nil },
		"self-engine":  func(r *JournalRecord) { r.Intent.Candidate.Engine.PID = r.Controller.PID },
		"older-engine": func(r *JournalRecord) {
			r.Intent.Candidate.Engine.StartTimeUTCTicks = r.Controller.StartTimeUTCTicks - 1
		},
		"other-logon":   func(r *JournalRecord) { r.Intent.Candidate.Engine.AuthenticationID++ },
		"other-session": func(r *JournalRecord) { r.Intent.Candidate.Engine.SessionID++ },
		"other-user":    func(r *JournalRecord) { r.Intent.Candidate.Engine.SID = "S-1-5-18" },
		"live-prior":    func(r *JournalRecord) { r.Committed = journalTestState("c", true) },
		"reused-prior": func(r *JournalRecord) {
			r.Committed = cloneJournalState(r.Intent.Candidate)
			r.Committed.Engine = nil
		},
		"absent-profile": func(r *JournalRecord) { r.Committed.ProfileID = "not-absent" },
		"empty-profile":  func(r *JournalRecord) { r.Intent.Candidate.ProfileID = "" },
		"control-profile": func(r *JournalRecord) {
			r.Intent.ProfileID, r.Intent.Candidate.ProfileID = "node\x00", "node\x00"
		},
		"action": func(r *JournalRecord) { r.Intent.Action = "force-off" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			record := cloneJournalRecord(base)
			change(&record)
			if record.Validate() == nil {
				t.Fatal("changed journal identity was admitted")
			}
			if _, err := CanonicalJournalRecord(record); err == nil {
				t.Fatal("changed journal identity acquired a canonical record")
			}
		})
	}
}

func TestWindowsProtectionJournalStrictEncoding(t *testing.T) {
	record := journalTestOff(t)
	raw := journalTestBody(t, record)
	variants := [][]byte{
		append([]byte(" "), raw...), append(append([]byte(nil), raw...), '\n'),
		append(append([]byte(nil), raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"SCHEMA":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"\u0073chema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1,`), nil, 1),
		bytes.Replace(raw, []byte(`"intent":{`), []byte(`"unrecognized":false,"intent":{`), 1),
		bytes.Replace(raw, []byte(`"target":null`), []byte(`"target":{}`), 1),
		bytes.Replace(raw, []byte(`"engine":null`), nil, 1),
		bytes.Replace(raw, []byte(`"sequence":4`), []byte(`"sequence":"4"`), 1),
		bytes.Repeat([]byte("x"), JournalRecordLimit+1), nil,
	}
	for index, changed := range variants {
		if bytes.Equal(raw, changed) {
			t.Fatalf("strict journal mutation %d did not change bytes", index)
		}
		if _, err := ParseJournalRecord(changed); err == nil {
			t.Fatalf("noncanonical journal encoding was admitted: %d", index)
		}
		if _, err := JournalRecordSHA256(changed); err == nil {
			t.Fatalf("noncanonical journal encoding acquired a digest: %d", index)
		}
	}
	zeroSession := cloneJournalRecord(record)
	zeroSession.Controller.SessionID = 0
	zeroRaw := journalTestBody(t, zeroSession)
	if _, err := ParseJournalRecord(bytes.Replace(zeroRaw, []byte(`,"session_id":0`), nil, 1)); err == nil {
		t.Fatal("missing zero-valued journal identity was admitted")
	}
}

func TestWindowsProtectionJournalRetirementSemantics(t *testing.T) {
	for _, policy := range []string{"always", "on-connect"} {
		for _, action := range []string{"release", "off"} {
			t.Run(policy+"/"+action, func(t *testing.T) {
				previous := journalTestRetained(t)
				previous.Committed.Target.Policy = policy
				next := journalTestNext(t, previous)
				next.Phase = "intent"
				next.Intent = &JournalIntent{Action: action, RequestID: strings.Repeat("d", 32), ProfileID: previous.Committed.ProfileID,
					ProfileRevision: strings.Repeat("f", 64), ResultProfileRevision: strings.Repeat("f", 64)}
				if policy == "always" && action == "release" {
					next.Intent.Candidate = cloneJournalState(previous.Committed)
				}
				if err := CheckJournalTransition(previous, next); err != nil {
					t.Fatal("exact retirement semantics rejected", err)
				}
				wrong := cloneJournalRecord(next)
				if wrong.Intent.Candidate.Target == nil {
					wrong.Intent.Candidate = cloneJournalState(previous.Committed)
				} else {
					wrong.Intent.Candidate = JournalState{}
				}
				if wrong.Validate() == nil {
					t.Fatal("retirement changed normal Always or explicit Off semantics")
				}
				wrong = cloneJournalRecord(next)
				wrong.Intent.ProfileID = "another-node"
				if wrong.Validate() == nil {
					t.Fatal("another profile acquired journal retirement authority")
				}
			})
		}
	}
}

func TestWindowsProtectionJournalRejectsUnprovedTransitions(t *testing.T) {
	initial := journalTestInitial()
	intent := journalTestSuccessor(t, initial, "b")
	settled := journalTestSettled(t, intent, intent.Intent.Candidate)
	retired := cloneJournalState(settled.Committed)
	retired.Engine = nil
	joined := journalTestSettled(t, settled, retired)
	for _, fault := range []string{"gap", "digest", "journal", "intent-again", "changed-outcome", "changed-checkpoint", "other-engine", "unjoined-next", "overflow", "initial-adoption"} {
		t.Run(fault, func(t *testing.T) {
			previous, next := intent, settled
			switch fault {
			case "gap":
				next.Sequence += 2
			case "digest":
				next.PreviousSHA256 = strings.Repeat("0", 64)
			case "journal":
				next.JournalID = strings.Repeat("0", 32)
			case "intent-again":
				next = journalTestSuccessor(t, intent, "c")
			case "changed-outcome":
				next.Committed = journalTestState("c", false)
			case "changed-checkpoint":
				previous, next = settled, joined
				next.Committed = journalTestState("c", false)
			case "other-engine":
				next.Committed = cloneJournalState(next.Committed)
				next.Committed.Engine.PID++
			case "unjoined-next":
				previous = settled
				next = journalTestNext(t, settled)
				next.Phase, next.Intent = "intent", cloneJournalRecord(intent).Intent
			case "overflow":
				previous.Sequence, next.Sequence = math.MaxUint64, 0
			case "initial-adoption":
				previous = initial
				previous.Committed = journalTestState("b", false)
			}
			if err := CheckJournalTransition(previous, next); err == nil {
				t.Fatal("journal accepted a transition without its exact resolved predecessor")
			}
		})
	}
}

func TestWindowsProtectionJournalSlotRecoveryDoesNotGuessCommit(t *testing.T) {
	initial := journalTestInitial()
	intent := journalTestSuccessor(t, initial, "b")
	settled := journalTestSettled(t, intent, intent.Intent.Candidate)
	initialRaw, intentRaw, settledRaw := journalTestBody(t, initial), journalTestBody(t, intent), journalTestBody(t, settled)
	for _, test := range []struct {
		name       string
		slots      [2][]byte
		sequence   uint64
		incomplete bool
		states     int
	}{
		{"initial", [2][]byte{initialRaw, nil}, 1, false, 1},
		{"intent", [2][]byte{initialRaw, intentRaw}, 2, false, 2},
		{"committed", [2][]byte{settledRaw, intentRaw}, 3, false, 1},
		{"torn-acknowledged-intent", [2][]byte{initialRaw, intentRaw[:len(intentRaw)-1]}, 1, true, 1},
		{"torn-settlement", [2][]byte{settledRaw[:len(settledRaw)-1], intentRaw}, 2, true, 2},
		{"lost-prior-slot", [2][]byte{nil, intentRaw}, 2, true, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected, err := SelectJournalRecord(initial.JournalID, test.slots)
			if err != nil || selected.Record.Sequence != test.sequence || selected.Incomplete != test.incomplete {
				t.Fatal("journal slot selection lost its exact complete record", err)
			}
			states, err := JournalRecoveryCandidates(selected.Record)
			if err != nil || len(states) != test.states {
				t.Fatal("journal recovery changed the recorded outcome alternatives", err)
			}
			if test.name == "torn-acknowledged-intent" && states[0].Target != nil {
				t.Fatal("torn acknowledged intent fabricated authority over its unrecorded candidate")
			}
			if test.name == "torn-settlement" && (states[0].Target != nil || !sameJournalState(states[1], intent.Intent.Candidate)) {
				t.Fatal("torn settlement assumed its pending intent committed or aborted")
			}
		})
	}
	// Every torn prefix of a new slot keeps only the valid older checkpoint.
	// If BFE already contains the missing acknowledged candidate, these values
	// cannot match it and the native recovery adapter must remain blocked.
	for length := 1; length < len(intentRaw); length++ {
		selected, err := SelectJournalRecord(initial.JournalID, [2][]byte{initialRaw, intentRaw[:length]})
		if err != nil || selected.Record.Sequence != 1 || !selected.Incomplete || selected.Record.Committed.Target != nil {
			t.Fatalf("torn slot prefix %d changed the recorded native authority: %v", length, err)
		}
	}
}

func TestWindowsProtectionJournalRejectsForeignOrReorderedSlots(t *testing.T) {
	initial := journalTestInitial()
	intent := journalTestSuccessor(t, initial, "b")
	initialRaw, intentRaw := journalTestBody(t, initial), journalTestBody(t, intent)
	changed := cloneJournalRecord(intent)
	changed.PreviousSHA256 = strings.Repeat("0", 64)
	foreign := cloneJournalRecord(intent)
	foreign.JournalID = strings.Repeat("f", 32)
	gap := cloneJournalRecord(intent)
	gap.Sequence = 4
	for _, slots := range [][2][]byte{
		{nil, nil}, {[]byte("{"), []byte("}")}, {initialRaw, journalTestBody(t, changed)},
		{initialRaw, journalTestBody(t, foreign)}, {intentRaw, initialRaw}, {initialRaw, initialRaw},
		{initialRaw, journalTestBody(t, gap)}, {initialRaw, bytes.Repeat([]byte("x"), JournalRecordLimit+1)},
	} {
		if _, err := SelectJournalRecord(initial.JournalID, slots); err == nil {
			t.Fatal("foreign, reordered, unchained or unbounded journal slots were admitted")
		}
	}
}

func TestWindowsProtectionJournalRecoveryCopiesCapturedTargets(t *testing.T) {
	intent := journalTestSuccessor(t, journalTestInitial(), "b")
	original := journalTestBody(t, intent)
	states, err := JournalRecoveryCandidates(intent)
	if err != nil {
		t.Fatal(err)
	}
	states[1].Target.BaselineSHA256 = strings.Repeat("c", 64)
	states[1].Engine.PID++
	if after := journalTestBody(t, intent); !bytes.Equal(after, original) {
		t.Fatal("recovery comparison values mutated the captured journal")
	}
	var decoded map[string]any
	if err := json.Unmarshal(original, &decoded); err != nil {
		t.Fatal(err)
	}
	// The digest covers each operation's required profile save result too.
	off := journalTestOff(t)
	before, err := JournalRecordSHA256(journalTestBody(t, off))
	if err != nil {
		t.Fatal(err)
	}
	off.Intent.ResultProfileRevision = strings.Repeat("c", 64)
	after, err := JournalRecordSHA256(journalTestBody(t, off))
	if err != nil || before == after {
		t.Fatal("durable intent did not bind its exact Off save result", err)
	}
}

// Native recovery needs a separate checked controller-adoption operation.
// Ordinary checkpoints must never discard the previous creation identity,
// including while a live engine or unresolved native intent remains recorded.
func TestWindowsProtectionJournalRejectsUncheckedControllerReplacement(t *testing.T) {
	initial := journalTestInitial()
	intent := journalTestSuccessor(t, initial, "b")
	installed := journalTestSettled(t, intent, intent.Intent.Candidate)
	retained := journalTestRetained(t)
	off := journalTestOff(t)
	states := map[string]JournalRecord{"initial": initial, "live-engine": installed, "retained": retained, "pending-off": off}
	changes := map[string]func(*Controller){
		"pid":            func(c *Controller) { c.PID += 50 },
		"creation":       func(c *Controller) { c.StartTimeUTCTicks++ },
		"sid":            func(c *Controller) { c.SID = "S-1-5-21-400-500-600-1001" },
		"authentication": func(c *Controller) { c.AuthenticationID++ },
		"session":        func(c *Controller) { c.SessionID++ },
	}
	for stateName, previous := range states {
		for name, change := range changes {
			t.Run(stateName+"/"+name, func(t *testing.T) {
				next := journalTestSettled(t, previous, previous.Committed)
				change(&next.Controller)
				if err := next.Validate(); err != nil {
					t.Fatal("replacement fixture is structurally invalid", err)
				}
				if err := CheckJournalTransition(previous, next); err == nil {
					t.Fatal("ordinary journal transition discarded the retained controller creation identity")
				}
				var slots [2][]byte
				slots[(previous.Sequence-1)%2] = journalTestBody(t, previous)
				slots[(next.Sequence-1)%2] = journalTestBody(t, next)
				if _, err := SelectJournalRecord(previous.JournalID, slots); err == nil {
					t.Fatal("journal selection admitted an unchecked controller replacement")
				}
			})
		}
	}
}
