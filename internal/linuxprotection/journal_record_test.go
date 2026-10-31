package linuxprotection

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

func testParent() ParentRecord {
	object := func(device, inode uint64, mode uint32) NativeObject {
		return NativeObject{Device: device, Inode: inode, Mode: mode}
	}
	p := ParentRecord{Generation: strings.Repeat("1", 32), BootID: "11111111-2222-4333-8444-555555555555", ProcessID: 101, ProcProcessID: 301,
		StartTicks: 300, CallerUID: 1000, InstallationAnchor: object(1, 1, 0040755), Root: object(1, 2, 0040755), Image: object(1, 3, 0100755),
		Input: object(2, 4, 0010600), InstallLock: object(1, 5, 0100600), ProcessLock: object(1, 6, 0100600),
		NetworkNamespace: object(3, 7, 0100444), PIDNamespace: object(3, 8, 0100444)}
	p.Input.UID = p.CallerUID
	return p
}

func testInitial() JournalRecord {
	return JournalRecord{Schema: JournalRecordSchema, Kind: JournalRecordKind, JournalID: strings.Repeat("2", 32), Sequence: 1, Controller: testParent(), Phase: "settled"}
}

func testState(policy string) JournalState {
	p := testParent()
	engine := ProcessRecord{BootID: p.BootID, ProcessID: 102, ProcProcessID: 302, ParentProcessID: p.ProcessID, StartTicks: 400,
		Image: NativeObject{Device: 1, Inode: 9, Mode: 0100755}, NetworkNamespace: p.NetworkNamespace, PIDNamespace: p.PIDNamespace}
	guardian := engine
	guardian.ProcessID, guardian.ProcProcessID, guardian.ParentProcessID, guardian.StartTicks = 103, 303, 102, 401
	target := ProtectionTarget{ConfigSHA256: strings.Repeat("b", 64), Policy: policy, Guardian: guardian,
		Native: mobiletor.DesktopLinuxProtectionRecord{
			Capture: mobiletor.DesktopSocketCapture{SessionID: strings.Repeat("3", 32), SourceSHA256: strings.Repeat("4", 64), NetworkID: strings.Repeat("5", 32)},
			Owner:   mobiletor.DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("6", 64), Generation: 7, ProcessID: 103},
			UID:     55001, PermitPrefix: "rvpn_" + strings.Repeat("7", 20), TableHandle: 10, ChainHandle: 11, BaselineSHA256: strings.Repeat("8", 64)}}
	return JournalState{Target: &target, ProfileID: "home-router", ProfileRevision: strings.Repeat("9", 64), Engine: &engine}
}

func nextRecord(t *testing.T, old JournalRecord) JournalRecord {
	t.Helper()
	body, err := CanonicalJournalRecord(old)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := JournalRecordSHA256(body)
	if err != nil {
		t.Fatal(err)
	}
	next := CloneRecord(old)
	next.Sequence++
	next.PreviousSHA256 = digest
	return next
}

func testIntent(t *testing.T, old JournalRecord, action string, candidate JournalState) JournalRecord {
	t.Helper()
	next := nextRecord(t, old)
	next.Phase = "intent"
	profile, revision := candidate.ProfileID, candidate.ProfileRevision
	if action != "successor" {
		profile, revision = old.Committed.ProfileID, old.Committed.ProfileRevision
	}
	next.Intent = &JournalIntent{Action: action, RequestID: strings.Repeat("a", 32), ProfileID: profile, ProfileRevision: revision, ResultProfileRevision: revision, Candidate: CloneState(candidate)}
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	return next
}

func testSettled(t *testing.T, old JournalRecord, state JournalState) JournalRecord {
	next := nextRecord(t, old)
	next.Phase, next.Intent, next.Committed = "settled", nil, CloneState(state)
	if err := CheckJournalTransition(old, next); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestLinuxParentRecordRequiresNativeBirthAndDistinctObjects(t *testing.T) {
	base := testParent()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ParentRecord){
		"empty-boot": func(p *ParentRecord) { p.BootID = "" }, "zero-boot": func(p *ParentRecord) { p.BootID = "00000000-0000-0000-0000-000000000000" },
		"upper-boot": func(p *ParentRecord) { p.BootID = "AAAAAAAA-2222-4333-8444-555555555555" }, "generation": func(p *ParentRecord) { p.Generation = "" },
		"zero-pid": func(p *ParentRecord) { p.ProcessID = 0 }, "proc-pid": func(p *ParentRecord) { p.ProcProcessID = -1 }, "start": func(p *ParentRecord) { p.StartTicks = 0 },
		"root-gui": func(p *ParentRecord) { p.CallerUID = 0 }, "caller-overflow": func(p *ParentRecord) { p.CallerUID = math.MaxUint32 },
		"foreign-pipe": func(p *ParentRecord) { p.Input.UID = 1001 }, "ordinary-input": func(p *ParentRecord) { p.Input.Mode = 0100600 },
		"broad-pipe": func(p *ParentRecord) { p.Input.Mode |= 0040 }, "writable-image": func(p *ParentRecord) { p.Image.Mode |= 0002 },
		"nonexec-image": func(p *ParentRecord) { p.Image.Mode = 0100600 }, "foreign-root": func(p *ParentRecord) { p.Root.UID = 1000 },
		"broad-lock": func(p *ParentRecord) { p.InstallLock.Mode |= 0040 }, "lock-alias": func(p *ParentRecord) { p.ProcessLock = p.InstallLock },
		"anchor-alias": func(p *ParentRecord) { p.Root = p.InstallationAnchor }, "namespace-type": func(p *ParentRecord) { p.NetworkNamespace.Mode = 0010600 },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			change(&p)
			if p.Validate() == nil {
				t.Fatal("incomplete or substituted native parent accepted")
			}
		})
	}
}

func TestLinuxJournalCanonicalRoundTripAndBoundedParser(t *testing.T) {
	r := testInitial()
	body, err := CanonicalJournalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseJournalRecord(body)
	if err != nil || parsed != r {
		t.Fatal("exact initial record changed", err)
	}
	for name, raw := range map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte{'x'}, JournalRecordLimit+1), "whitespace": append([]byte(" "), body...),
		"trailing": append(append([]byte(nil), body...), []byte("{}")...), "unknown": bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"unknown":1`), 1),
		"duplicate": bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"windows":   bytes.Replace(body, []byte(JournalRecordKind), []byte("routervpn-owned-wfp-journal"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJournalRecord(raw); err == nil {
				t.Fatal("noncanonical/foreign durable record accepted")
			}
		})
	}
}

func TestLinuxJournalRealSequenceRetainsAlwaysAndExplicitOffIntent(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			initial := testInitial()
			live := testState(policy)
			intent := testIntent(t, initial, "successor", live)
			if err := CheckJournalTransition(initial, intent); err != nil {
				t.Fatal(err)
			}
			active := testSettled(t, intent, live)
			joined := CloneState(live)
			joined.Engine = nil
			retained := testSettled(t, active, joined)
			outcome := JournalState{}
			if policy == "always" {
				outcome = joined
			}
			release := testIntent(t, retained, "release", outcome)
			if err := CheckJournalTransition(retained, release); err != nil {
				t.Fatal(err)
			}
			_ = testSettled(t, release, outcome)
			off := testIntent(t, retained, "off", JournalState{})
			off.Intent.ResultProfileRevision = strings.Repeat("c", 64)
			if err := CheckJournalTransition(retained, off); err != nil {
				t.Fatal(err)
			}
			body, err := CanonicalJournalRecord(off)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseJournalRecord(body)
			if err != nil || parsed.Intent == nil || parsed.Intent.ResultProfileRevision != off.Intent.ResultProfileRevision || parsed.Committed.Target == nil {
				t.Fatal("pending Off lost its exact accepted source/result or old retained target", err)
			}
		})
	}
}

func TestLinuxJournalRejectsForeignCreatorAndIllegalSuccession(t *testing.T) {
	initial := testInitial()
	live := testState("always")
	intent := testIntent(t, initial, "successor", live)
	for name, change := range map[string]func(*JournalRecord){
		"new-controller-generation": func(r *JournalRecord) { r.Controller.Generation = strings.Repeat("b", 32) },
		"new-boot":                  func(r *JournalRecord) { r.Controller.BootID = "aaaaaaaa-2222-4333-8444-555555555555" },
		"sequence-gap":              func(r *JournalRecord) { r.Sequence++ }, "prior-digest": func(r *JournalRecord) { r.PreviousSHA256 = strings.Repeat("0", 64) },
		"profile-mix": func(r *JournalRecord) { r.Intent.Candidate.ProfileID = "other-node" }, "profile-revision": func(r *JournalRecord) { r.Intent.Candidate.ProfileRevision = strings.Repeat("c", 64) },
		"engine-parent":    func(r *JournalRecord) { r.Intent.Candidate.Engine.ParentProcessID++ },
		"engine-boot":      func(r *JournalRecord) { r.Intent.Candidate.Engine.BootID = "aaaaaaaa-2222-4333-8444-555555555555" },
		"guardian-parent":  func(r *JournalRecord) { r.Intent.Candidate.Target.Guardian.ParentProcessID++ },
		"guardian-image":   func(r *JournalRecord) { r.Intent.Candidate.Target.Guardian.Image.Inode++ },
		"guardian-pid":     func(r *JournalRecord) { r.Intent.Candidate.Target.Native.Owner.ProcessID++ },
		"missing-source":   func(r *JournalRecord) { r.Intent.Candidate.Target.Native.Capture.SourceSHA256 = "" },
		"wrong-policy":     func(r *JournalRecord) { r.Intent.Candidate.Target.Policy = "off" },
		"unrecorded-state": func(r *JournalRecord) { r.Committed = CloneState(live) },
	} {
		t.Run(name, func(t *testing.T) {
			r := CloneRecord(intent)
			change(&r)
			if CheckJournalTransition(initial, r) == nil {
				t.Fatal("foreign or unproved successor accepted")
			}
		})
	}
	active := testSettled(t, intent, live)
	joined := CloneState(live)
	joined.Engine = nil
	retained := testSettled(t, active, joined)
	second := CloneState(live)
	second.Engine.ProcessID += 3
	second.Engine.ProcProcessID += 3
	second.Target.Guardian.ProcessID += 3
	second.Target.Guardian.ProcProcessID += 3
	second.Target.Guardian.ParentProcessID += 3
	second.Target.Native.Owner.ProcessID += 3
	bad := nextRecord(t, retained)
	bad.Phase = "intent"
	bad.Intent = &JournalIntent{Action: "successor", RequestID: strings.Repeat("a", 32), ProfileID: second.ProfileID, ProfileRevision: second.ProfileRevision, ResultProfileRevision: second.ProfileRevision, Candidate: second}
	if bad.Validate() == nil {
		t.Fatal("same native session was reused under a replacement engine")
	}
	second.Target.Native.Capture.SessionID = strings.Repeat("d", 32)
	bad.Intent.Candidate = second
	if err := CheckJournalTransition(retained, bad); err != nil {
		t.Fatal("fresh retained successor refused", err)
	}
	wrong := nextRecord(t, retained)
	wrong.Phase = "intent"
	wrong.Intent = &JournalIntent{Action: "release", RequestID: strings.Repeat("a", 32), ProfileID: retained.Committed.ProfileID, ProfileRevision: retained.Committed.ProfileRevision, ResultProfileRevision: retained.Committed.ProfileRevision}
	if wrong.Validate() == nil {
		t.Fatal("ordinary release silently removed Always protection")
	}
}

func TestLinuxJournalFixedSlotsPreserveTornAndForeignBoundaries(t *testing.T) {
	initial := testInitial()
	body, _ := CanonicalJournalRecord(initial)
	selection, err := SelectJournalRecord(initial.JournalID, [2][]byte{body, nil})
	if err != nil || selection.Incomplete || selection.Record.Sequence != 1 {
		t.Fatal("new complete journal rejected", err)
	}
	intent := testIntent(t, initial, "successor", testState("always"))
	next, _ := CanonicalJournalRecord(intent)
	selection, err = SelectJournalRecord(initial.JournalID, [2][]byte{body, next})
	if err != nil || selection.Incomplete || selection.Record.Sequence != 2 {
		t.Fatal("durable successor not selected", err)
	}
	for _, slots := range [][2][]byte{{body, []byte(`{"schema":1`)}, {nil, next}} {
		selection, err = SelectJournalRecord(initial.JournalID, slots)
		if err != nil || !selection.Incomplete {
			t.Fatal("torn peer was silently treated as ordinary complete state", err)
		}
	}
	foreign := CloneRecord(intent)
	foreign.JournalID = strings.Repeat("f", 32)
	foreignRaw, _ := CanonicalJournalRecord(foreign)
	for name, slots := range map[string][2][]byte{"wrong-owner": {body, foreignRaw}, "wrong-slot": {next, body}, "both-torn": {[]byte("{"), []byte("{")}, "oversized": {body, bytes.Repeat([]byte{'x'}, JournalRecordLimit+1)}} {
		t.Run(name, func(t *testing.T) {
			if _, err := SelectJournalRecord(initial.JournalID, slots); err == nil {
				t.Fatal("foreign or unbounded journal became recovery authority")
			}
		})
	}
}

func TestLinuxJournalImmutableHeaderBindsDistinctInodes(t *testing.T) {
	p := testParent()
	file := func(inode uint64) NativeObject {
		return NativeObject{Device: p.InstallationAnchor.Device, Inode: inode, Mode: 0100600}
	}
	h := JournalHeader{Schema: 1, Kind: "routervpn-owned-nft-journal-files", JournalID: strings.Repeat("2", 32), Creator: p,
		Root: NativeObject{Device: 1, Inode: 20, Mode: 0040700}, Header: file(21), Lock: file(22), Slots: [2]NativeObject{file(23), file(24)}}
	body, err := CanonicalJournalHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := ParseJournalHeader(body)
	if err != nil || actual != h {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*JournalHeader){
		"foreign-filesystem": func(h *JournalHeader) { h.Slots[0].Device++ }, "slot-alias": func(h *JournalHeader) { h.Slots[1] = h.Slots[0] },
		"parent-lock-alias": func(h *JournalHeader) { h.Lock = h.Creator.ProcessLock }, "broad-root": func(h *JournalHeader) { h.Root.Mode |= 0055 },
		"readable-slot": func(h *JournalHeader) { h.Slots[0].Mode |= 0040 }, "same-root": func(h *JournalHeader) { h.Root = h.Creator.Root },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := h
			change(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("header accepted substituted/unprotected native objects")
			}
		})
	}
	if _, err := ParseJournalHeader(append(body, '\n')); err == nil {
		t.Fatal("noncanonical header accepted")
	}
}

func TestLinuxJournalCloneDoesNotShareMutableSelection(t *testing.T) {
	initial := testInitial()
	intent := testIntent(t, initial, "successor", testState("always"))
	copy := CloneRecord(intent)
	copy.Intent.Candidate.Target.Policy = "off"
	copy.Intent.Candidate.Engine.ProcessID++
	if intent.Intent.Candidate.Target.Policy != "always" || intent.Intent.Candidate.Engine.ProcessID != 102 {
		t.Fatal("caller mutation changed retained original durable identity")
	}
}
