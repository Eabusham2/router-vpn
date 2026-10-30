package windowsprotection

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsProtectionJournalRetainsCapturedProfileRevision(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, true)
	intent, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil || intent.Intent.Candidate.ProfileRevision != capture.ProfileRevision || intent.Committed.ProfileRevision != capture.Head.Committed.ProfileRevision {
		t.Fatal("successor lost its actual captured profile binding", err)
	}
	active, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil || active.Committed.ProfileRevision != capture.ProfileRevision {
		t.Fatal("active checkpoint erased its captured source revision", err)
	}
	joined := journalTestNext(t, active)
	joined.Committed.Engine = nil
	if err := CheckJournalTransition(active, joined); err != nil || joined.Committed.ProfileRevision != capture.ProfileRevision {
		t.Fatal("joined checkpoint changed its captured source revision", err)
	}
	for _, revision := range []string{"", strings.Repeat("a", 64)} {
		changed := journalTestNext(t, joined)
		changed.Committed.ProfileRevision = revision
		if err := CheckJournalTransition(joined, changed); err == nil {
			t.Fatal("checkpoint replaced or erased its captured profile binding")
		}
	}
	copy, err := JournalRecoveryCandidates(joined)
	if err != nil || len(copy) != 1 || copy[0].ProfileRevision != capture.ProfileRevision {
		t.Fatal("recovery comparisons forgot the retained source revision", err)
	}
}

func TestWindowsProtectionJournalLegacyBytesStayUnbound(t *testing.T) {
	// This is the old canonical retained-state encoding, without a source
	// profile revision. Reading it must not rewrite its bytes or invent one.
	raw := []byte(`{"schema":1,"kind":"routervpn-owned-wfp-journal","journal_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":3,"previous_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","controller":{"pid":101,"start_time_utc_ticks":638000000000000000,"sid":"S-1-5-21-100-200-300-1001","authentication_id":9223372036854775931,"session_id":2},"phase":"settled","committed":{"target":{"capture":{"SessionID":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","SourceSHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","NetworkID":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"policy":"always","baseline_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"profile_id":"legacy-node","engine":null},"intent":null}`)
	legacy, err := ParseJournalRecord(raw)
	if err != nil || legacy.Committed.ProfileRevision != "" {
		t.Fatal("legacy canonical state was discarded or rebound", err)
	}
	encoded, err := CanonicalJournalRecord(legacy)
	if err != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("legacy source binding migration changed original canonical bytes", err)
	}
	if err := requireJournalProfileBindings(legacy); err == nil {
		t.Fatal("unbound legacy state acquired modern source authority")
	}
	capture, _, _ := journalCommitFixture(t, false)
	capture.Head = legacy
	capture.Transfer.Predecessor = legacy.Committed.Target
	if err := capture.Validate(); err == nil {
		t.Fatal("today's selected profile rebound a legacy retained target")
	}
	if again, err := CanonicalJournalRecord(legacy); err != nil || !bytes.Equal(again, raw) {
		t.Fatal("rejected legacy adoption mutated its preserved evidence", err)
	}
}

func TestWindowsProtectionJournalRejectsMissingOrMixedBinding(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, false)
	intent, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{"", strings.Repeat("a", 64), strings.Repeat("F", 64), "short"} {
		changed := cloneJournalRecord(intent)
		changed.Intent.Candidate.ProfileRevision = revision
		if _, err := DeriveJournalAdmissionSettlement(changed); err == nil {
			t.Fatal("missing or mixed source revision acquired active admission")
		}
	}
	absent := journalTestInitial()
	absent.Committed.ProfileRevision = capture.ProfileRevision
	if err := absent.Validate(); err == nil {
		t.Fatal("absent protection retained an unrelated profile revision")
	}
	retained := journalTestRetained(t)
	next := journalTestNext(t, retained)
	next.Phase = "intent"
	next.Intent = &JournalIntent{Action: "release", RequestID: strings.Repeat("c", 32), ProfileID: retained.Committed.ProfileID,
		ProfileRevision: strings.Repeat("d", 64), ResultProfileRevision: strings.Repeat("d", 64), Candidate: retained.Committed}
	if err := next.Validate(); err == nil {
		t.Fatal("normal release substituted the retained source revision")
	}
}
