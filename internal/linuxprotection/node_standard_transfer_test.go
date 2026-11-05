package linuxprotection

import (
	"strings"
	"testing"
)

func reverseJournalFixture(t *testing.T) (JournalRecord, JournalRecord) {
	t.Helper()
	old := testInitial()
	old.Sequence = 4
	old.PreviousSHA256 = strings.Repeat("1", 64)
	old.Committed = testState("always")
	old.Committed.Engine = nil
	next := nextRecord(t, old)
	source := old.Committed.Target
	next.ReverseTransfer = &NodeStandardTransfer{ID: strings.Repeat("a", 32), DeadlineNS: 123, Source: NodeSelection{SessionID: source.Native.Capture.SessionID, SourceSHA256: source.Native.Capture.SourceSHA256, ConfigSHA256: source.ConfigSHA256, Policy: source.Policy}, SourceProfileID: old.Committed.ProfileID, SourceProfileRevision: old.Committed.ProfileRevision, SourceReceiptSHA256: strings.Repeat("2", 64), DestinationSession: strings.Repeat("d", 32), DestinationConfigSHA256: strings.Repeat("e", 64), DestinationProfileID: "exit-policy", DestinationProfileSHA256: strings.Repeat("f", 64), Endpoint: "203.0.113.7", Policy: "always"}
	next.Phase = "intent"
	next.Intent = &JournalIntent{Action: "standard-transfer", RequestID: next.ReverseTransfer.ID, ProfileID: old.Committed.ProfileID, ProfileRevision: old.Committed.ProfileRevision, ResultProfileRevision: old.Committed.ProfileRevision}
	return old, next
}
func TestLinuxNodeStandardTransferJournalRequiresOriginalClosedSource(t *testing.T) {
	for _, scenario := range []string{"original", "engine-live", "foreign-source", "foreign-profile", "foreign-config", "foreign-request", "no-transfer", "candidate-widened"} {
		t.Run(scenario, func(t *testing.T) {
			old, next := reverseJournalFixture(t)
			switch scenario {
			case "engine-live":
				next.Committed.Engine = testState("always").Engine
			case "foreign-source":
				next.ReverseTransfer.Source.SessionID = strings.Repeat("5", 32)
			case "foreign-profile":
				next.ReverseTransfer.SourceProfileID = "other"
			case "foreign-config":
				next.ReverseTransfer.Source.ConfigSHA256 = strings.Repeat("6", 64)
			case "foreign-request":
				next.Intent.RequestID = strings.Repeat("7", 32)
			case "no-transfer":
				next.ReverseTransfer = nil
			case "candidate-widened":
				next.Intent.Candidate = CloneState(old.Committed)
			}
			err := CheckJournalTransition(old, next)
			if (err == nil) != (scenario == "original") {
				t.Fatal("reverse intent source identity", err)
			}
		})
	}
}
func TestLinuxNodeStandardTransferJournalKeepsOutcomeAndIntent(t *testing.T) {
	for _, scenario := range []string{"commit", "abort", "changed-deadline", "changed-destination", "dropped-intent", "foreign-outcome"} {
		t.Run(scenario, func(t *testing.T) {
			_, intent := reverseJournalFixture(t)
			next := nextRecord(t, intent)
			next.Phase = "settled"
			next.Intent = nil
			next.Committed = JournalState{}
			switch scenario {
			case "abort":
				next.Committed = CloneState(intent.Committed)
			case "changed-deadline":
				next.ReverseTransfer.DeadlineNS++
			case "changed-destination":
				next.ReverseTransfer.DestinationConfigSHA256 = strings.Repeat("8", 64)
			case "dropped-intent":
				next.ReverseTransfer = nil
			case "foreign-outcome":
				next.Committed = CloneState(intent.Committed)
				next.Committed.ProfileRevision = strings.Repeat("0", 64)
			}
			err := CheckJournalTransition(intent, next)
			if (err == nil) != (scenario == "commit" || scenario == "abort") {
				t.Fatal("reverse settlement changed recorded ownership", err)
			}
			if intent.ReverseTransfer.DeadlineNS != 123 {
				t.Fatal("cloning rewrote original intent")
			}
		})
	}
}
