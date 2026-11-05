package linuxprotection

import (
	"strings"
	"testing"
)

func transferRecordFixture() *StandardNodeTransfer {
	return &StandardNodeTransfer{ID: strings.Repeat("a", 32), DeadlineNS: 123, SourceSession: strings.Repeat("b", 32), SourceConfigSHA256: strings.Repeat("c", 64), SourceReceiptSHA256: strings.Repeat("d", 64), Destination: NodeSelection{SessionID: strings.Repeat("e", 32), SourceSHA256: strings.Repeat("f", 64), ConfigSHA256: strings.Repeat("1", 64), Policy: "on-connect"}, ProfileID: "original", ProfileRevision: strings.Repeat("2", 64)}
}
func TestLinuxStandardNodeTransferJournalKeepsOriginalIntent(t *testing.T) {
	for _, name := range []string{"original", "changed-deadline", "changed-source", "changed-destination", "new-idle-request", "active-replacement"} {
		t.Run(name, func(t *testing.T) {
			previous := testInitial()
			previous.Transfer = transferRecordFixture()
			next := CloneRecord(previous)
			next.Sequence++
			raw, _ := CanonicalJournalRecord(previous)
			next.PreviousSHA256, _ = JournalRecordSHA256(raw)
			switch name {
			case "changed-deadline":
				next.Transfer.DeadlineNS++
			case "changed-source":
				next.Transfer.SourceSession = strings.Repeat("3", 32)
			case "changed-destination":
				next.Transfer.Destination.ConfigSHA256 = strings.Repeat("4", 64)
			case "new-idle-request":
				next.Transfer.ID = strings.Repeat("5", 32)
			case "active-replacement":
				previous.Phase = "intent"
				next.Transfer.ID = strings.Repeat("5", 32)
			}
			err := CheckJournalTransition(previous, next)
			want := name == "original" || name == "new-idle-request"
			if (err == nil) != want {
				t.Fatal("journal changed transfer identity", err)
			}
			if previous.Transfer.ID != strings.Repeat("a", 32) {
				t.Fatal("clone modified original intent")
			}
		})
	}
}
