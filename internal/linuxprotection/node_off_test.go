package linuxprotection

import (
	"encoding/json"
	"router-vpn/internal/mobiletor"
	"strings"
	"testing"
)

func TestLinuxNodeOffReceiptAndJournalKeepExactMode(t *testing.T) {
	selection, created, prepared, _ := nodeControlRecords(t)
	protectedHash, err := selection.ControlSHA256()
	if err != nil {
		t.Fatal(err)
	}
	selection.Policy = "off"
	created.HostProtectionOff = true
	prepared.Policy = "off"
	prepared.Protection.HostProtectionOff = true
	prepared.Protection.DenyHandle = 301
	offHash, err := selection.ControlSHA256()
	if err != nil || offHash == protectedHash || prepared.Validate() != nil || !created.MatchesPrepared(prepared.Protection) {
		t.Fatal("Off lost original control/creation binding", err)
	}
	state := scopedCandidate("off")
	state.Target.Native.HostProtectionOff = true
	state.Target.Native.DenyHandle = 301
	initial := testInitial()
	intent := preparationIntent(t, initial, state, false)
	receipt := nextRecord(t, intent)
	n := state.Target.Native
	receipt.Intent.Preparation.Created = &mobiletor.DesktopLinuxNodeCreationRecord{HostProtectionOff: true, Capture: n.Capture, TableName: n.TableName, TableHandle: n.TableHandle, ChainHandle: n.ChainHandle, BaselineSHA256: n.BaselineSHA256}
	if err := CheckJournalTransition(intent, receipt); err != nil {
		t.Fatal(err)
	}
	candidate := preparationSuccessor(t, receipt, state)
	for _, fault := range []string{"original", "receipt-mode", "prepared-mode", "target-mode", "intent-mode", "foreign-source"} {
		t.Run(fault, func(t *testing.T) {
			r := CloneRecord(candidate)
			p := prepared
			switch fault {
			case "receipt-mode":
				r.Intent.Preparation.Created.HostProtectionOff = false
			case "prepared-mode":
				p.Protection.HostProtectionOff = false
			case "target-mode":
				r.Intent.Candidate.Target.Native.HostProtectionOff = false
			case "intent-mode":
				r.Intent.Preparation.Policy = "on-connect"
			case "foreign-source":
				r.Intent.Preparation.Created.Capture.SourceSHA256 = strings.Repeat("9", 64)
			}
			err := CheckJournalTransition(receipt, r)
			if fault == "prepared-mode" {
				err = p.Validate()
			}
			if (err == nil) != (fault == "original") {
				t.Fatal("changed selected mode or owner passed durable admission", err)
			}
		})
	}
	body, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseJournalRecord(body)
	if err != nil || !decoded.Intent.Candidate.Target.Native.HostProtectionOff {
		t.Fatal("durable Off round trip lost original mode", err)
	}
}
