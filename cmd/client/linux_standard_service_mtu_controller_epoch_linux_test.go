//go:build linux

package main

import (
	"strings"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

func standardMTUReportFixture(t *testing.T) (standardengine.OperationReport, string) {
	t.Helper()
	ready := func(nonce string, index uint32, mtu int) string {
		raw, err := desktopnetwork.CanonicalDesktopNetworkReceipt(desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: "linux", Incarnation: strings.Repeat(nonce, 32), Name: "rvtun0", Index: index, MTU: mtu, Addresses: []string{"172.19.0.1/30"}, Objects: []desktopnetwork.DesktopNetworkObject{}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	old, next := ready("a", 4, 1500), ready("b", 5, 1400)
	retired, err := desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(desktopnetwork.DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: strings.Repeat("a", 32), Name: "rvtun0", Index: 4, Addresses: []string{"172.19.0.1/30"}, Objects: []desktopnetwork.DesktopNetworkObject{}})
	if err != nil {
		t.Fatal(err)
	}
	capture := strings.Repeat("c", 64)
	binding := standardengine.InitialReaderBinding(capture, old)
	report := standardengine.OperationReport{Command: standardengine.OperationCommand{Reservation: standardengine.OperationReservation{Slot: 0, Key: standardengine.OperationKey{CaptureSHA256: capture, ID: strings.Repeat("d", 32), Sequence: 1, DeadlineNS: time.Now().Add(time.Second).UnixNano(), Original: binding}}, MTU: 1400}, Result: standardengine.OperationResult{CurrentRole: standardengine.CandidateReader, WorkerJoined: true, Revision: 1, ReadyMask: 3, RetirementMask: 1}}
	report.Readers[0] = &standardengine.OperationReaderEvidence{Binding: binding, Ready: []byte(old), Retirement: []byte(retired)}
	report.Readers[1] = &standardengine.OperationReaderEvidence{Binding: standardengine.ReaderBinding{IdentitySHA256: strings.Repeat("e", 64), Generation: 2, InitialReceiptSHA256: standardengine.SHA256([]byte(next))}, Ready: []byte(next)}
	report.Result.Digest, err = standardengine.OperationResultDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	return report, old
}
func TestLinuxStandardMTUReportKeepsExactRawHistory(t *testing.T) {
	report, old := standardMTUReportFixture(t)
	current, err := validateLinuxStandardServiceMTUReport(report, old)
	if err != nil || current == nil || current.MTU != 1400 {
		t.Fatalf("joined result: %v %+v", err, current)
	}
	for _, tc := range []struct {
		name   string
		change func(*standardengine.OperationReport)
	}{
		{"unjoined", func(r *standardengine.OperationReport) { r.Result.WorkerJoined = false }},
		{"pending", func(r *standardengine.OperationReport) { r.Result.Pending = true }},
		{"different-digest", func(r *standardengine.OperationReport) { r.Result.Digest = strings.Repeat("0", 64) }},
		{"missing-retirement", func(r *standardengine.OperationReport) { r.Readers[0].Retirement = nil; r.Result.RetirementMask = 0 }},
		{"changed-current-MTU", func(r *standardengine.OperationReport) { r.Command.MTU = 1380 }},
		{"retirement-lost-address", func(r *standardengine.OperationReport) {
			p, _ := desktopnetwork.ParseDesktopNetworkRetirementReceipt(string(r.Readers[0].Retirement))
			p.Addresses = nil
			raw, _ := desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(p)
			r.Readers[0].Retirement = []byte(raw)
		}},
		{"retirement-wrong-incarnation", func(r *standardengine.OperationReport) {
			p, _ := desktopnetwork.ParseDesktopNetworkRetirementReceipt(string(r.Readers[0].Retirement))
			p.Incarnation = strings.Repeat("f", 32)
			raw, _ := desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(p)
			r.Readers[0].Retirement = []byte(raw)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, original := standardMTUReportFixture(t)
			tc.change(&r)
			if tc.name != "different-digest" {
				if digest, err := standardengine.OperationResultDigest(r); err == nil {
					r.Result.Digest = digest
				}
			}
			if _, err := validateLinuxStandardServiceMTUReport(r, original); err == nil {
				t.Fatal("accepted mismatched original history")
			}
		})
	}
	if _, err := validateLinuxStandardServiceMTUReport(report, old+"\n"); err == nil {
		t.Fatal("accepted replaced original Ready")
	}
}
func TestLinuxStandardMTUControllerBindsOnlyOriginalAdmission(t *testing.T) {
	r, _ := standardMTUReportFixture(t)
	key := r.Command.Reservation.Key
	provisional := key
	provisional.Sequence = 0
	epoch := &linuxStandardRequestEpoch{mtuTransition: &linuxStandardControllerMTUTransition{key: provisional}}
	bad := key
	bad.DeadlineNS++
	if epoch.bindMTU(bad) == nil {
		t.Fatal("renewed original candidate budget")
	}
	if err := epoch.bindMTU(key); err != nil {
		t.Fatal(err)
	}
	if err := epoch.bindMTU(key); err != nil {
		t.Fatal("same retained reply was not idempotent", err)
	}
	bad = key
	bad.Sequence++
	if epoch.bindMTU(bad) == nil {
		t.Fatal("replaced original native admission")
	}
}

func TestLinuxStandardMTUReportRetainsPartialFailedConstructor(t *testing.T) {
	report, old := standardMTUReportFixture(t)
	partial, err := desktopnetwork.CanonicalDesktopNetworkRetirementReceipt(desktopnetwork.DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: false, Objects: []desktopnetwork.DesktopNetworkObject{}})
	if err != nil {
		t.Fatal(err)
	}
	report.Readers[1].Ready = nil
	report.Readers[1].Binding.InitialReceiptSHA256 = ""
	report.Readers[1].Retirement = []byte(partial)
	report.Result.CurrentRole = standardengine.NoReader
	report.Result.Failed = true
	report.Result.ReadyMask = 1
	report.Result.RetirementMask = 3
	report.Result.Digest, err = standardengine.OperationResultDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	current, err := validateLinuxStandardServiceMTUReport(report, old)
	if err != nil || current != nil {
		t.Fatalf("partial failed construction became Ready: %+v %v", current, err)
	}
	report.Result.Failed = false
	report.Result.Digest, err = standardengine.OperationResultDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateLinuxStandardServiceMTUReport(report, old); err == nil {
		t.Fatal("no current reader became successful MTU")
	}
}
func TestLinuxStandardMTURejectionCannotAbandonAnotherAdmission(t *testing.T) {
	report, _ := standardMTUReportFixture(t)
	key := report.Command.Reservation.Key
	epoch := &linuxStandardRequestEpoch{mtuBinding: key.Original, mtuTransition: &linuxStandardControllerMTUTransition{key: key}}
	rejected := linuxStandardServiceMTURejected{ID: key.ID, DeadlineNS: key.DeadlineNS + 1, Expected: key.Original, Reason: "not submitted"}
	if epoch.rejectMTU(nil, rejected) == nil {
		t.Fatal("rejection renewed original deadline")
	}
	if epoch.mtuTransition == nil {
		t.Fatal("mismatched rejection abandoned original transition")
	}
}
