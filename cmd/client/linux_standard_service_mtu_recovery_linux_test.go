//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/standardengine"
)

// These exercise retained protocol identity and representation only. No fixture
// below stands in for a successful native observer or a live TUN measurement.
func TestLinuxStandardMTURecoveryCannotCrossOriginalIntents(t *testing.T) {
	report, ready := standardMTUReportFixture(t)
	key := report.Command.Reservation.Key
	m := &linuxStandardServiceMTU{native: &linuxStandardEngine{captureSHA: key.CaptureSHA256}, ready: ready, current: key.Original,
		active: &linuxStandardServiceMTUOperation{command: report.Command, original: ready, noSubmission: true, rejection: "cancelled before submit"}}
	exact := linuxStandardServiceMTURequest{ID: key.ID, DeadlineNS: key.DeadlineNS, Expected: &key.Original}
	if err := m.matches(&exact); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*linuxStandardServiceMTURequest){
		func(q *linuxStandardServiceMTURequest) { q.ID = strings.Repeat("f", 32) },
		func(q *linuxStandardServiceMTURequest) { q.DeadlineNS++ },
		func(q *linuxStandardServiceMTURequest) {
			changed := *q.Expected
			changed.Generation++
			q.Expected = &changed
		},
		func(q *linuxStandardServiceMTURequest) {
			reservation := report.Command.Reservation
			q.Reservation = &reservation
		},
	} {
		q := exact
		mutate(&q)
		if m.matches(&q) == nil {
			t.Fatal("recovery substituted its original retained intent")
		}
	}
	// An unsettled rejected intent still prevents a different ID from admitting
	// any worker; begin fails before it could acquire a native tracker.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	different := exact
	different.ID = strings.Repeat("f", 32)
	different.MTU = 1400
	if err := m.begin(ctx, &different); err == nil {
		t.Fatal("new ID bypassed original unsettled rejection")
	}
	if m.active.command.Reservation.Key != key {
		t.Fatal("new ID replaced original cancelled admission")
	}
}
func TestLinuxStandardMTURetirementResponseDoesNotClaimSettlement(t *testing.T) {
	report, ready := standardMTUReportFixture(t)
	key := report.Command.Reservation.Key
	m := &linuxStandardServiceMTU{native: &linuxStandardEngine{captureSHA: key.CaptureSHA256}, ready: ready, current: key.Original,
		active: &linuxStandardServiceMTUOperation{command: report.Command, original: ready, report: &report, historyValid: true}}
	normal := m.responseFor(false, errors.New("observer failed"))
	if !normal.Pending || normal.Settled {
		t.Fatal("incomplete original observer became healthy settlement")
	}
	retired := m.responseFor(true, errors.New("observer failed"))
	if retired.Pending || retired.Settled || retired.ObservationError == "" || retired.Result == nil || retired.Result.Digest != report.Result.Digest {
		t.Fatal("retirement hid actual joined history or claimed healthy settlement")
	}
	m.active.noSubmission = true
	m.active.rejection = "never submitted"
	rejected := m.responseFor(true, errors.New("observer failed"))
	if rejected.Rejected == nil || rejected.Rejected.ID != key.ID || rejected.Rejected.Expected != key.Original || rejected.Pending || rejected.Settled || rejected.Command != nil || rejected.Result != nil {
		t.Fatal("unsent retirement invented native worker evidence")
	}
}
func TestLinuxStandardMTUEvidenceChunkKeepsRawBytesWithinPacket(t *testing.T) {
	report, _ := standardMTUReportFixture(t)
	// A chunk may split a UTF-8 sequence or carry every JSON escape byte. Base64
	// transport must preserve those original bytes, not replace invalid UTF-8.
	raw := bytes.Repeat([]byte{0xff, 0xfe, 0xc3, 0x00, '"', '\\', '\n'}, linuxStandardServiceMTUEvidencePart/7+1)[:linuxStandardServiceMTUEvidencePart]
	binding := report.Readers[0].Binding
	response := linuxStandardServiceResponse{Schema: 1, Action: "mtu-evidence", Session: strings.Repeat("a", 32), Complete: true, MTU: &linuxStandardServiceMTUResponse{CaptureSHA256: report.Command.Reservation.Key.CaptureSHA256, Current: binding, Command: &report.Command, Result: &report.Result, Binding: &binding, Evidence: raw, EvidenceSize: 48 << 10, NextOffset: len(raw)}}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > linuxStandardServicePacketLimit {
		t.Fatalf("bounded evidence chunk exceeded packet: %d", len(encoded))
	}
	var decoded linuxStandardServiceResponse
	if err := linuxStandardServiceDecode(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.MTU == nil || !bytes.Equal(decoded.MTU.Evidence, raw) {
		t.Fatal("raw chunk bytes were normalized by transport")
	}
}

func TestLinuxStandardMTURetiredEvidencePreservesExplicitStop(t *testing.T) {
	for _, scenario := range []string{"status", "cancel", "evidence", "unsubmitted", "closed-observer", "foreign-peer", "foreign-session", "changed-reservation", "pending", "unjoined", "unvalidated", "changed-digest", "healthy-ack", "cleanup-retry", "new-candidate", "ordinary-observation"} {
		t.Run(scenario, func(t *testing.T) {
			report, ready := standardMTUReportFixture(t)
			key := report.Command.Reservation.Key
			peer := &linuxStandardServicePeer{record: linuxprocess.Observation{ProcessID: 10}}
			native := &linuxStandardEngine{captureSHA: key.CaptureSHA256, closed: true}
			session := &linuxStandardServiceSession{peer: peer, request: linuxStandardServiceRequest{Session: strings.Repeat("a", 32)}, joined: true, owner: &linuxLegacyStandardExitOwner{native: native}}
			m := &linuxStandardServiceMTU{session: session, native: native, current: key.Original, ready: ready, active: &linuxStandardServiceMTUOperation{command: report.Command, original: ready, report: &report, historyValid: true}}
			session.mtu = m
			s := &linuxStandardService{session: session, app: &app{}}
			q := &linuxStandardServiceMTURequest{Reservation: &report.Command.Reservation, Retiring: true}
			request := linuxStandardServiceRequest{Session: session.request.Session, Action: "mtu-status", MTU: q}
			switch scenario {
			case "cancel":
				request.Action = "mtu-cancel"
			case "evidence":
				request.Action, q.Digest, q.Phase = "mtu-evidence", report.Result.Digest, standardengine.RetirementEvidence
			case "unsubmitted":
				m.active.noSubmission, m.active.rejection = true, "cancelled before submission"
			case "closed-observer":
				session.joined, native.closed = false, false
				session.network = &linuxStandardServiceNetwork{closed: true}
			case "foreign-peer":
				peer = &linuxStandardServicePeer{record: linuxprocess.Observation{ProcessID: 11}}
			case "foreign-session":
				request.Session = strings.Repeat("b", 32)
			case "changed-reservation":
				changed := *q.Reservation
				changed.Key.DeadlineNS++
				q.Reservation = &changed
			case "pending":
				report.Result.Pending = true
			case "unjoined":
				report.Result.WorkerJoined = false
			case "unvalidated":
				m.active.historyValid = false
			case "changed-digest":
				report.Result.Digest = strings.Repeat("0", 64)
			case "healthy-ack":
				request.Action = "mtu-ack"
			case "cleanup-retry":
				request.Action = "mtu-cleanup"
			case "new-candidate":
				request.Action = "mtu-begin"
			case "ordinary-observation":
				q.Retiring = false
			}
			// This fixture has no native descriptor or live observer. Recovery
			// must use retained evidence without reconstructing native authority.
			response, err := s.retiredMTUResponse(request, peer)
			pass := scenario == "status" || scenario == "cancel" || scenario == "evidence" || scenario == "unsubmitted" || scenario == "closed-observer"
			if !pass {
				if err == nil || response != nil {
					t.Fatal("retired observation acquired another intent or healthy operation", response, err)
				}
				if scenario == "pending" || scenario == "unjoined" || scenario == "unvalidated" || scenario == "changed-digest" {
					if m.drainForStop(context.Background()) == nil {
						t.Fatal("retired drain abandoned unproved native work")
					}
				}
				return
			}
			if err != nil || response == nil || response.Pending || response.Settled || response.ObservationError == "" {
				t.Fatal("original Stop could not recover retained evidence without claiming health", response, err)
			}
			if scenario == "unsubmitted" {
				if response.Rejected == nil || response.Rejected.ID != key.ID || response.Command != nil || response.Result != nil {
					t.Fatal("never-submitted Stop fabricated worker completion")
				}
			} else if response.Result == nil || response.Result.Digest != report.Result.Digest {
				t.Fatal("retired Stop lost exact joined evidence")
			}
			if scenario == "evidence" && (!bytes.Equal(response.Evidence, report.Readers[0].Retirement) || response.Ready != "" || response.Binding == nil || *response.Binding != report.Readers[0].Binding) {
				t.Fatal("retired raw evidence was replaced")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := m.drainForStop(ctx); err != nil {
				t.Fatal("original Stop retried a closed FD11 instead of consuming retained completion", err)
			}
			if scenario != "closed-observer" {
				if err := s.retire(ctx, true); err != nil {
					t.Fatal("explicit service Stop could not continue after autonomous retirement", err)
				}
			}
		})
	}
}
