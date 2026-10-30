package windowsprotection

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func journalAdmissionFixture(t *testing.T, retained bool) (JournalRecord, JournalAdmissionRequest) {
	t.Helper()
	capture, request, engine := journalCommitFixture(t, retained)
	intent, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJournalRecord(intent)
	if err != nil {
		t.Fatal(err)
	}
	return intent, JournalAdmissionRequest{Schema: JournalAdmissionSchema, Kind: JournalAdmissionRequestKind,
		IntentSHA256: journalCommitTestDigest(raw), Nonce: strings.Repeat("6", 64)}
}

func TestJournalAdmissionExactRoundTrip(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			intent, request := journalAdmissionFixture(t, retained)
			requestRaw, err := CanonicalJournalAdmissionRequest(request, intent)
			if err != nil {
				t.Fatal(err)
			}
			decodedRequest, err := ParseJournalAdmissionRequest(requestRaw, intent)
			if err != nil || decodedRequest != request {
				t.Fatal("exact prepared admission request did not round trip", err)
			}
			requestDigest, err := JournalAdmissionRequestSHA256(requestRaw, intent)
			if err != nil || requestDigest != journalCommitTestDigest(requestRaw) {
				t.Fatal("admission request digest lost its exact intent and nonce", err)
			}
			reply, err := NewJournalAdmissionReply(intent, decodedRequest)
			if err != nil {
				t.Fatal(err)
			}
			replyRaw, err := CanonicalJournalAdmissionReply(reply, intent, request)
			if err != nil {
				t.Fatal(err)
			}
			decodedReply, err := ParseJournalAdmissionReply(replyRaw, intent, request)
			if err != nil || decodedReply != reply {
				t.Fatal("exact prepared admission reply did not round trip", err)
			}
			replyDigest, err := JournalAdmissionReplySHA256(replyRaw, intent, request)
			if err != nil || replyDigest != journalCommitTestDigest(replyRaw) {
				t.Fatal("admission reply digest lost its full comparison record", err)
			}
			settled, err := DeriveJournalAdmissionSettlement(intent)
			if err != nil {
				t.Fatal(err)
			}
			settledRaw, err := CanonicalJournalRecord(settled)
			if err != nil || reply.RequestSHA256 != requestDigest || reply.SettledSHA256 != journalCommitTestDigest(settledRaw) || reply.Sequence != intent.Sequence+1 {
				t.Fatal("admission reply did not bind the exact active checkpoint", err)
			}
			for _, raw := range [][]byte{requestRaw, replyRaw} {
				if len(raw) > 2048 || bytes.HasSuffix(raw, []byte("\n")) || !bytes.HasPrefix(raw, []byte(`{"schema":1,"kind":`)) {
					t.Fatal("admission record escaped its compact bounded frame")
				}
			}
		})
	}
}

func TestJournalAdmissionRequestBindsWholeIntent(t *testing.T) {
	intent, request := journalAdmissionFixture(t, true)
	changes := map[string]func(*JournalRecord){
		"journal":          func(r *JournalRecord) { r.JournalID = strings.Repeat("1", 32) },
		"sequence":         func(r *JournalRecord) { r.Sequence++ },
		"previous-digest":  func(r *JournalRecord) { r.PreviousSHA256 = strings.Repeat("2", 64) },
		"controller-pid":   func(r *JournalRecord) { r.Controller.PID += 2 },
		"controller-start": func(r *JournalRecord) { r.Controller.StartTimeUTCTicks-- },
		"controller-sid": func(r *JournalRecord) {
			r.Controller.SID = "S-1-5-21-1-2-3-1002"
			r.Intent.Candidate.Engine.SID = r.Controller.SID
		},
		"controller-logon":   func(r *JournalRecord) { r.Controller.AuthenticationID++; r.Intent.Candidate.Engine.AuthenticationID++ },
		"controller-session": func(r *JournalRecord) { r.Controller.SessionID++; r.Intent.Candidate.Engine.SessionID++ },
		"old-baseline":       func(r *JournalRecord) { r.Committed.Target.BaselineSHA256 = strings.Repeat("3", 64) },
		"old-profile":        func(r *JournalRecord) { r.Committed.ProfileID = "another-old-router" },
		"accepted-request":   func(r *JournalRecord) { r.Intent.RequestID = strings.Repeat("4", 32) },
		"selected-profile": func(r *JournalRecord) {
			r.Intent.ProfileID = "شبكة/नोड-🙂"
			r.Intent.Candidate.ProfileID = r.Intent.ProfileID
		},
		"profile-revision": func(r *JournalRecord) {
			r.Intent.ProfileRevision = strings.Repeat("5", 64)
			r.Intent.ResultProfileRevision = r.Intent.ProfileRevision
		},
		"candidate-session":   func(r *JournalRecord) { r.Intent.Candidate.Target.Capture.SessionID = strings.Repeat("6", 32) },
		"candidate-source":    func(r *JournalRecord) { r.Intent.Candidate.Target.Capture.SourceSHA256 = strings.Repeat("7", 64) },
		"candidate-network":   func(r *JournalRecord) { r.Intent.Candidate.Target.Capture.NetworkID = strings.Repeat("8", 32) },
		"candidate-policy":    func(r *JournalRecord) { r.Intent.Candidate.Target.Policy = "always" },
		"candidate-baseline":  func(r *JournalRecord) { r.Intent.Candidate.Target.BaselineSHA256 = strings.Repeat("9", 64) },
		"actual-engine-pid":   func(r *JournalRecord) { r.Intent.Candidate.Engine.PID++ },
		"actual-engine-start": func(r *JournalRecord) { r.Intent.Candidate.Engine.StartTimeUTCTicks++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := cloneJournalRecord(intent)
			change(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatal("intent-binding negative fixture is not independently valid", err)
			}
			if err := request.Validate(changed); err == nil {
				t.Fatal("admission request accepted another complete successor intent")
			}
			if _, err := NewJournalAdmissionReply(changed, request); err == nil {
				t.Fatal("another successor intent acquired an admission reply")
			}
		})
	}
	for name, change := range map[string]func(*JournalAdmissionRequest){
		"schema":        func(r *JournalAdmissionRequest) { r.Schema = 2 },
		"kind":          func(r *JournalAdmissionRequest) { r.Kind = JournalCommitRequestKind },
		"digest":        func(r *JournalAdmissionRequest) { r.IntentSHA256 = strings.Repeat("f", 64) },
		"missing-nonce": func(r *JournalAdmissionRequest) { r.Nonce = "" },
		"short-nonce":   func(r *JournalAdmissionRequest) { r.Nonce = strings.Repeat("a", 63) },
		"long-nonce":    func(r *JournalAdmissionRequest) { r.Nonce = strings.Repeat("a", 65) },
		"upper-nonce":   func(r *JournalAdmissionRequest) { r.Nonce = strings.Repeat("A", 64) },
		"invalid-nonce": func(r *JournalAdmissionRequest) { r.Nonce = strings.Repeat("z", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			if err := changed.Validate(intent); err == nil {
				t.Fatal("invalid admission request reached the comparison contract")
			}
		})
	}
}

func TestJournalAdmissionRejectsUnreadyIntent(t *testing.T) {
	intent, request := journalAdmissionFixture(t, true)
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	off := journalTestOff(t)
	release := cloneJournalRecord(off)
	release.Intent.Action = "release"
	release.Intent.ResultProfileRevision = release.Intent.ProfileRevision
	release.Intent.Candidate = cloneJournalState(release.Committed)
	for _, valid := range []JournalRecord{settled, off, release} {
		if err := valid.Validate(); err != nil {
			t.Fatal("non-admission negative journal must remain independently valid", err)
		}
	}
	changes := map[string]func(*JournalRecord){
		"settled":          func(r *JournalRecord) { *r = settled },
		"off":              func(r *JournalRecord) { *r = off },
		"release":          func(r *JournalRecord) { *r = release },
		"overflow":         func(r *JournalRecord) { r.Sequence = math.MaxUint64 },
		"zero-sequence":    func(r *JournalRecord) { r.Sequence = 0 },
		"missing-intent":   func(r *JournalRecord) { r.Intent = nil },
		"missing-target":   func(r *JournalRecord) { r.Intent.Candidate.Target = nil },
		"missing-engine":   func(r *JournalRecord) { r.Intent.Candidate.Engine = nil },
		"invalid-engine":   func(r *JournalRecord) { r.Intent.Candidate.Engine.PID = 0 },
		"live-predecessor": func(r *JournalRecord) { engine := *r.Intent.Candidate.Engine; r.Committed.Engine = &engine },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := cloneJournalRecord(intent)
			change(&changed)
			if _, err := DeriveJournalAdmissionSettlement(changed); err == nil {
				t.Fatal("non-successor or unready intent produced an active admission checkpoint")
			}
			if raw, err := CanonicalJournalRecord(changed); err == nil {
				request.IntentSHA256 = journalCommitTestDigest(raw)
			}
			if err := request.Validate(changed); err == nil {
				t.Fatal("non-successor or unready intent accepted an admission request")
			}
		})
	}
	last := cloneJournalRecord(intent)
	last.Sequence = math.MaxUint64 - 1
	checkpoint, err := DeriveJournalAdmissionSettlement(last)
	if err != nil || checkpoint.Sequence != math.MaxUint64 {
		t.Fatal("final representable active checkpoint was rejected", err)
	}
}

func TestJournalAdmissionSettlementKeepsExactLiveSuccessor(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			intent, _ := journalAdmissionFixture(t, retained)
			before := cloneJournalRecord(intent)
			settled, err := DeriveJournalAdmissionSettlement(intent)
			if err != nil {
				t.Fatal(err)
			}
			if settled.Committed.Target == nil || *settled.Committed.Target != *intent.Intent.Candidate.Target || settled.Committed.ProfileID != intent.Intent.Candidate.ProfileID {
				t.Fatal("admission checkpoint retained the predecessor instead of its exact candidate")
			}
			if settled.Committed.Engine == nil || *settled.Committed.Engine != *intent.Intent.Candidate.Engine {
				t.Fatal("admission checkpoint prematurely forgot its live native engine")
			}
			intentRaw, err := CanonicalJournalRecord(intent)
			if err != nil || settled.Schema != intent.Schema || settled.Kind != intent.Kind || settled.JournalID != intent.JournalID ||
				settled.Controller != intent.Controller || settled.Sequence != intent.Sequence+1 || settled.PreviousSHA256 != journalCommitTestDigest(intentRaw) ||
				settled.Phase != "settled" || settled.Intent != nil {
				t.Fatal("admission checkpoint changed its exact journal sequence or identity", err)
			}
			if err := CheckJournalTransition(intent, settled); err != nil {
				t.Fatal("admission checkpoint escaped the actual journal transition contract", err)
			}
			if !reflect.DeepEqual(intent, before) {
				t.Fatal("admission derivation mutated its captured intent")
			}
		})
	}
}

func TestJournalAdmissionSettlementCopiesCapturedState(t *testing.T) {
	intent, _ := journalAdmissionFixture(t, true)
	before := cloneJournalRecord(intent)
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	settled.Committed.Target.BaselineSHA256 = strings.Repeat("a", 64)
	settled.Committed.Engine.PID++
	if !reflect.DeepEqual(intent, before) {
		t.Fatal("admission checkpoint aliases the captured candidate owner")
	}
	settled, err = DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	stable := cloneJournalRecord(settled)
	intent.Intent.Candidate.Target.Capture.NetworkID = strings.Repeat("5", 32)
	intent.Intent.Candidate.Engine.StartTimeUTCTicks++
	intent.Committed.Target.BaselineSHA256 = strings.Repeat("f", 64)
	if !reflect.DeepEqual(settled, stable) {
		t.Fatal("caller mutation rewrote an already derived admission checkpoint")
	}
}

func TestJournalAdmissionReplyBindsRequestAndSettlement(t *testing.T) {
	intent, request := journalAdmissionFixture(t, true)
	reply, err := NewJournalAdmissionReply(intent, request)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest := request
	otherRequest.Nonce = strings.Repeat("7", 64)
	if err := otherRequest.Validate(intent); err != nil {
		t.Fatal(err)
	}
	if err := reply.Validate(intent, otherRequest); err == nil {
		t.Fatal("admission reply accepted a different challenge")
	}
	otherIntent := cloneJournalRecord(intent)
	otherIntent.Intent.Candidate.Engine.PID++
	otherIntentRaw, err := CanonicalJournalRecord(otherIntent)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest = request
	otherRequest.IntentSHA256 = journalCommitTestDigest(otherIntentRaw)
	otherRaw, err := CanonicalJournalAdmissionRequest(otherRequest, otherIntent)
	if err != nil {
		t.Fatal(err)
	}
	changedReply := reply
	changedReply.RequestSHA256 = journalCommitTestDigest(otherRaw)
	if err := changedReply.Validate(otherIntent, otherRequest); err == nil {
		t.Fatal("admission reply accepted another actual engine checkpoint")
	}
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*JournalRecord){
		"forgot-engine":   func(r *JournalRecord) { r.Committed.Engine = nil },
		"old-predecessor": func(r *JournalRecord) { r.Committed = cloneJournalState(intent.Committed) },
		"wrong-source":    func(r *JournalRecord) { r.Committed.Target.Capture.SourceSHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneJournalRecord(settled)
			change(&changed)
			raw, err := CanonicalJournalRecord(changed)
			if err != nil {
				t.Fatal("reply negative checkpoint must remain independently valid", err)
			}
			bad := reply
			bad.SettledSHA256 = journalCommitTestDigest(raw)
			if err := bad.Validate(intent, request); err == nil {
				t.Fatal("admission reply accepted a substituted active checkpoint")
			}
		})
	}
	for name, change := range map[string]func(*JournalAdmissionReply){
		"schema":        func(r *JournalAdmissionReply) { r.Schema = 0 },
		"kind":          func(r *JournalAdmissionReply) { r.Kind = JournalCommitReplyKind },
		"request":       func(r *JournalAdmissionReply) { r.RequestSHA256 = strings.Repeat("0", 64) },
		"settled":       func(r *JournalAdmissionReply) { r.SettledSHA256 = strings.Repeat("0", 64) },
		"sequence":      func(r *JournalAdmissionReply) { r.Sequence++ },
		"zero-sequence": func(r *JournalAdmissionReply) { r.Sequence = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := reply
			change(&bad)
			if err := bad.Validate(intent, request); err == nil {
				t.Fatal("invalid admission reply reached the prepared comparison")
			}
		})
	}
}

func TestJournalAdmissionRejectsNoncanonicalFrames(t *testing.T) {
	intent, request := journalAdmissionFixture(t, true)
	reply, err := NewJournalAdmissionReply(intent, request)
	if err != nil {
		t.Fatal(err)
	}
	requestRaw, err := CanonicalJournalAdmissionRequest(request, intent)
	if err != nil {
		t.Fatal(err)
	}
	replyRaw, err := CanonicalJournalAdmissionReply(reply, intent, request)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range journalCommitInvalidEncodings(requestRaw, JournalAdmissionWireLimit) {
		t.Run("request/"+name, func(t *testing.T) {
			if _, err := ParseJournalAdmissionRequest(raw, intent); err == nil {
				t.Fatal("noncanonical admission request reached prepared comparison")
			}
			if _, err := JournalAdmissionRequestSHA256(raw, intent); err == nil {
				t.Fatal("noncanonical admission request acquired an identity digest")
			}
		})
	}
	for name, raw := range journalCommitInvalidEncodings(replyRaw, JournalAdmissionWireLimit) {
		t.Run("reply/"+name, func(t *testing.T) {
			if _, err := ParseJournalAdmissionReply(raw, intent, request); err == nil {
				t.Fatal("noncanonical admission reply reached active checkpoint comparison")
			}
			if _, err := JournalAdmissionReplySHA256(raw, intent, request); err == nil {
				t.Fatal("noncanonical admission reply acquired an identity digest")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"negative":         bytes.Replace(replyRaw, []byte(fmt.Sprintf(`"sequence":%d`, reply.Sequence)), []byte(`"sequence":-1`), 1),
		"overflow":         bytes.Replace(replyRaw, []byte(fmt.Sprintf(`"sequence":%d`, reply.Sequence)), []byte(`"sequence":18446744073709551616`), 1),
		"duplicate-digest": bytes.Replace(replyRaw, []byte(`"settled_sha256":`), []byte(`"settled_sha256":"`+reply.SettledSHA256+`","settled_sha256":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJournalAdmissionReply(raw, intent, request); err == nil {
				t.Fatal("ambiguous admission reply sequence or digest was accepted")
			}
		})
	}
}
