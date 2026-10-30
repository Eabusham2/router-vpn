package windowsprotection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

func journalCommitFixture(t *testing.T, retained bool) (JournalCommitCapture, JournalCommitRequest, Controller) {
	t.Helper()
	controller := Controller{PID: 240, StartTimeUTCTicks: 100000, SID: "S-1-5-21-1-2-3-1001", AuthenticationID: 31, SessionID: 4}
	head := JournalRecord{Schema: JournalRecordSchema, Kind: JournalRecordKind, JournalID: strings.Repeat("a", 32),
		Sequence: 1, Controller: controller, Phase: "settled"}
	if retained {
		head.Sequence, head.PreviousSHA256 = 3, strings.Repeat("e", 64)
		head.Committed = JournalState{ProfileID: "previous/router", Target: &mobiletor.DesktopWindowsProtectionTarget{
			Capture: mobiletor.DesktopSocketCapture{SessionID: strings.Repeat("b", 32), SourceSHA256: strings.Repeat("b", 64), NetworkID: strings.Repeat("c", 32)},
			Policy:  "always", BaselineSHA256: strings.Repeat("d", 64)}}
	}
	capture := JournalCommitCapture{Schema: JournalCommitSchema, Kind: JournalCommitCaptureKind, Head: head,
		ProfileID: "selected/router", ProfileRevision: strings.Repeat("d", 64), Transfer: mobiletor.DesktopProtectionTransferRecord{
			Schema: 1, Kind: "routervpn-windows-protection-transfer-v1", SessionID: strings.Repeat("e", 32),
			SourceSHA256: strings.Repeat("f", 64), ConfigSHA256: strings.Repeat("c", 64), Policy: "on-connect"}}
	if head.Committed.Target != nil {
		previous := *head.Committed.Target
		capture.Transfer.Predecessor = &previous
	}
	raw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := JournalCommitCaptureSHA256(raw)
	if err != nil {
		t.Fatal(err)
	}
	request := JournalCommitRequest{Schema: JournalCommitSchema, Kind: JournalCommitRequestKind,
		CaptureSHA256: digest, Nonce: strings.Repeat("2", 64), Candidate: mobiletor.DesktopWindowsProtectionTarget{
			Capture: mobiletor.DesktopSocketCapture{SessionID: capture.Transfer.SessionID, SourceSHA256: capture.Transfer.SourceSHA256, NetworkID: strings.Repeat("9", 32)},
			Policy:  capture.Transfer.Policy, BaselineSHA256: strings.Repeat("1", 64)}}
	engine := controller
	engine.PID, engine.StartTimeUTCTicks = controller.PID+1, controller.StartTimeUTCTicks+10
	return capture, request, engine
}

func cloneJournalCommitFixture(capture JournalCommitCapture) JournalCommitCapture {
	capture.Head = cloneJournalRecord(capture.Head)
	if capture.Transfer.Predecessor != nil {
		previous := *capture.Transfer.Predecessor
		capture.Transfer.Predecessor = &previous
	}
	return capture
}

func journalCommitTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestJournalCommitExactRoundTrip(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			capture, request, engine := journalCommitFixture(t, retained)
			captureRaw, err := CanonicalJournalCommitCapture(capture)
			if err != nil {
				t.Fatal(err)
			}
			decodedCapture, err := ParseJournalCommitCapture(captureRaw)
			if err != nil || !reflect.DeepEqual(decodedCapture, capture) {
				t.Fatal("exact private capture did not round trip", err)
			}
			requestRaw, err := CanonicalJournalCommitRequest(request, decodedCapture)
			if err != nil {
				t.Fatal(err)
			}
			decodedRequest, err := ParseJournalCommitRequest(requestRaw, decodedCapture)
			if err != nil || decodedRequest != request {
				t.Fatal("exact child request did not round trip", err)
			}
			reply, err := NewJournalCommitReply(decodedCapture, decodedRequest, engine)
			if err != nil {
				t.Fatal(err)
			}
			replyRaw, err := CanonicalJournalCommitReply(reply, decodedCapture, decodedRequest, engine)
			if err != nil {
				t.Fatal(err)
			}
			decodedReply, err := ParseJournalCommitReply(replyRaw, decodedCapture, decodedRequest, engine)
			if err != nil || decodedReply != reply {
				t.Fatal("exact parent reply did not round trip", err)
			}
			captureDigest, err := JournalCommitCaptureSHA256(captureRaw)
			if err != nil || captureDigest != journalCommitTestDigest(captureRaw) || captureDigest != request.CaptureSHA256 {
				t.Fatal("capture digest did not bind its complete private record", err)
			}
			requestDigest, err := JournalCommitRequestSHA256(requestRaw, decodedCapture)
			if err != nil || requestDigest != journalCommitTestDigest(requestRaw) || requestDigest != reply.RequestSHA256 {
				t.Fatal("request digest did not bind its actual nonce and candidate", err)
			}
			replyDigest, err := JournalCommitReplySHA256(replyRaw, decodedCapture, decodedRequest, engine)
			if err != nil || replyDigest != journalCommitTestDigest(replyRaw) {
				t.Fatal("reply digest did not bind its exact derived intent", err)
			}
			for index, raw := range [][]byte{captureRaw, requestRaw, replyRaw} {
				if bytes.HasSuffix(raw, []byte("\n")) || !bytes.HasPrefix(raw, []byte(`{"schema":1,"kind":`)) {
					t.Fatal("commit record changed its compact canonical frame", index)
				}
			}
			if len(captureRaw) > 32768 || len(requestRaw) > 2048 || len(replyRaw) > 2048 {
				t.Fatal("commit records exceeded the existing private-file or pipe frame contract")
			}
		})
	}
}

func TestJournalCommitCaptureRejectsUnownedHead(t *testing.T) {
	base, _, _ := journalCommitFixture(t, true)
	changes := map[string]func(*JournalCommitCapture){
		"schema":             func(c *JournalCommitCapture) { c.Schema = 0 },
		"kind":               func(c *JournalCommitCapture) { c.Kind = "routervpn-wfp-commit-request-v1" },
		"journal-id":         func(c *JournalCommitCapture) { c.Head.JournalID = strings.Repeat("A", 32) },
		"zero-sequence":      func(c *JournalCommitCapture) { c.Head.Sequence = 0 },
		"overflow-sequence":  func(c *JournalCommitCapture) { c.Head.Sequence = math.MaxUint64 },
		"head-digest":        func(c *JournalCommitCapture) { c.Head.PreviousSHA256 = "" },
		"invalid-controller": func(c *JournalCommitCapture) { c.Head.Controller.PID = 0 },
		"unsettled":          func(c *JournalCommitCapture) { c.Head.Phase = "intent" },
		"live-engine": func(c *JournalCommitCapture) {
			engine := c.Head.Controller
			engine.PID++
			c.Head.Committed.Engine = &engine
		},
		"missing-profile":     func(c *JournalCommitCapture) { c.ProfileID = "" },
		"trimmed-profile":     func(c *JournalCommitCapture) { c.ProfileID = " selected " },
		"control-profile":     func(c *JournalCommitCapture) { c.ProfileID = "selected\x00router" },
		"oversized-profile":   func(c *JournalCommitCapture) { c.ProfileID = strings.Repeat("x", 1025) },
		"unknown-revision":    func(c *JournalCommitCapture) { c.ProfileRevision = "" },
		"aliased-revision":    func(c *JournalCommitCapture) { c.ProfileRevision = strings.Repeat("D", 64) },
		"transfer-kind":       func(c *JournalCommitCapture) { c.Transfer.Kind = "unrelated" },
		"transfer-config":     func(c *JournalCommitCapture) { c.Transfer.ConfigSHA256 = "" },
		"reused-session":      func(c *JournalCommitCapture) { c.Transfer.SessionID = c.Transfer.Predecessor.Capture.SessionID },
		"missing-prior":       func(c *JournalCommitCapture) { c.Transfer.Predecessor = nil },
		"substituted-prior":   func(c *JournalCommitCapture) { c.Transfer.Predecessor.BaselineSHA256 = strings.Repeat("8", 64) },
		"prior-policy":        func(c *JournalCommitCapture) { c.Transfer.Predecessor.Policy = "on-connect" },
		"prior-network":       func(c *JournalCommitCapture) { c.Transfer.Predecessor.Capture.NetworkID = strings.Repeat("8", 32) },
		"contradictory-prior": func(c *JournalCommitCapture) { c.Head.Committed = JournalState{} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			capture := cloneJournalCommitFixture(base)
			change(&capture)
			if capture.Validate() == nil {
				t.Fatal("invalid captured journal head or predecessor was accepted")
			}
			if _, err := CanonicalJournalCommitCapture(capture); err == nil {
				t.Fatal("invalid capture acquired canonical commit bytes")
			}
		})
	}
}

func TestJournalCommitRequestBindsWholeCapture(t *testing.T) {
	capture, request, _ := journalCommitFixture(t, true)
	for _, field := range []string{"configuration", "profile", "revision", "controller", "prior-profile", "sequence"} {
		t.Run(field, func(t *testing.T) {
			changed := cloneJournalCommitFixture(capture)
			switch field {
			case "configuration":
				changed.Transfer.ConfigSHA256 = strings.Repeat("6", 64)
			case "profile":
				changed.ProfileID = "another/router"
			case "revision":
				changed.ProfileRevision = strings.Repeat("6", 64)
			case "controller":
				changed.Head.Controller.StartTimeUTCTicks++
			case "prior-profile":
				changed.Head.Committed.ProfileID = "another/prior-router"
			case "sequence":
				changed.Head.Sequence++
			}
			if changed.Validate() != nil {
				t.Fatal("changed complete capture did not establish an independently valid comparison")
			}
			if request.Validate(changed) == nil {
				t.Fatal("request admitted another complete captured journal or configuration")
			}
		})
	}
	changes := map[string]func(*JournalCommitRequest){
		"schema":       func(r *JournalCommitRequest) { r.Schema++ },
		"kind":         func(r *JournalCommitRequest) { r.Kind = "unknown" },
		"capture":      func(r *JournalCommitRequest) { r.CaptureSHA256 = strings.Repeat("0", 64) },
		"empty-nonce":  func(r *JournalCommitRequest) { r.Nonce = "" },
		"nonce-case":   func(r *JournalCommitRequest) { r.Nonce = strings.Repeat("A", 64) },
		"nonce-length": func(r *JournalCommitRequest) { r.Nonce = strings.Repeat("a", 65) },
		"session":      func(r *JournalCommitRequest) { r.Candidate.Capture.SessionID = strings.Repeat("7", 32) },
		"source":       func(r *JournalCommitRequest) { r.Candidate.Capture.SourceSHA256 = strings.Repeat("7", 64) },
		"network":      func(r *JournalCommitRequest) { r.Candidate.Capture.NetworkID = "" },
		"policy":       func(r *JournalCommitRequest) { r.Candidate.Policy = "always" },
		"baseline":     func(r *JournalCommitRequest) { r.Candidate.BaselineSHA256 = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			if changed.Validate(capture) == nil {
				t.Fatal("request admitted a changed native candidate or challenge")
			}
		})
	}
}

func TestJournalCommitDerivesExactIntentWithoutAliasing(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, true)
	headBefore := cloneJournalRecord(capture.Head)
	intent, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil {
		t.Fatal("valid exact commit intent was not derived", err)
	}
	headRaw, err := CanonicalJournalRecord(capture.Head)
	if err != nil {
		t.Fatal(err)
	}
	if intent.JournalID != capture.Head.JournalID || intent.Controller != capture.Head.Controller ||
		intent.Sequence != capture.Head.Sequence+1 || intent.PreviousSHA256 != journalCommitTestDigest(headRaw) || intent.Phase != "intent" ||
		!reflect.DeepEqual(intent.Committed, capture.Head.Committed) || intent.Intent == nil {
		t.Fatal("derived intent changed its captured journal generation")
	}
	accepted := intent.Intent
	if accepted.Action != "successor" || accepted.RequestID != capture.Transfer.SessionID || accepted.ProfileID != capture.ProfileID ||
		accepted.ProfileRevision != capture.ProfileRevision || accepted.ResultProfileRevision != capture.ProfileRevision ||
		accepted.Candidate.ProfileID != capture.ProfileID || accepted.Candidate.Target == nil || *accepted.Candidate.Target != request.Candidate ||
		accepted.Candidate.Engine == nil || *accepted.Candidate.Engine != engine || CheckJournalTransition(capture.Head, intent) != nil {
		t.Fatal("derived intent lost its original profile, actual engine or full candidate")
	}
	intent.Committed.Target.BaselineSHA256 = strings.Repeat("7", 64)
	accepted.Candidate.Target.Capture.NetworkID = strings.Repeat("7", 32)
	accepted.Candidate.Engine.PID++
	if !reflect.DeepEqual(capture.Head, headBefore) || request.Candidate.Capture.NetworkID != strings.Repeat("9", 32) || engine.PID != 241 {
		t.Fatal("derived intent rewrote its captured caller-owned comparison values")
	}
	// The last representable next sequence is valid; a further transition
	// must be rejected before uint64 increment can wrap to a fresh generation.
	capture.Head.Sequence = math.MaxUint64 - 1
	raw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	request.CaptureSHA256 = journalCommitTestDigest(raw)
	last, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil || last.Sequence != math.MaxUint64 {
		t.Fatal("last bounded journal sequence was lost", err)
	}
	capture.Head.Sequence = math.MaxUint64
	if _, err := DeriveJournalCommitIntent(capture, request, engine); err == nil {
		t.Fatal("commit sequence wrapped into another journal generation")
	}
}

func TestJournalCommitReplyBindsActualEngineAndNonce(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, true)
	reply, err := NewJournalCommitReply(capture, request, engine)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"pid", "creation", "sid", "logon", "session", "self", "older", "zero"} {
		t.Run(field, func(t *testing.T) {
			changed := engine
			switch field {
			case "pid":
				changed.PID++
			case "creation":
				changed.StartTimeUTCTicks++
			case "sid":
				changed.SID = "S-1-5-18"
			case "logon":
				changed.AuthenticationID++
			case "session":
				changed.SessionID++
			case "self":
				changed = capture.Head.Controller
			case "older":
				changed.StartTimeUTCTicks = capture.Head.Controller.StartTimeUTCTicks - 1
			case "zero":
				changed.PID = 0
			}
			if reply.Validate(capture, request, changed) == nil {
				t.Fatal("commit reply accepted another actual engine identity")
			}
			if field != "pid" && field != "creation" {
				if _, err := NewJournalCommitReply(capture, request, changed); err == nil {
					t.Fatal("commit reply was derived for an unrelated engine token or creation")
				}
			}
		})
	}
	changedRequest := request
	changedRequest.Nonce = strings.Repeat("3", 64)
	if changedRequest.Validate(capture) != nil || reply.Validate(capture, changedRequest, engine) == nil {
		t.Fatal("commit reply did not bind the exact acknowledged request nonce")
	}
	changes := map[string]func(*JournalCommitReply){
		"schema":   func(r *JournalCommitReply) { r.Schema = 0 },
		"kind":     func(r *JournalCommitReply) { r.Kind = "accepted" },
		"request":  func(r *JournalCommitReply) { r.RequestSHA256 = strings.Repeat("5", 64) },
		"intent":   func(r *JournalCommitReply) { r.IntentSHA256 = strings.Repeat("5", 64) },
		"zero":     func(r *JournalCommitReply) { r.Sequence = 0 },
		"sequence": func(r *JournalCommitReply) { r.Sequence++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := reply
			change(&changed)
			if changed.Validate(capture, request, engine) == nil {
				t.Fatal("commit reply accepted an unrelated intent digest or sequence")
			}
		})
	}
}

func TestJournalCommitPreservesProfileBytesAndIntentBound(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, true)
	capture.ProfileID = "شبكة/नोड-🙂"
	raw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseJournalCommitCapture(raw)
	if err != nil || parsed.ProfileID != capture.ProfileID {
		t.Fatal("commit capture normalized the accepted profile identity", err)
	}
	request.CaptureSHA256 = journalCommitTestDigest(raw)
	intent, err := DeriveJournalCommitIntent(capture, request, engine)
	if err != nil || intent.Intent.ProfileID != capture.ProfileID || intent.Intent.Candidate.ProfileID != capture.ProfileID {
		t.Fatal("derived successor substituted its accepted profile identity", err)
	}
	// Valid individual IDs can expand during JSON escaping and appear more
	// than once in an intent. The private capture's larger bound must never
	// authorize a record exceeding the existing durable journal slot limit.
	capture.ProfileID = strings.Repeat("<", 1024)
	capture.Head.Committed.ProfileID = strings.Repeat(">", 1024)
	raw, err = CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal("bounded private capture could not establish the intent-size control", err)
	}
	request.CaptureSHA256 = journalCommitTestDigest(raw)
	if request.Validate(capture) != nil {
		t.Fatal("intent-size control lost its structurally valid request")
	}
	if _, err := DeriveJournalCommitIntent(capture, request, engine); err == nil {
		t.Fatal("larger private capture bypassed the durable intent slot bound")
	}
	if _, err := NewJournalCommitReply(capture, request, engine); err == nil {
		t.Fatal("unwritable oversized intent acquired a commit reply")
	}
}

func journalCommitInvalidEncodings(raw []byte, limit int) map[string][]byte {
	return map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte("x"), limit+1),
		"newline": append(append([]byte(nil), raw...), '\n'), "leading-space": append([]byte(" "), raw...),
		"trailing-object": append(append([]byte(nil), raw...), []byte("{}")...),
		"unknown":         bytes.Replace(raw, []byte(`{"schema":1,`), []byte(`{"unknown":1,"schema":1,`), 1),
		"duplicate":       bytes.Replace(raw, []byte(`"schema":1,`), []byte(`"schema":1,"schema":1,`), 1),
		"missing":         bytes.Replace(raw, []byte(`"schema":1,`), nil, 1),
		"case-alias":      bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"escaped-name":    bytes.Replace(raw, []byte(`"schema"`), []byte(`"\u0073chema"`), 1),
		"null":            bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":null`), 1),
		"string":          bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":"1"`), 1),
		"float":           bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1),
		"exponent":        bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1e0`), 1),
		"overflow":        bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":18446744073709551616`), 1),
	}
}

func TestJournalCommitRejectsNoncanonicalFrames(t *testing.T) {
	capture, request, engine := journalCommitFixture(t, true)
	reply, err := NewJournalCommitReply(capture, request, engine)
	if err != nil {
		t.Fatal(err)
	}
	captureRaw, _ := CanonicalJournalCommitCapture(capture)
	requestRaw, _ := CanonicalJournalCommitRequest(request, capture)
	replyRaw, _ := CanonicalJournalCommitReply(reply, capture, request, engine)
	for name, raw := range journalCommitInvalidEncodings(captureRaw, JournalCommitCaptureLimit) {
		t.Run("capture/"+name, func(t *testing.T) {
			if _, err := ParseJournalCommitCapture(raw); err == nil {
				t.Fatal("noncanonical capture reached the private commit contract")
			}
			if _, err := JournalCommitCaptureSHA256(raw); err == nil {
				t.Fatal("noncanonical capture acquired an identity digest")
			}
		})
	}
	for name, raw := range journalCommitInvalidEncodings(requestRaw, JournalCommitWireLimit) {
		t.Run("request/"+name, func(t *testing.T) {
			if _, err := ParseJournalCommitRequest(raw, capture); err == nil {
				t.Fatal("noncanonical child request reached durable intent derivation")
			}
			if _, err := JournalCommitRequestSHA256(raw, capture); err == nil {
				t.Fatal("noncanonical request acquired an identity digest")
			}
		})
	}
	for name, raw := range journalCommitInvalidEncodings(replyRaw, JournalCommitWireLimit) {
		t.Run("reply/"+name, func(t *testing.T) {
			if _, err := ParseJournalCommitReply(raw, capture, request, engine); err == nil {
				t.Fatal("noncanonical parent reply reached commit comparison")
			}
			if _, err := JournalCommitReplySHA256(raw, capture, request, engine); err == nil {
				t.Fatal("noncanonical reply acquired an identity digest")
			}
		})
	}
	for _, raw := range [][]byte{
		bytes.Replace(captureRaw, []byte(`"head":{`), []byte(`"head":{"unknown":0,`), 1),
		bytes.Replace(captureRaw, []byte(`"committed":{`), []byte(`"committed":{"target":null,`), 1),
		bytes.Replace(captureRaw, []byte(`"transfer":{`), []byte(`"transfer":{"schema":1,`), 1),
	} {
		if _, err := ParseJournalCommitCapture(raw); err == nil {
			t.Fatal("nested duplicate or unknown capture authority was accepted")
		}
	}
	if _, err := ParseJournalCommitRequest(bytes.Replace(requestRaw, []byte(`"candidate":{`), []byte(`"candidate":{"policy":"on-connect",`), 1), capture); err == nil {
		t.Fatal("duplicate candidate policy was accepted")
	}
	// A zero interactive-session number is valid comparison data, so only
	// canonical equality can reject omission of that required numeric field.
	capture.Head.Controller.SessionID = 0
	zeroRaw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJournalCommitCapture(bytes.Replace(zeroRaw, []byte(`,"session_id":0`), nil, 1)); err == nil {
		t.Fatal("missing zero-valued controller identity was accepted")
	}
}
