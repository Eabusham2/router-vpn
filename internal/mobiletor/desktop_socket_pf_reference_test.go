package mobiletor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDesktopPFReferenceCanonicalIdentity(t *testing.T) {
	for _, token := range []string{"1", "417", "18446744073709551615"} {
		request := DesktopDarwinPFReferenceRequest{Schema: 1, Token: token}
		raw, err := EncodeDesktopDarwinPFReferenceRequest(request)
		if err != nil || string(raw) != `{"schema":1,"token":"`+token+`"}` {
			t.Fatal("PF reference lost its exact canonical identity", string(raw), err)
		}
		if actual, err := ParseDesktopDarwinPFReferenceRequest(raw); err != nil || actual != request {
			t.Fatal("PF reference canonical identity did not round trip", actual, err)
		}
	}
	for _, token := range []string{"", "0", "01", "+1", "-1", "1.0", " 1", "1\n", "18446744073709551616", "0x1"} {
		if _, err := EncodeDesktopDarwinPFReferenceRequest(DesktopDarwinPFReferenceRequest{Schema: 1, Token: token}); err == nil {
			t.Fatal("PF reference accepted an ambiguous or overflowing token", token)
		}
	}
}

func TestDesktopPFReferenceMalformedRecord(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"schema":1}`, `{"schema":2,"token":"1"}`, `{"schema":1,"token":1}`, `{"schema":1,"token":null}`, `{"schema":null,"token":"1"}`, `{"schema":1,"token":"1","anchor":"foreign"}`, `{"schema":1,"token":"1","token":"2"}`, `{"schema":1,"schema":1,"token":"1"}`, `{"token":"1","schema":1}`, ` {"schema":1,"token":"1"}`, `{"schema":1,"token":"1"} {}`, strings.Repeat("x", DesktopDarwinPFReferenceLimit+1)} {
		if _, err := ParseDesktopDarwinPFReferenceRequest([]byte(raw)); err == nil {
			t.Fatal("PF reference accepted an incomplete or noncanonical record", raw)
		}
	}
}

func TestDesktopPFReferenceCancelledHasNoAbsenceReceipt(t *testing.T) {
	raw, _ := EncodeDesktopDarwinPFReferenceRequest(DesktopDarwinPFReferenceRequest{Schema: 1, Token: "417"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if body, err := RunDesktopDarwinPFReference(ctx, raw); !errors.Is(err, context.Canceled) || len(body) != 0 {
		t.Fatal("cancelled PF reference inspection fabricated a kernel absence", string(body), err)
	}
	if body, err := RunDesktopDarwinPFReference(nil, raw); err == nil || len(body) != 0 {
		t.Fatal("PF reference inspection accepted a missing capture", string(body), err)
	}
}
