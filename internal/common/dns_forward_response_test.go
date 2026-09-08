package common

import "testing"

func TestDNSForwardingPreservesFailuresWithoutCallingThemProof(t *testing.T) {
	q := probeQueryFixture()
	for _, rcode := range []byte{1, 2, 4, 5} {
		r := append([]byte(nil), q...)
		r[2], r[3] = 0x81, 0x80|rcode
		if err := ValidateDNSForwardResponse(q, r); err != nil {
			t.Fatalf("genuine DNS error %d was not forwarded: %v", rcode, err)
		}
		if err := ValidateDNSProbeResponse(q, r); err == nil {
			t.Fatalf("DNS error %d counted as working proof", rcode)
		}
	}
	r := append([]byte(nil), q...)
	r[2], r[7] = 0x83, 1
	if err := ValidateDNSForwardResponse(q, r); err != nil {
		t.Fatal("client cannot receive TC and retry over TCP:", err)
	}
	if err := ValidateDNSProbeResponse(q, r); err == nil {
		t.Fatal("TC counted as complete probe")
	}
	r[13] = 'z'
	if err := ValidateDNSForwardResponse(q, r); err == nil {
		t.Fatal("TC bypassed question identity")
	}
}

func TestDNSForwardingRejectsMismatchedOrUnframedMessages(t *testing.T) {
	q := probeQueryFixture()
	for _, mutate := range []func([]byte) []byte{
		func(r []byte) []byte { r[0]++; return r },
		func(r []byte) []byte { r[13] = 'z'; return r },
		func(r []byte) []byte { r[3] |= 0x40; return r },
		func(r []byte) []byte { return append(r, 0) },
		func(r []byte) []byte { r[7] = 1; return r },
		func(r []byte) []byte { return r[:12] },
	} {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		if err := ValidateDNSForwardResponse(q, mutate(r)); err == nil {
			t.Fatal("invalid forwarded DNS response accepted")
		}
	}
	// AD and CD are assigned flags, not the reserved Z bit.
	r := append([]byte(nil), q...)
	r[2], r[3] = 0x81, 0xb0
	if err := ValidateDNSForwardResponse(q, r); err != nil {
		t.Fatal("valid DNSSEC signaling bits rejected:", err)
	}
}

func FuzzDNSForwardResponse(f *testing.F) {
	q := probeQueryFixture()
	r := append([]byte(nil), q...)
	r[2] |= 128
	f.Add(q, r)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, q, r []byte) { _ = ValidateDNSForwardResponse(q, r) })
}

func TestDNSForwardQueryRejectsMalformedBeforeUpstreamWork(t *testing.T) {
	q := probeQueryFixture()
	if err := ValidateDNSForwardQuery(q); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(q []byte) []byte { return q[:11] },
		func(q []byte) []byte { return q[:len(q)-1] },
		func(q []byte) []byte { q[2] |= 128; return q },
		func(q []byte) []byte { q[5] = 2; return q },
		func(q []byte) []byte { return append(q, 0) },
	} {
		if err := ValidateDNSForwardQuery(mutate(append([]byte(nil), q...))); err == nil {
			t.Fatal("malformed query accepted")
		}
	}
}
