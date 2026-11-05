package dnsmeasure

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func bootstrapAnswerFixture(t *testing.T, ipv6 bool) ([]byte, []byte) {
	t.Helper()
	q, e := TransportBootstrapQuery("node.example", ipv6)
	if e != nil {
		t.Fatal(e)
	}
	r := append([]byte(nil), q...)
	r[2] = 0x81
	r[3] = 0x80
	r[7] = 1
	typ, size, ip := byte(1), byte(4), netip.MustParseAddr("192.168.40.2").AsSlice()
	if ipv6 {
		typ, size, ip = 28, 16, netip.MustParseAddr("fd00::2").AsSlice()
	}
	r = append(r, 0xc0, 12, 0, typ, 0, 1, 0, 0, 0, 30, 0, size)
	r = append(r, ip...)
	return q, r
}
func TestTransportBootstrapExactQuestionAndFamilies(t *testing.T) {
	for _, v := range []bool{false, true} {
		q, r := bootstrapAnswerFixture(t, v)
		a, e := TransportBootstrapAnswers(q, r)
		if e != nil || len(a) != 1 || a[0].Is6() != v {
			t.Fatalf("%v %v", a, e)
		}
		empty := append([]byte(nil), q...)
		empty[2] = 0x81
		empty[3] = 0x80
		if a, e := TransportBootstrapAnswers(q, empty); e != nil || len(a) != 0 {
			t.Fatalf("empty family: %v %v", a, e)
		}
	}
}
func TestTransportBootstrapRejectsForeignOrMalformedAnswer(t *testing.T) {
	for _, name := range []string{"id", "question", "truncated", "nxdomain", "trailing", "short-address", "foreign-owner", "mapped", "too-many"} {
		t.Run(name, func(t *testing.T) {
			q, r := bootstrapAnswerFixture(t, name == "mapped")
			switch name {
			case "id":
				r[0] ^= 1
			case "question":
				r[13] = 'x'
			case "truncated":
				r[2] |= 2
			case "nxdomain":
				r[3] |= 3
			case "trailing":
				r = append(r, 0)
			case "short-address":
				r = r[:len(r)-1]
			case "foreign-owner":
				r[len(q)+1] = 18
			case "mapped":
				copy(r[len(r)-16:], netip.MustParseAddr("::ffff:192.0.2.1").AsSlice())
			case "too-many":
				binary.BigEndian.PutUint16(r[6:8], 129)
			}
			a, e := TransportBootstrapAnswers(q, r)
			if e == nil && len(a) > 0 {
				t.Fatalf("foreign answer adopted: %v", a)
			}
			if name != "foreign-owner" && e == nil {
				t.Fatal("malformed packet accepted")
			}
		})
	}
}
func TestTransportBootstrapBoundedAliasChain(t *testing.T) {
	q, r := bootstrapAnswerFixture(t, false)
	base := append([]byte(nil), q...)
	base[2] = 0x81
	base[3] = 0x80
	base[7] = 2
	alias := []byte{5, 'a', 'l', 'i', 'a', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	base = append(base, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, byte(len(alias)))
	aliasOffset := len(base)
	base = append(base, alias...)
	rr := append([]byte(nil), r[len(q):]...)
	rr[1] = byte(aliasOffset)
	base = append(base, rr...)
	a, e := TransportBootstrapAnswers(q, base)
	if e != nil || len(a) != 1 {
		t.Fatalf("exact alias: %v %v", a, e)
	}
	// A CNAME to itself cannot be rescued by an unrelated answer record.
	loop := append([]byte(nil), q...)
	loop[2] = 0x81
	loop[3] = 0x80
	loop[7] = 1
	loop = append(loop, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xc0, 12)
	if _, e := TransportBootstrapAnswers(q, loop); e == nil {
		t.Fatal("cyclic alias accepted")
	}
}
func TestTransportBootstrapDoesNotExpandSearchNames(t *testing.T) {
	for _, s := range []string{"", " x.example", "x.example.", "x..example", "-x.example", "x_.example", "x.example/other", "*.example"} {
		if _, e := TransportBootstrapQuery(s, false); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
