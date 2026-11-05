package dnsmeasure

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestPublicAddressExtractionKeepsOnlyExactQuestionChain(t *testing.T) {
	query, _ := newQuery()
	valid := answer(query)
	got, err := PublicIPv4Answers(query, valid)
	if err != nil || len(got) != 1 || !got[0].Is4() {
		t.Fatalf("valid original answer: %v %v", got, err)
	}
	base := got[0]
	// An unrelated additional public answer must never become a dial target.
	withExtra := append([]byte(nil), valid...)
	withExtra[11] = 1
	withExtra = append(withExtra, 1, 'x', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 8, 8, 8, 8)
	got, err = PublicIPv4Answers(query, withExtra)
	if err != nil || !reflect.DeepEqual(got, []netip.Addr{base}) {
		t.Fatalf("unrelated additional answer adopted: %v %v", got, err)
	}
	alias := []byte{3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	chain := append([]byte(nil), query...)
	chain[2], chain[3], chain[7] = 0x81, 0x80, 2
	chain = append(chain, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, byte(len(alias)))
	at := len(chain)
	chain = append(chain, alias...)
	chain = append(chain, 0xc0, byte(at), 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34)
	got, err = PublicIPv4Answers(query, chain)
	if err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("93.184.216.34")}) {
		t.Fatalf("actual CNAME target: %v %v", got, err)
	}
	for _, name := range []string{"different-question", "private-target", "truncated", "trailing", "wrong-type"} {
		t.Run(name, func(t *testing.T) {
			q, b := append([]byte(nil), query...), append([]byte(nil), valid...)
			switch name {
			case "different-question":
				b[13] = 'z'
			case "private-target":
				copy(b[len(b)-4:], []byte{192, 168, 1, 1})
			case "truncated":
				b = b[:len(b)-1]
			case "trailing":
				b = append(b, 0)
			case "wrong-type":
				q[len(q)-3] = 28
				b[len(q)-3] = 28
			}
			if got, err := PublicIPv4Answers(q, b); err == nil || len(got) != 0 {
				t.Fatalf("invalid source supplied addresses: %v %v", got, err)
			}
		})
	}
}

func TestPublicAddressExtractionBoundsAndDeduplicates(t *testing.T) {
	query, _ := newQuery()
	makeAnswer := func(count int, repeated bool) []byte {
		b := append([]byte(nil), query...)
		b[2], b[3], b[7] = 0x81, 0x80, byte(count)
		for i := 0; i < count; i++ {
			last := byte(i + 1)
			if repeated {
				last = 1
			}
			b = append(b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, last)
		}
		return b
	}
	got, err := PublicIPv4Answers(query, makeAnswer(20, true))
	if err != nil || len(got) != 1 {
		t.Fatalf("same address should deduplicate: %v %v", got, err)
	}
	if got, err := PublicIPv4Answers(query, makeAnswer(17, false)); err == nil || got != nil {
		t.Fatalf("unbounded target set: %v %v", got, err)
	}
}
