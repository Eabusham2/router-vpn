package standardengine

import (
	"strings"
	"testing"
)

func TestResolvedLocalOriginalDaemonVerdicts(t *testing.T) {
	for _, local := range []bool{true, false} {
		r := ResolvedLocalResult{PolicySHA256: strings.Repeat("a", 64), Name: "actual-daemon-host.example", Local: local}
		if local {
			r.CanonicalName = r.Name
			r.Addresses = []ResolvedDNS{{Address: "127.0.0.2"}}
			r.Flags = 1<<9 | 1<<19
		}
		raw, err := r.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedLocal(raw, r.PolicySHA256, r.Name); err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedLocal(raw, r.PolicySHA256, "helper-hostname.example"); err == nil {
			t.Fatal("helper name replaced original daemon question")
		}
		if _, err = DecodeResolvedLocal(raw, strings.Repeat("b", 64), r.Name); err == nil {
			t.Fatal("local result adopted successor policy")
		}
		if local {
			for _, flags := range []uint64{0, 1<<9 | 1<<20, 1<<9 | 1<<23} {
				r.Flags = flags
				if _, err = r.Canonical(); err == nil {
					t.Fatal("unauthenticated/cached/network reply accepted as local", flags)
				}
			}
		} else {
			r.Flags = 1 << 9
			if _, err = r.Canonical(); err == nil {
				t.Fatal("local miss carried invented answer")
			}
		}
	}
}
