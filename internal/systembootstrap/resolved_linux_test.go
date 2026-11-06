//go:build linux

package systembootstrap

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
)

func TestSystemBootstrapResolvedStubRemainsSeparate(t *testing.T) {
	for _, entry := range []struct {
		name, resolver string
		allow          bool
	}{
		{"exact", "nameserver 127.0.0.53\n", true},
		{"mixed", "nameserver 127.0.0.53\nnameserver 192.0.2.53\n", false},
		{"reverse-mixed", "nameserver 192.0.2.53\nnameserver 127.0.0.53\n", false},
		{"other-loopback", "nameserver 127.0.0.54\n", false},
		{"duplicate", "nameserver 127.0.0.53\nnameserver 127.0.0.53\n", false},
	} {
		t.Run(entry.name, func(t *testing.T) {
			ctx := original(t)
			paths := sources(t, "hosts: files dns\n", "", entry.resolver)
			c, err := capturePolicy(ctx, "vpn.example", paths, uint32(os.Geteuid()), false, true)
			if c != nil {
				defer c.Close()
			}
			if !entry.allow {
				if err == nil {
					t.Fatal("ambiguous stub escaped original authority")
				}
				return
			}
			if err != nil || !c.ResolvedStub() {
				t.Fatalf("exact stub capture failed: %v", err)
			}
			if _, err = c.Resolve(ctx, nil); err == nil {
				t.Fatal("stub observation became direct socket authority")
			}
			if err = os.WriteFile(paths[2], []byte("nameserver 192.0.2.53\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = c.Current(ctx); err == nil {
				t.Fatal("source replacement retained original stub")
			}
		})
	}
}

type localResolvedAuthority struct {
	name      string
	exchanges int
}

func (o *localResolvedAuthority) Current(context.Context) error { return nil }
func (o *localResolvedAuthority) Exchange(context.Context, string, netip.AddrPort, []byte) ([]byte, error) {
	o.exchanges++
	return nil, errors.New("unexpected physical query")
}
func (o *localResolvedAuthority) PreflightResolvedName(_ context.Context, name string, _ bool) ([]netip.Addr, bool, error) {
	o.name = name
	return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, true, nil
}
func TestSystemBootstrapResolvedLocalBeforePhysical(t *testing.T) {
	ctx := original(t)
	c, err := capturePolicy(ctx, "vpn", sources(t, "hosts: files dns\n", "", "nameserver 127.0.0.53\nsearch private.example\n"), uint32(os.Geteuid()), false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	owner := &localResolvedAuthority{}
	answer, err := c.Resolve(ctx, owner)
	if err != nil || len(answer.Addresses) != 1 || owner.exchanges != 0 || owner.name != "vpn.private.example" {
		t.Fatalf("original expanded local name was not handled before network: %+v %+v %v", answer, owner, err)
	}
}
func TestSystemBootstrapResolvedQuestionIdentity(t *testing.T) {
	for _, edns := range []bool{false, true} {
		for _, ad := range []bool{false, true} {
			for _, kind := range []uint16{1, 28} {
				q, err := queryFor("vpn.example", kind, ad, edns)
				if err != nil {
					t.Fatal(err)
				}
				if !QuestionMatchesName(q, "vpn.example") || QuestionMatchesName(q, "other.example") {
					t.Fatal("original question identity lost")
				}
				q[2] |= 0x80
				if QuestionMatchesName(q, "vpn.example") {
					t.Fatal("response admitted as query")
				}
			}
		}
	}
}
