package hopmeasure

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
)

func orderedImportedHops() []Hop {
	h := orderedHops(3)
	h[0].Kind, h[2].Kind = "private-node", "private-node"
	h[1].Kind, h[1].API, h[1].Token, h[1].Proof = "public-path", "", "", ""
	h[1].Label = "Cumulative custom middle → Cloudflare edge"
	return h
}
func TestOrderedImportedMiddleMeasurementAuthority(t *testing.T) {
	engine := &testEngine{generation: "original"}
	original := orderedImportedHops()
	service, err := NewOrderedImportedMiddleContext(context.Background(), engine, original)
	if err != nil {
		t.Fatal(err)
	}
	if service.hops[1].Kind != "public-path" || service.hops[1].Role != "intermediate" || service.hops[1].API != "" {
		t.Fatal("imported middle acquired private authority")
	}
	if _, err := NewOrderedContext(context.Background(), engine, original); err == nil {
		t.Fatal("schema1 ordered authority broadened")
	}
	for name, mutate := range map[string]func([]Hop) []Hop{
		"two": func(h []Hop) []Hop { return h[:2] }, "four": func(h []Hop) []Hop { return append(h, h[0]) },
		"reorder": func(h []Hop) []Hop { h[0], h[1] = h[1], h[0]; return h },
		"api":     func(h []Hop) []Hop { h[1].API = h[0].API; return h }, "token": func(h []Hop) []Hop { h[1].Token = h[0].Token; return h }, "proof": func(h []Hop) []Hop { h[1].Proof = h[0].Proof; return h },
		"kind": func(h []Hop) []Hop { h[1].Kind = "private-node"; return h }, "role": func(h []Hop) []Hop { h[1].Role = "entry"; return h },
		"tag": func(h []Hop) []Hop { h[1].Tag = "external-entry"; return h }, "wrong-position": func(h []Hop) []Hop { h[1].Tag = strings.Replace(h[1].Tag, "chain-1-", "chain-0-", 1); return h },
		"same-paired-proof": func(h []Hop) []Hop { h[2].Proof = h[0].Proof; return h },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOrderedImportedMiddleContext(context.Background(), engine, mutate(orderedImportedHops())); err == nil {
				t.Fatal("unowned public inventory admitted")
			}
		})
	}
}

// Only the native route boundary is doubled. Both private HTTP identities and
// public TLS transfers run against real listeners with their original policies.
type orderedImportedMeasurementFixture struct {
	private *testEngine
	public  *publicFixture
	hops    []Hop
}

func (e *orderedImportedMeasurementFixture) Identity() string {
	if e.public.Identity() == "" {
		return ""
	}
	return e.private.Identity() + ":" + e.public.Identity()
}
func (e *orderedImportedMeasurementFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	switch tag {
	case e.hops[0].Tag:
		return e.private.Dial(ctx, "entry-wg", address)
	case e.hops[1].Tag:
		return e.public.Dial(ctx, "external-entry", address)
	case e.hops[2].Tag:
		return e.private.Dial(ctx, "proxy", address)
	default:
		return nil, errors.New("foreign ordered prefix")
	}
}
func TestOrderedImportedMiddleTransfersExactBytes(t *testing.T) {
	for _, fault := range []string{"", "untrusted-middle", "middle-retired"} {
		t.Run(fault, func(t *testing.T) {
			legacy, private := fixture(t)
			public := newPublicFixture(t)
			hops := orderedImportedHops()
			for _, position := range []int{0, 2} {
				original := legacy.hops[position/2]
				hops[position].API, hops[position].Token, hops[position].Proof = original.API, original.Token, original.Proof
			}
			engine := &orderedImportedMeasurementFixture{private: private, public: public, hops: hops}
			s, err := NewOrderedImportedMiddleContext(context.Background(), engine, hops)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			if fault != "untrusted-middle" {
				s.publicTLS = public.tls
			}
			if fault == "middle-retired" {
				public.mode.Store("retired")
			}
			request := strings.Repeat("d", 32)
			if err := s.Start(request, 65536); err != nil {
				t.Fatal(err)
			}
			if err := s.Drain(request); err != nil {
				t.Fatal(err)
			}
			result := status(t, s)
			if !result.Complete || !result.Drained {
				t.Fatal("measurement did not drain", result)
			}
			if fault != "" {
				for _, row := range result.Results {
					if row.ID == hops[1].ID && row.Ready {
						t.Fatal("unproved public middle published", row)
					}
				}
				return
			}
			if len(result.Results) != 3 || result.Failure != "" {
				t.Fatal(result)
			}
			for i, row := range result.Results {
				if row.ID != hops[i].ID || row.Role != hops[i].Role || row.Kind != hops[i].Kind || !row.Ready || row.Idle == nil || row.Idle.Samples != 6 {
					t.Fatal("mixed ordered inventory changed", row)
				}
				for _, transfer := range []*Transfer{row.Download, row.Upload} {
					if transfer == nil || transfer.Bytes != 65536 || transfer.Seconds <= 0 || math.Abs(transfer.Mbps-float64(transfer.Bytes)*8/transfer.Seconds/1e6) > 1e-9 {
						t.Fatal("fabricated prefix transfer", transfer)
					}
				}
			}
			if public.uploaded.Load() != 65536 || public.downloaded.Load() < 65536 {
				t.Fatal("custom prefix byte receipts missing")
			}
		})
	}
}
