package hopmeasure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func importedNodesHops(count int, positions ...int) []Hop {
	hops := orderedHops(count)
	for i := range hops {
		hops[i].Kind = "private-node"
	}
	for _, i := range positions {
		hops[i].Kind, hops[i].API, hops[i].Token, hops[i].Proof = "public-path", "", "", ""
		hops[i].Label = fmt.Sprintf("Cumulative path through independent import %d → Cloudflare edge", i)
	}
	return hops
}

func TestOrderedImportedNodesRetainsEveryInteriorInventory(t *testing.T) {
	for count := 3; count <= 8; count++ {
		for mask := 1; mask < 1<<(count-2); mask++ {
			t.Run(fmt.Sprintf("%d-%02x", count, mask), func(t *testing.T) {
				var positions []int
				for i := 1; i < count-1; i++ {
					if mask&(1<<(i-1)) != 0 {
						positions = append(positions, i)
					}
				}
				hops := importedNodesHops(count, positions...)
				original := append([]Hop(nil), hops...)
				engine := &testEngine{generation: "original-imported-node-owner"}
				service, err := NewOrderedImportedNodesContext(t.Context(), engine, hops)
				if err != nil || service == nil || service.engine != engine || len(service.hops) != count {
					t.Fatal("complete independent public inventory refused", err)
				}
				for i := range service.hops {
					retained := service.hops[i]
					// Empty private labels are completed by the existing validator.
					retained.Label = original[i].Label
					if retained != original[i] {
						t.Fatal("position or original credential changed", i)
					}
				}
				frozen := append([]Hop(nil), service.hops...)
				for i := range hops {
					hops[i] = Hop{ID: "replacement", Kind: "private-node", Token: "foreign"}
				}
				if !reflect.DeepEqual(service.hops, frozen) {
					t.Fatal("caller replaced original captured inventory")
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestOrderedImportedNodesRejectsForeignAuthority(t *testing.T) {
	for name, mutate := range map[string]func([]Hop) []Hop{
		"two":               func(h []Hop) []Hop { return h[:2] },
		"nine":              func([]Hop) []Hop { return importedNodesHops(9, 1, 7) },
		"no-public":         func([]Hop) []Hop { return importedNodesHops(6) },
		"public-entry":      func([]Hop) []Hop { return importedNodesHops(6, 0, 1, 4) },
		"public-final":      func([]Hop) []Hop { return importedNodesHops(6, 1, 4, 5) },
		"omitted-position":  func(h []Hop) []Hop { return append(h[:2], h[3:]...) },
		"swapped-imports":   func(h []Hop) []Hop { h[1], h[4] = h[4], h[1]; return h },
		"wrong-role":        func(h []Hop) []Hop { h[1].Role = "exit"; return h },
		"wrong-position":    func(h []Hop) []Hop { h[1].Tag = h[4].Tag; return h },
		"server-tag":        func(h []Hop) []Hop { h[1].Tag = "routervpn-chain-server-1-" + strings.Repeat("a", 16); return h },
		"legacy-tag":        func(h []Hop) []Hop { h[1].Tag = "external-entry"; return h },
		"dns-tag":           func(h []Hop) []Hop { h[1].Tag = strings.Replace(h[1].Tag, "-node-", "-dns-", 1); return h },
		"duplicate-import":  func(h []Hop) []Hop { h[4].ID = h[1].ID; return h },
		"duplicate-private": func(h []Hop) []Hop { h[2].Proof = h[0].Proof; return h },
		"empty-private":     func(h []Hop) []Hop { h[2].Proof = ""; return h },
		"private-api":       func(h []Hop) []Hop { h[1].API = h[0].API; return h },
		"private-token":     func(h []Hop) []Hop { h[1].Token = h[0].Token; return h },
		"private-proof":     func(h []Hop) []Hop { h[1].Proof = h[0].Proof; return h },
		"private-public-ip": func(h []Hop) []Hop { h[2].API = "http://1.1.1.1:8787"; return h },
		"blank-kind":        func(h []Hop) []Hop { h[2].Kind = ""; return h },
		"unknown-kind":      func(h []Hop) []Hop { h[1].Kind = "saved-node"; return h },
		"foreign-label":     func(h []Hop) []Hop { h[1].Label = "captured\nforeign"; return h },
	} {
		t.Run(name, func(t *testing.T) {
			if service, err := NewOrderedImportedNodesContext(t.Context(), &testEngine{generation: "original"}, mutate(importedNodesHops(6, 1, 4))); err == nil || service != nil {
				t.Fatal("multiple imports acquired changed positional authority")
			}
		})
	}
}

func TestOrderedImportedNodesDoesNotWidenOlderConstructors(t *testing.T) {
	constructors := map[string]func(context.Context, Engine, []Hop) (*Service, error){
		"ordinary": NewContext, "ordered-private": NewOrderedContext,
		"imported-trio": NewOrderedImportedMiddleContext, "imported-prefix": NewOrderedImportedSSPrefixContext,
		"connect-prefix": NewOrderedCONNECTPrefixContext, "socks-prefix": NewOrderedSOCKSPrefixContext,
		"openvpn-prefix": NewOrderedOpenVPNPrefixContext, "server-private": NewOrderedServerContext,
		"server-imported-trio": NewOrderedImportedServerContext, "server-imported-prefix": NewOrderedImportedSSServerPrefixContext,
		"server-connect-prefix": NewOrderedCONNECTServerPrefixContext, "server-socks-prefix": NewOrderedSOCKSServerPrefixContext,
		"server-openvpn-prefix": NewOrderedOpenVPNServerPrefixContext,
	}
	for name, construct := range constructors {
		for _, positions := range [][]int{{1}, {1, 2}} {
			t.Run(fmt.Sprintf("%s-%v", name, positions), func(t *testing.T) {
				if service, err := construct(t.Context(), &testEngine{generation: "original"}, importedNodesHops(4, positions...)); err == nil || service != nil {
					t.Fatal("older constructor acquired multiple-import or earlier-public authority")
				}
			})
		}
	}
}

func TestOrderedImportedNodesRetainsConstructorContextAndLifetime(t *testing.T) {
	for _, phase := range []string{"current", "nil", "cancel-before", "cancel-during", "refused", "empty"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int32
			engine := &observedMeasurementEngine{observe: func(observed context.Context) (string, error) {
				calls.Add(1)
				if observed != ctx {
					return "", errors.New("constructor replaced caller context")
				}
				if phase == "cancel-during" {
					cancel()
				}
				if phase == "refused" {
					return "", errors.New("original owner refused observation")
				}
				if phase == "empty" {
					return "", nil
				}
				return "captured-context-owner", nil
			}}
			if phase == "cancel-before" {
				cancel()
			}
			if phase == "nil" {
				ctx = nil
			}
			service, err := NewOrderedImportedNodesContext(ctx, engine, importedNodesHops(4, 1, 2))
			if phase == "current" {
				if err != nil || service == nil {
					t.Fatal(err)
				}
				cancel()
				engine.setObserve(nil)
				request := strings.Repeat("a", 32)
				if err := service.start(request, func(ctx context.Context) { <-ctx.Done() }); err != nil {
					t.Fatal("constructor cancellation retired the returned service", err)
				}
				service.Cancel(request)
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if service.valid(t.Context()) == nil {
					t.Fatal("closed original lifetime remained usable")
				}
			} else if err == nil || service != nil {
				t.Fatal("refused or expired original owner was admitted")
			}
			if engine.legacy.Load() != 0 || (phase == "nil" || phase == "cancel-before") && calls.Load() != 0 {
				t.Fatal("detached or already-cancelled observation used")
			}
		})
	}
}

// Only tag-to-listener routing is doubled. The paired entry/final HTTP proof
// and both separately certified public HTTPS providers execute real requests.
type importedNodesMeasurementFixture struct {
	private  *testEngine
	public   [2]*publicFixture
	hops     []Hop
	held     atomic.Bool
	releases atomic.Int32
	before   func(context.Context) error
}

func (e *importedNodesMeasurementFixture) Identity() string {
	if e.public[0].Identity() == "" || e.public[1].Identity() == "" {
		return ""
	}
	return e.private.Identity() + ":two-original-public-routes"
}
func (e *importedNodesMeasurementFixture) IdentityContext(ctx context.Context) (string, error) {
	return e.Identity(), ctx.Err()
}
func (e *importedNodesMeasurementFixture) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	switch tag {
	case e.hops[0].Tag:
		return e.private.Dial(ctx, "entry-wg", address)
	case e.hops[1].Tag:
		return e.public[0].Dial(ctx, "external-entry", address)
	case e.hops[2].Tag:
		return e.public[1].Dial(ctx, "external-entry", address)
	case e.hops[3].Tag:
		return e.private.Dial(ctx, "proxy", address)
	default:
		return nil, errors.New("uncaptured independent prefix")
	}
}
func (e *importedNodesMeasurementFixture) VerifyMeasurement(ctx context.Context) error {
	if e.before != nil {
		return e.before(ctx)
	}
	return ctx.Err()
}
func (e *importedNodesMeasurementFixture) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.held.CompareAndSwap(false, true) {
		return nil, errors.New("original activity occupied")
	}
	return func() { e.releases.Add(1); e.held.Store(false) }, nil
}

func importedNodesLatencyFixture(t *testing.T) (*OrderedLatencyService, *importedNodesMeasurementFixture) {
	t.Helper()
	legacy, private := fixture(t)
	hops := importedNodesHops(4, 1, 2)
	for i, position := range []int{0, 3} {
		original := legacy.hops[i]
		hops[position].API, hops[position].Token, hops[position].Proof = original.API, original.Token, original.Proof
	}
	engine := &importedNodesMeasurementFixture{private: private, public: [2]*publicFixture{newPublicFixture(t), newPublicFixture(t)}, hops: append([]Hop(nil), hops...)}
	base, err := NewOrderedImportedNodesContext(t.Context(), engine, hops)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	for _, public := range engine.public {
		roots.AddCert(public.server.Certificate())
	}
	base.publicTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	t.Cleanup(func() {
		if err := base.Close(); err != nil {
			t.Error(err)
		}
	})
	service, err := NewOrderedLatencyContext(t.Context(), base, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, engine
}

func TestOrderedImportedNodesMeasuresFiftyResponsesThroughEachOriginalTag(t *testing.T) {
	service, engine := importedNodesLatencyFixture(t)
	for position, hop := range engine.hops {
		request := fmt.Sprintf("%032x", position+1)
		if err := service.Start(request, hop.ID); err != nil {
			t.Fatal(err)
		}
		state := orderedLatencyResult(t, service, request)
		if state.Failure != "" || len(state.Results) != 1 {
			t.Fatal(state)
		}
		row := state.Results[0]
		if !row.Ready || row.ID != hop.ID || row.Kind != hop.Kind || row.Role != hop.Role || row.Label != hop.Label && hop.Label != "" || row.Benchmark == nil || row.Benchmark.Attempts != 50 || row.Benchmark.Failed != 0 || row.Benchmark.Distribution == nil || row.Benchmark.Distribution.Samples != 50 {
			t.Fatal("independent prefix lost its exact fifty-response result", row)
		}
		metric := "routed-private-response-including-connection"
		if hop.Kind == "public-path" {
			metric = "routed-https-response-after-tls"
		}
		if row.Benchmark.Measurement != metric {
			t.Fatal("private and public response timing conflated")
		}
		var receipt OrderedLatencyReceipt
		if json.Unmarshal([]byte(service.SavedJSON(hop.ID)), &receipt) != nil || receipt.Position != position || receipt.NodeID != hop.ID || receipt.Request != request || receipt.SourceSHA256 != strings.Repeat("a", 64) || receipt.ConfigSHA256 != strings.Repeat("b", 64) {
			t.Fatal("independent prefix receipt changed its complete source or position")
		}
		if engine.held.Load() || engine.releases.Load() != int32(position+1) || service.Start(request, hop.ID) == nil {
			t.Fatal("original activity failed to join or request replayed")
		}
	}
	engine.private.mu.Lock()
	entry, final := engine.private.requests["entry-wg"], engine.private.requests["proxy"]
	engine.private.mu.Unlock()
	if entry != 50 || final != 50 {
		t.Fatal("paired entry/final original response inventory changed", entry, final)
	}
	for position, public := range engine.public {
		public.mu.Lock()
		calls := len(public.tags)
		public.mu.Unlock()
		if calls != 50 || public.downloaded.Load() != 50 {
			t.Fatal("one imported route borrowed another's samples", position, calls, public.downloaded.Load())
		}
	}
}

func TestOrderedImportedNodesRefusesIncompleteTLSStaleAndCancelledResults(t *testing.T) {
	for _, fault := range []string{"failed-fiftieth", "untrusted-second", "generation-replaced", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			service, engine := importedNodesLatencyFixture(t)
			first, second := engine.hops[1], engine.hops[2]
			for i, hop := range []Hop{first, second} {
				request := fmt.Sprintf("%032x", i+1)
				if err := service.Start(request, hop.ID); err != nil {
					t.Fatal(err)
				}
				state := orderedLatencyResult(t, service, request)
				if state.Failure != "" || len(state.Results) != 1 || !state.Results[0].Ready {
					t.Fatal("baseline did not reach both original TLS providers", state)
				}
			}
			savedFirst, savedSecond := service.SavedJSON(first.ID), service.SavedJSON(second.ID)
			beforeFirst, beforeSecond := engine.public[0].downloaded.Load(), engine.public[1].downloaded.Load()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch fault {
			case "failed-fiftieth":
				var attempts atomic.Int32
				engine.public[1].dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) == 50 {
						return nil, errors.New("second import's original fiftieth connection refused")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp", engine.public[1].server.Listener.Addr().String())
				}
			case "untrusted-second":
				service.service.publicTLS = engine.public[0].tls
			case "generation-replaced", "cancel":
				var observations atomic.Int32
				engine.before = func(ctx context.Context) error {
					if observations.Add(1) == 12 {
						if fault == "cancel" {
							cancel()
						} else {
							engine.private.mu.Lock()
							engine.private.generation = "replacement-original-engine"
							engine.private.mu.Unlock()
						}
					}
					return ctx.Err()
				}
			}
			request := strings.Repeat("c", 32)
			if err := service.StartContext(ctx, request, second.ID); err != nil {
				t.Fatal("control did not enter the original selected worker", err)
			}
			state := orderedLatencyResult(t, service, request)
			for _, row := range state.Results {
				if row.Ready || row.Benchmark != nil {
					t.Fatal("partial or substituted imported response published", row)
				}
			}
			if service.SavedJSON(first.ID) != savedFirst || service.SavedJSON(second.ID) != savedSecond || engine.held.Load() || engine.releases.Load() != 3 {
				t.Fatal("failed second import replaced an original result or escaped join")
			}
			if engine.public[0].downloaded.Load() != beforeFirst {
				t.Fatal("second import's failed measurement used the first import")
			}
			actual := engine.public[1].downloaded.Load() - beforeSecond
			if fault == "failed-fiftieth" && actual != 49 || fault == "untrusted-second" && actual != 0 || (fault == "generation-replaced" || fault == "cancel") && (actual == 0 || actual >= 50) {
				t.Fatal("control did not reach its intended original response boundary", actual)
			}
		})
	}
}
