//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobiletor"
	"sync"
	"testing"
	"time"
)

type resolvedScopeFixture struct {
	mu              sync.Mutex
	active, entered int
	barrier         chan struct{}
	count           int
	run             func(context.Context, mobiletor.DesktopLinuxBootstrapDNSUpstream, []byte) ([]byte, error)
	closed          bool
	closeErr        error
}

func (f *resolvedScopeFixture) Exchange(ctx context.Context, s mobiletor.DesktopLinuxBootstrapDNSUpstream, q []byte) ([]byte, error) {
	f.mu.Lock()
	f.active++
	f.entered++
	if f.entered == f.count {
		close(f.barrier)
	}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
	select {
	case <-f.barrier:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return f.run(ctx, s, q)
}
func (f *resolvedScopeFixture) Close(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}
func resolvedScopeAnswer(q []byte, code byte) []byte {
	a := append([]byte(nil), q...)
	a[2] = 0x81
	a[3] = 0x80 | code
	return a
}
func TestResolvedGroupIndependentScopes(t *testing.T) {
	q, e := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"parallel-winner-joins-loser", "negative-cannot-cancel-positive", "invalid-cannot-cancel-positive", "all-negative", "cleanup-failure", "cancelled-original", "udp-truncation-original-tcp"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			servers := []resolvedQueryScope{{DesktopLinuxBootstrapDNSUpstream: mobiletor.DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("192.0.2.53:2053"), Network: "udp", InterfaceIndex: 7}}, {DesktopLinuxBootstrapDNSUpstream: mobiletor.DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("192.0.2.54:3053"), Network: "udp", InterfaceIndex: 8}}}
			f := &resolvedScopeFixture{barrier: make(chan struct{}), count: 2}
			first := make(chan struct{})
			f.run = func(work context.Context, s mobiletor.DesktopLinuxBootstrapDNSUpstream, question []byte) ([]byte, error) {
				if s.InterfaceIndex == 7 {
					switch name {
					case "negative-cannot-cancel-positive", "all-negative":
						close(first)
						return resolvedScopeAnswer(question, 3), nil
					case "invalid-cannot-cancel-positive":
						close(first)
						a := resolvedScopeAnswer(question, 0)
						a[0] ^= 1
						return a, nil
					case "cancelled-original":
						cancel()
						<-work.Done()
						return nil, work.Err()
					case "udp-truncation-original-tcp":
						if s.Endpoint != servers[0].Endpoint {
							t.Error("TCP changed original tuple")
						}
						if s.Network == "udp" {
							a := resolvedScopeAnswer(question, 0)
							a[2] |= 2
							return a, nil
						}
						if s.Network != "tcp" {
							t.Error("truncation used wrong transport")
						}
					}
					return resolvedScopeAnswer(question, 0), nil
				}
				switch name {
				case "negative-cannot-cancel-positive", "invalid-cannot-cancel-positive":
					select {
					case <-first:
						return resolvedScopeAnswer(question, 0), nil
					case <-work.Done():
						return nil, errors.New("fast negative cancelled positive scope")
					}
				case "all-negative":
					return resolvedScopeAnswer(question, 3), nil
				default:
					<-work.Done()
					return nil, work.Err()
				}
			}
			if name == "cleanup-failure" {
				f.closeErr = errors.New("original grant remains")
			}
			answer, err := resolveOriginalScopes(ctx, f, servers, q)
			f.mu.Lock()
			active, closed, entered := f.active, f.closed, f.entered
			f.mu.Unlock()
			if !closed || entered < 2 {
				t.Fatal("scopes did not enter before original group retirement", entered, closed)
			}
			if name == "cleanup-failure" {
				var retained *resolvedGroupRetirementError
				if answer != nil || !errors.As(err, &retained) {
					t.Fatal("unjoined grant allowed adoption", err)
				}
				return
			}
			if active != 0 {
				t.Fatal("answer escaped unjoined worker")
			}
			if name == "cancelled-original" {
				if answer != nil || err == nil {
					t.Fatal("cancelled original adopted result")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := byte(0)
			if name == "all-negative" {
				want = 3
			}
			if answer[3]&15 != want {
				t.Fatal("wrong independent-scope winner")
			}
		})
	}
}

func TestResolvedHelperFrameLockIsBounded(t *testing.T) {
	h := &linuxResolvedHelper{}
	h.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := h.observe(ctx, "vpn.example"); err == nil {
		t.Fatal("cancelled concurrent observer entered frame stream")
	}
	h.mu.Unlock()
	if err := h.current(context.Background()); err == nil {
		t.Fatal("empty helper acquired authority")
	}
}

func TestResolvedFrameScopeCancellation(t *testing.T) {
	operation, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	scope, cancel := context.WithCancel(operation)
	frame, finish, err := resolvedFrameContext(scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	scopeDeadline, _ := scope.Deadline()
	frameDeadline, _ := frame.Deadline()
	cancel()
	if frame.Err() != nil || !scopeDeadline.Equal(frameDeadline) {
		t.Fatal("loser cancellation abandoned or renewed shared frame")
	}
	stop()
	if frame.Err() == nil {
		t.Fatal("original operation cancellation was ignored")
	}
}

type resolvedOpportunisticFixture struct {
	resolvedScopeFixture
	answer []byte
	calls  int
}

func (f *resolvedOpportunisticFixture) ExchangeOpportunistic(ctx context.Context, capability *mobiletor.DesktopLinuxOpportunisticDNS, question []byte, current func(context.Context) error) ([]byte, error) {
	f.calls++
	if capability == nil || current == nil {
		return nil, errors.New("captured opportunistic owner omitted")
	}
	if err := current(ctx); err != nil {
		return nil, err
	}
	if err := current(ctx); err != nil {
		return nil, err
	}
	return f.answer, nil
}
func TestResolvedGroupOpportunisticDispatch(t *testing.T) {
	q, err := dnsmeasure.TransportBootstrapQuery("vpn.example", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"captured-policy", "owner-changed", "terminal-truncation-not-retried"} {
		t.Run(name, func(t *testing.T) {
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSOverTLS = "opportunistic"
			scopes, err := resolvedSelectedUpstreams(policy, "vpn.example", "udp")
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			scopes[0].current = func(context.Context) error {
				calls++
				if name == "owner-changed" {
					return errors.New("original daemon changed")
				}
				return nil
			}
			f := &resolvedOpportunisticFixture{answer: resolvedScopeAnswer(q, 0)}
			f.resolvedScopeFixture.run = func(context.Context, mobiletor.DesktopLinuxBootstrapDNSUpstream, []byte) ([]byte, error) {
				return nil, errors.New("opportunistic escaped typed transport")
			}
			if name == "terminal-truncation-not-retried" {
				f.answer[2] |= 2
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			answer, err := resolveOriginalScopes(ctx, f, scopes, q)
			if f.calls != 1 || calls == 0 || !f.closed {
				t.Fatal("original opportunistic owner or joined group omitted", f.calls, calls, f.closed)
			}
			if name == "captured-policy" {
				if err != nil || answer == nil {
					t.Fatal(err)
				}
			} else if err == nil || answer != nil {
				t.Fatal("invalid opportunistic result adopted")
			}
		})
	}
}
