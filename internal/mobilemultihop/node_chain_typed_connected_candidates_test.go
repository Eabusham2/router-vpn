package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"router-vpn/internal/hopmeasure"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The complete typed source and all authenticated private/public proof HTTP
// execute; packet/native-manager pointers are the original explicit doubles.
// Candidate samples use real loopback TCP and the captured prefix tag/address.
type typedConnectedSOCKSReader struct{ *nodeChainSOCKSTestEngine }
type typedConnectedCONNECTReader struct{ *nodeChainCONNECTTestEngine }

type typedConnectedOwner struct {
	candidateOwnerFixture
	socks    atomic.Pointer[NodeChainSOCKSRuntime]
	connect  atomic.Pointer[NodeChainCONNECTRuntime]
	callback func()
}

func (o *typedConnectedOwner) MeasurementSOCKSContext(ctx context.Context) (*NodeChainSOCKSRuntime, error) {
	return o.socks.Load(), ctx.Err()
}
func (o *typedConnectedOwner) MeasurementCONNECTContext(ctx context.Context) (*NodeChainCONNECTRuntime, error) {
	return o.connect.Load(), ctx.Err()
}
func (o *typedConnectedOwner) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	if o.callback != nil {
		o.callback()
	}
	return o.candidateOwnerFixture.CandidateInventoryCurrentContext(ctx, capture)
}

type typedConnectedFixture struct {
	socks         *NodeChainSOCKSRuntime
	connect       *NodeChainCONNECTRuntime
	socksEngine   *nodeChainSOCKSTestEngine
	connectEngine *nodeChainCONNECTTestEngine
	chain         *NodeChain
	plan          *NodeChainCandidatePlan
	owner         *typedConnectedOwner
	route         *candidateRouteFixture
	inventory     string
	run           func(context.Context) error
	service       func(context.Context) (*hopmeasure.CandidateService, error)
}

func newTypedConnectedFixture(t *testing.T, family string, count int, run bool) *typedConnectedFixture {
	t.Helper()
	source, inventory := typedCandidatePreparationSource(t, family, count)
	f := &typedConnectedFixture{inventory: inventory, owner: &typedConnectedOwner{}}
	if family == "socks" {
		original, err := NewNodeChainSOCKSSource(startJSON(t, source))
		if err != nil {
			t.Fatal(err)
		}
		f.socks, f.socksEngine = newNodeChainSOCKSRuntimeSourceFixture(t, original)
		f.chain = f.socks.chain
		f.owner.socks.Store(f.socks)
		plan, err := NewNodeChainSOCKSConnectedCandidatePlan(f.socks, count-3, inventory)
		if err != nil {
			t.Fatal(err)
		}
		f.plan = plan.plan
		f.service = func(ctx context.Context) (*hopmeasure.CandidateService, error) {
			return plan.NewMeasurementContext(ctx, f.owner)
		}
		f.run = func(ctx context.Context) error { return f.socks.Run(ctx, f.socksEngine) }
	} else {
		original, err := NewNodeChainCONNECTSource(startJSON(t, source))
		if err != nil {
			t.Fatal(err)
		}
		f.connect, f.connectEngine = newNodeChainCONNECTRuntimeSourceFixture(t, original)
		f.chain = f.connect.chain
		f.owner.connect.Store(f.connect)
		plan, err := NewNodeChainCONNECTConnectedCandidatePlan(f.connect, count-3, inventory)
		if err != nil {
			t.Fatal(err)
		}
		f.plan = plan.plan
		f.service = func(ctx context.Context) (*hopmeasure.CandidateService, error) {
			return plan.NewMeasurementContext(ctx, f.owner)
		}
		f.run = func(ctx context.Context) error { return f.connect.Run(ctx, f.connectEngine) }
	}
	f.owner.chain = f.chain
	f.owner.capture = f.plan.CaptureSHA256()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	f.route = &candidateRouteFixture{tag: f.plan.prefix.Tag, address: f.plan.targets[0].Address, peer: listener.Addr().String()}
	hook := func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
		if address != f.route.address {
			return nil, nil, false
		}
		c, e := f.route.Dial(ctx, tag, address)
		return c, e, true
	}
	if f.socksEngine != nil {
		f.socksEngine.dialHook = hook
	} else {
		f.connectEngine.dialHook = hook
	}
	if run {
		if err := f.run(context.Background()); err != nil {
			t.Fatal("original complete typed proofs failed", err)
		}
	}
	return f
}
func TestNodeChainTypedConnectedCandidateSource(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				f := newTypedConnectedFixture(t, family, count, false)
				if _, err := f.service(t.Context()); err == nil {
					t.Fatal("unproved typed runtime acquired connected candidate authority")
				}
				if _, err := NewNodeChain(f.chain.sourceJSON); err == nil {
					t.Fatal("typed connected candidate widened generic parser")
				}
				var value any = f.connect
				if f.socks != nil {
					value = f.socks
				}
				for _, name := range []string{"NewCandidatePlan", "BindNative", "LaunchInput", "NodeChain"} {
					if _, ok := reflect.TypeOf(value).MethodByName(name); ok {
						t.Fatal("typed candidate exposed generic runtime method", name)
					}
				}
				for pos := -1; pos <= count; pos++ {
					var meta string
					var err error
					if f.socks != nil {
						var p *NodeChainSOCKSConnectedCandidatePlan
						p, err = NewNodeChainSOCKSConnectedCandidatePlan(f.socks, pos, f.inventory)
						if err == nil {
							if p.original != f.socks || p.plan.chain != f.chain {
								t.Fatal("typed candidate detached original runtime")
							}
							meta = p.Metadata()
						}
					} else {
						var p *NodeChainCONNECTConnectedCandidatePlan
						p, err = NewNodeChainCONNECTConnectedCandidatePlan(f.connect, pos, f.inventory)
						if err == nil {
							if p.original != f.connect || p.plan.chain != f.chain {
								t.Fatal("typed candidate detached original runtime")
							}
							meta = p.Metadata()
						}
					}
					if pos >= 0 && pos < count-2 {
						if err != nil {
							t.Fatal(err)
						}
						var m map[string]any
						if json.Unmarshal([]byte(meta), &m) != nil || m["source_sha256"] != f.chain.SourceSHA256() || m["config_sha256"] != f.chain.ConfigSHA256() {
							t.Fatal("connected candidate lost complete typed source/config")
						}
					} else if err == nil {
						t.Fatal("typed candidate admitted imported/final/foreign prefix", pos)
					}
				}
				if f.socks != nil {
					copied := *f.socks
					if _, err := NewNodeChainSOCKSConnectedCandidatePlan(&copied, 0, f.inventory); err == nil {
						t.Fatal("copied typed runtime borrowed connected candidate authority")
					}
				} else {
					copied := *f.connect
					if _, err := NewNodeChainCONNECTConnectedCandidatePlan(&copied, 0, f.inventory); err == nil {
						t.Fatal("copied typed runtime borrowed connected candidate authority")
					}
				}
			})
		}
	}
}
func TestNodeChainTypedConnectedCandidateFifty(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, count := range []int{3, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", family, count), func(t *testing.T) {
				f := newTypedConnectedFixture(t, family, count, true)
				source, config, reader := f.chain.SourceSHA256(), f.chain.ConfigSHA256(), f.chain.runtime.engine
				service, err := f.service(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				release, err := f.owner.BeginMeasurementContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if service.Start(strings.Repeat("a", 32), f.plan.targets[0].ID) == nil {
					t.Fatal("typed candidate bypassed original measurement/MTU lease")
				}
				release()
				request := strings.Repeat("b", 32)
				if err := service.Start(request, f.plan.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				// The original worker owns its full ninety-second sample
				// budget. Drain remains the distinct five-second join; do
				// not mistake that join bound for a fifty-sample deadline.
				deadline := time.Now().Add(hopmeasure.RequestTimeout + hopmeasure.ObservationTimeout)
				for !candidateStatus(t, service).Complete && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if !candidateStatus(t, service).Complete {
					t.Fatal("typed fifty worker did not finish within original request bound")
				}
				if err := service.Drain(request); err != nil {
					t.Fatal(err)
				}
				status := candidateStatus(t, service)
				if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || f.route.count.Load() != 50 || f.owner.active.Load() || f.owner.checks.Load() < 50 {
					t.Fatal("typed candidate lost original fifty samples and joined lease", status)
				}
				if f.chain.SourceSHA256() != source || f.chain.ConfigSHA256() != config || f.chain.runtime.engine != reader || status.CaptureSHA256 != f.plan.capture || status.PrefixPosition != count-3 {
					t.Fatal("typed candidate replaced complete source or prefix reader")
				}
				if service.Start(strings.Repeat("c", 32), "127.0.0.1:80") == nil {
					t.Fatal("typed candidate admitted arbitrary destination")
				}
			})
		}
	}
}
func TestNodeChainTypedConnectedCandidateRefusesOwners(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		for _, fault := range []string{"copied-runtime", "replacement-runtime", "catalog", "callback-runtime", "engine-reader", "network", "source", "cancelled-caller"} {
			t.Run(family+"/"+fault, func(t *testing.T) {
				f := newTypedConnectedFixture(t, family, 4, true)
				service, err := f.service(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				replace := func() {
					if f.socks != nil {
						copy := *f.socks
						f.owner.socks.Store(&copy)
					} else {
						copy := *f.connect
						f.owner.connect.Store(&copy)
					}
				}
				switch fault {
				case "copied-runtime":
					replace()
				case "replacement-runtime":
					if f.socks != nil {
						r, e := NewNodeChainSOCKSRuntime(f.socks.source)
						if e != nil {
							t.Fatal(e)
						}
						f.owner.socks.Store(r)
					} else {
						r, e := NewNodeChainCONNECTRuntime(f.connect.source)
						if e != nil {
							t.Fatal(e)
						}
						f.owner.connect.Store(r)
					}
				case "catalog":
					f.owner.setCapture(strings.Repeat("d", 64))
				case "callback-runtime":
					f.owner.callback = replace
				case "engine-reader":
					f.chain.runtime.mu.Lock()
					if f.socksEngine != nil {
						f.chain.runtime.engine = &typedConnectedSOCKSReader{f.socksEngine}
					} else {
						f.chain.runtime.engine = &typedConnectedCONNECTReader{f.connectEngine}
					}
					f.chain.runtime.mu.Unlock()
				case "network":
					var e *nodeChainTestEngine
					if f.socksEngine != nil {
						e = f.socksEngine.nodeChainTestEngine
					} else {
						e = f.connectEngine.nodeChainTestEngine
					}
					e.mu.Lock()
					e.identity.NetworkID = "changed-original-network"
					e.mu.Unlock()
				case "source":
					f.chain.nodes[0].profile["api_token"] = "changed-original-token"
				case "cancelled-caller":
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					if _, err := f.service(ctx); !errors.Is(err, context.Canceled) {
						t.Fatal("cancelled constructor lost caller", err)
					}
					fresh, err := f.service(t.Context())
					if err != nil {
						t.Fatal("disposable caller revoked original runtime", err)
					}
					defer fresh.Close()
					return
				}
				if err := service.Start(strings.Repeat("d", 32), f.plan.targets[0].ID); err == nil {
					t.Fatal("typed candidate retained copied/replaced original owner", fault)
				}
				if f.route.count.Load() != 0 || f.owner.active.Load() {
					t.Fatal("foreign typed owner reached dial or retained unused lease")
				}
				f.owner.socks.Store(f.socks)
				f.owner.connect.Store(f.connect)
				f.owner.setCapture(f.plan.capture)
				f.owner.callback = nil
				if service.Start(strings.Repeat("e", 32), f.plan.targets[0].ID) == nil {
					t.Fatal("observed foreign typed owner revived by changing back")
				}
			})
		}
	}
}
func TestNodeChainTypedConnectedCandidateCancelDrain(t *testing.T) {
	for _, family := range []string{"socks", "http", "https"} {
		t.Run(family, func(t *testing.T) {
			f := newTypedConnectedFixture(t, family, 4, true)
			f.route.closeEntered = make(chan struct{})
			f.route.closeRelease = make(chan struct{})
			service, err := f.service(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			release := func() { once.Do(func() { close(f.route.closeRelease) }) }
			defer func() { release(); _ = service.Close() }()
			request := strings.Repeat("f", 32)
			if err := service.Start(request, f.plan.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			select {
			case <-f.route.closeEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("typed candidate did not reach original socket close")
			}
			service.Cancel(request)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			err = service.CloseContext(ctx)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) || !f.owner.active.Load() || candidateStatus(t, service).Drained {
				t.Fatal("typed cancellation released original lease before socket join", err)
			}
			release()
			if err := service.Drain(request); err != nil {
				t.Fatal(err)
			}
			if f.owner.active.Load() || f.owner.released.Load() != 1 || len(candidateStatus(t, service).Results) != 0 {
				t.Fatal("typed cancelled result survived joined socket drain")
			}
		})
	}
}
