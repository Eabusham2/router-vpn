package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

type nodeChainExecutionReadbackMTUOwner struct {
	mu            sync.Mutex
	runtime       *NodeChainExecutionRuntime
	state         mobilemtu.State
	captures      atomic.Int32
	bindings      atomic.Int32
	beforeCapture func(context.Context, int32)
	beforeBinding func(context.Context, int32)
}

// Capture the final node's real private MTU service identity before runtime
// construction. The control Manager and private endpoint identity stay exact.
func nodeChainExecutionReadbackMeasurementProjection(t *testing.T, f *nodeChainExecutionRuntimeFixture) {
	t.Helper()
	previous := f.runtime.projection
	source := previous.policy.source
	var local NodeChainSource
	if json.Unmarshal([]byte(source.LocalSource), &local) != nil {
		t.Fatal("original Local source")
	}
	last := len(previous.policy.local.nodes) - 1
	node := previous.policy.local.nodes[last]
	profile := predecessorCopy(node.profile)
	api, err := privateAPI(predecessorText(profile, "router_api"))
	if err != nil {
		t.Fatal(err)
	}
	profile["daita_host"], profile["daita_port"] = api.Hostname(), float64(mobilemtu.ProbePort)
	changed, err := NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	local.Nodes[last], err = changed.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	source.LocalSource = startJSON(t, local)
	projection := nodeChainExecutionMTUProjection(t, source)
	peers := map[string]string{}
	for _, execution := range []string{"local", "server"} {
		before, _ := previous.ProofInventory(execution)
		after, _ := projection.ProofInventory(execution)
		for i, proof := range before {
			api, _ := privateAPI(predecessorText(previous.policy.local.nodes[i].profile, "router_api"))
			peers[after[i].Tag+"/"+api.Host] = f.engine.peers[proof.Tag+"/"+api.Host]
		}
	}
	f.engine.projection, f.engine.peers = projection, peers
	f.engine.identity.SourceSHA256, f.engine.identity.ConfigSHA256 = projection.SourceSHA256(), projection.ConfigSHA256()
	f.engine.selected = projection.policy.local.FinalTag()
	f.runtime, err = NewNodeChainExecutionRuntime(projection, f.engine)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.testTLS = f.trust
}

func (o *nodeChainExecutionReadbackMTUOwner) MTUExecutionContext(ctx context.Context) (*NodeChainExecutionRuntime, error) {
	n := o.bindings.Add(1)
	if o.beforeBinding != nil {
		o.beforeBinding(ctx, n)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.runtime, ctx.Err()
}
func (o *nodeChainExecutionReadbackMTUOwner) Capture() (mobilemtu.State, error) {
	return mobilemtu.State{}, errors.New("unbounded native capture forbidden")
}
func (o *nodeChainExecutionReadbackMTUOwner) CaptureContext(ctx context.Context) (mobilemtu.State, error) {
	n := o.captures.Add(1)
	if o.beforeCapture != nil {
		o.beforeCapture(ctx, n)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state, ctx.Err()
}
func (*nodeChainExecutionReadbackMTUOwner) ChangeMTU(context.Context, mobilemtu.State, int) (mobilemtu.State, error) {
	return mobilemtu.State{}, errors.New("attachment cannot change native reader")
}
func (*nodeChainExecutionReadbackMTUOwner) DialThroughTunnel(context.Context, mobilemtu.State, string, string) (net.Conn, error) {
	return nil, errors.New("attachment cannot open native measurement traffic")
}

func nodeChainExecutionReadbackOwner(r *NodeChainExecutionRuntime, mtu int) *nodeChainExecutionReadbackMTUOwner {
	// Platform-owned labels deliberately differ from native engine IDs. The
	// typed runtime companion binds the actual bridge instead of guessing them.
	return &nodeChainExecutionReadbackMTUOwner{runtime: r, state: mobilemtu.State{
		Session: "platform-original-session", Path: "platform-original-network", Interface: "platform-reader-3", MTU: mtu}}
}

func TestNodeChainExecutionMTUReattachmentUsesActualReadback(t *testing.T) {
	f, e, ctx := nodeChainExecutionReadbackConfiguredFixture(t, "android", "server", false, true)
	owner := nodeChainExecutionReadbackOwner(f.runtime, 1400)
	projection := f.runtime.projection
	bound, err := projection.MTUPlan()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projection.NewMTUControllerContext(ctx, owner, nil); err == nil {
		t.Fatal("fixture did not witness immutable-config reattachment gap")
	}
	for _, actual := range []int{1400, 1420} {
		if actual > bound.Ceiling {
			t.Fatal("fixture effective MTU exceeds captured envelope", bound)
		}
		e.readMu.Lock()
		e.issued.MTU = actual
		e.issued.ReaderGeneration++
		e.readMu.Unlock()
		owner.mu.Lock()
		owner.state.MTU = actual
		owner.mu.Unlock()
		controller, err := f.runtime.NewMTUControllerContext(ctx, owner, nil)
		if err != nil || controller == nil {
			t.Fatal("fresh optimizer could not attach to actual original reader MTU", actual, err)
		}
		var status mobilemtu.Status
		if json.Unmarshal([]byte(controller.StatusJSON()), &status) != nil || status.EffectiveMTU != actual || status.Measured || status.Source != "configured-unmeasured" {
			t.Fatal("reattachment substituted saved/claimed measured MTU", status)
		}
		if err := controller.CloseContext(ctx); err != nil {
			t.Fatal(err)
		}
		if f.runtime.projection != projection || !f.runtime.Progress().Ready {
			t.Fatal("optimizer reattachment replaced active projection or execution")
		}
	}
	if owner.captures.Load() < 6 || e.captures.Load() != 4 || owner.bindings.Load() != 4 {
		t.Fatal("attachment omitted original owner/readback observations", owner.captures.Load(), e.captures.Load(), owner.bindings.Load())
	}
}

func TestNodeChainExecutionMTUReattachmentRejectsChangedOwnerAndReader(t *testing.T) {
	for _, fault := range []string{"initial-owner", "late-owner", "effective-mtu", "reader-generation", "interface", "platform-state"} {
		t.Run(fault, func(t *testing.T) {
			f, e, ctx := nodeChainExecutionReadbackConfiguredFixture(t, "android", "server", false, true)
			owner := nodeChainExecutionReadbackOwner(f.runtime, 1400)
			switch fault {
			case "initial-owner":
				owner.runtime = &NodeChainExecutionRuntime{}
				owner.beforeBinding = func(_ context.Context, n int32) {
					if n == 2 {
						owner.mu.Lock()
						owner.runtime = f.runtime
						owner.mu.Unlock()
					}
				}
			case "late-owner":
				owner.beforeBinding = func(_ context.Context, n int32) {
					if n == 2 {
						owner.mu.Lock()
						owner.runtime = &NodeChainExecutionRuntime{}
						owner.mu.Unlock()
					}
				}
			case "effective-mtu":
				owner.state.MTU = 1420
			default:
				owner.beforeCapture = func(_ context.Context, n int32) {
					if n != 2 {
						return
					}
					e.readMu.Lock()
					switch fault {
					case "reader-generation":
						e.issued.ReaderGeneration++
					case "interface":
						e.issued.InterfaceIndex++
					case "platform-state":
						owner.mu.Lock()
						owner.state.Path = "replacement-network"
						owner.mu.Unlock()
					}
					e.readMu.Unlock()
				}
			}
			if controller, err := f.runtime.NewMTUControllerContext(ctx, owner, nil); err == nil || controller != nil {
				t.Fatal("optimizer attachment admitted changed original owner/readback", fault)
			}
		})
	}
}

func TestNodeChainExecutionMTUReattachmentRetainsCanceledOwnerObservation(t *testing.T) {
	f, e, ctx := nodeChainExecutionReadbackConfiguredFixture(t, "android", "server", false, true)
	owner := nodeChainExecutionReadbackOwner(f.runtime, 1400)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	owner.beforeCapture = func(_ context.Context, n int32) {
		if n == 1 {
			close(entered)
			<-release
		}
	}
	call, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		controller, err := f.runtime.NewMTUControllerContext(call, owner, nil)
		if controller != nil {
			_ = controller.Close()
			err = errors.New("late canceled controller was published")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native MTU owner capture did not enter")
	}
	cancel()
	if err := f.runtime.CloseContext(ctx); err == nil {
		t.Fatal("runtime acknowledged cleanup before MTU owner capture joined")
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("late canceled owner capture granted optimizer", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled original MTU owner capture did not join")
	}
	if err := f.runtime.CloseContext(ctx); err != nil {
		t.Fatal("joined optimizer observation blocked original cleanup", err)
	}
	before := e.captures.Load()
	if _, err := f.runtime.NewMTUControllerContext(ctx, owner, nil); err == nil || e.captures.Load() != before {
		t.Fatal("stale optimizer attachment touched retired native owner")
	}
}
