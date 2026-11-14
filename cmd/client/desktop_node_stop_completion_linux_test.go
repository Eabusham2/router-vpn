//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// Done witnesses a real failed TryLock wait, not an earlier ready session
// channel select. This makes cancellation controls exercise the held boundary.
type linuxStopWaitingContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *linuxStopWaitingContext) Done() <-chan struct{} {
	var pcs [16]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, "/internal/desktopnetwork.lockContext") {
			c.once.Do(func() { close(c.waiting) })
			break
		}
		if !more {
			break
		}
	}
	return c.Context.Done()
}

// This fixture begins at the explicitly modelled native-join boundary. It
// executes the actual capture, retained-completion and publication methods;
// installed guardian/journal/process acceptance remains the privileged suite.
func linuxStopCompletedModel(t *testing.T, ordered bool) *desktopNodeStopCapture {
	t.Helper()
	operation, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	controller := &ownedDesktopController{}
	p := &desktopLinuxNodeParent{controller: controller, gate: make(chan struct{}, 1), dependents: map[ownedDesktopNodeParent]struct{}{}}
	p.gate <- struct{}{}
	controller.nodeParent = p
	a := &app{localController: controller, connectionContext: operation, cfg: common.ClientConfig{
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	parent := &desktopLinuxNodeParentCapture{app: a, parent: p, controller: controller, lifetime: context.Background()}
	s := &desktopLinuxNodeSession{parent: parent, gate: make(chan struct{}, 1)}
	s.gate <- struct{}{}
	p.session = s
	p.dependents[s] = struct{}{}
	command := &exec.Cmd{}
	launch := &desktopNodeLaunch{command: command, profileID: "original", mode: "wg"}
	h := &desktopLinuxNodeHost{parent: parent, launch: launch}
	a.state.RouterID, a.state.Mode, a.state.Phase = "original", "wg", "stopping"
	dnsctx, dnscancel := context.WithCancel(context.Background())
	t.Cleanup(dnscancel)
	_ = dnsctx
	latctx, latcancel := context.WithCancel(context.Background())
	t.Cleanup(latcancel)
	_ = latctx
	a.dnsMeasurements = &desktopDNSSlot{current: &desktopDNSOperation{cancel: dnscancel}, used: map[string]bool{"old": true}}
	a.latencyMeasurements = &desktopLatencySlot{current: &desktopLatencyOperation{cancel: latcancel}}
	activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID: "original", RuntimeID: "original-runtime", Config: "original-config"})
	if ordered {
		launch.chain = &desktopNodeChainLaunch{}
		graph := activeMultihopGraph{Execution: "server", EntryID: "entry", ExitID: "exit", ChainNodes: 3, SourceSHA: "original-source"}
		activeMultihopGraphs.Store(a, graph)
		nativeMultihopOwners.Store(a, &nativeMultihopRuntime{launch: launch, graph: graph})
	}
	t.Cleanup(func() {
		activeDNSRuntimeIdentities.Delete(a)
		activeMultihopGraphs.Delete(a)
		nativeMultihopOwners.Delete(a)
		homeExitProofs.Delete(a)
	})
	c := &desktopNodeStopCapture{app: a, session: s, host: h, command: command, operation: operation}
	done := &desktopLinuxStopCompletion{owner: c, retained: true, disconnect: true, dns: a.dnsMeasurements, dnsOperation: a.dnsMeasurements.current,
		latency: a.latencyMeasurements, latencyOperation: a.latencyMeasurements.current, homeGeneration: homeExitProofs.generation(a)}
	c.completion = done
	s.stopCompletion = c
	for _, registry := range []*sync.Map{&activeDNSRuntimeIdentities, &activeMultihopGraphs, &nativeMultihopOwners, &homeExitProofs.Map} {
		value, present := registry.Load(a)
		done.registries = append(done.registries, desktopLinuxStopRegistry{registry, value, present})
	}
	<-s.gate
	c.joinedLocked()
	s.gate <- struct{}{}
	return c
}

func TestDesktopLinuxNodeStopCompletionHeldPublicationRetainsExactRetry(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		name := "ordinary"
		if ordered {
			name = "ordered"
		}
		for _, boundary := range []string{"application", "dns-slot", "dns-operation", "latency-slot", "latency-operation"} {
			t.Run(name+"/"+boundary, func(t *testing.T) {
				c := linuxStopCompletedModel(t, ordered)
				a := c.app
				var held *sync.Mutex
				switch boundary {
				case "application":
					held = &a.mu
				case "dns-slot":
					held = &c.completion.dns.mu
				case "dns-operation":
					held = &c.completion.dnsOperation.mu
				case "latency-slot":
					held = &c.completion.latency.mu
				default:
					held = &c.completion.latencyOperation.mu
				}
				held.Lock()
				locked := true
				defer func() {
					if locked {
						held.Unlock()
					}
				}()
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx := &linuxStopWaitingContext{Context: parent, waiting: make(chan struct{})}
				result := make(chan error, 1)
				go func() { result <- c.Retire(ctx, nil, true) }()
				select {
				case <-ctx.waiting:
				case err := <-result:
					t.Fatal("Stop did not enter the held publication boundary", err)
				case <-time.After(2 * time.Second):
					cancel()
					held.Unlock()
					locked = false
					<-result
					t.Fatal("Stop never reached its original bounded lock")
				}
				cancel()
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("cancelled publication passed")
					}
				case <-time.After(time.Second):
					held.Unlock()
					locked = false
					<-result
					t.Fatal("Stop publication ignored original caller")
				}
				held.Unlock()
				locked = false
				if c.session.stopCompletion != c || !c.completion.joined.Load() || c.completion.published.Load() || a.state.Phase == "off" {
					t.Fatal("cancelled terminal publication discarded joined owner")
				}
				fresh, err := a.captureDesktopNodeStopContext(context.Background())
				if err != nil || fresh != c {
					t.Fatal("empty session bypassed retained completion", err)
				}
				if err := fresh.Retire(context.Background(), nil, true); err != nil {
					t.Fatal("original joined retry failed", err)
				}
				if !c.completion.published.Load() || c.session.stopCompletion != nil || a.state.Phase != "off" || !c.completion.dnsOperation.invalid || !c.completion.latencyOperation.invalid {
					t.Fatal("retry did not complete exact original publication")
				}
				for _, registry := range c.completion.registries {
					if _, present := registry.registry.Load(a); present {
						t.Fatal("old runtime survived terminal publication")
					}
				}
			})
		}
	}
}

func TestDesktopLinuxNodeStopCompletionRejectsReplacement(t *testing.T) {
	for _, fault := range []string{"controller", "operation", "command", "host", "session", "journal", "predecessor", "reverse", "dns-slot", "dns-operation", "latency-operation", "dns-runtime", "graph", "native-owner", "home-proof", "legacy-owner", "intent", "copy"} {
		t.Run(fault, func(t *testing.T) {
			c := linuxStopCompletedModel(t, true)
			a, s := c.app, c.session
			candidate := c
			disconnect := true
			switch fault {
			case "controller":
				a.localController = &ownedDesktopController{}
			case "operation":
				a.connectionContext = context.Background()
			case "command":
				a.cmd = &exec.Cmd{}
			case "host":
				s.active = &desktopLinuxNodeHost{}
			case "session":
				s.parent.parent.session = &desktopLinuxNodeSession{}
			case "journal":
				s.journal = &desktopLinuxNodeJournal{}
			case "predecessor":
				s.predecessor = &desktopLinuxNodeTransaction{}
			case "reverse":
				s.reverse = &linuxStandardNodeReverseTransfer{}
			case "dns-slot":
				a.dnsMeasurements = &desktopDNSSlot{}
			case "dns-operation":
				a.dnsMeasurements.current = &desktopDNSOperation{}
			case "latency-operation":
				a.latencyMeasurements.current = &desktopLatencyOperation{}
			case "dns-runtime":
				activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{RuntimeID: "successor"})
			case "graph":
				activeMultihopGraphs.Store(a, activeMultihopGraph{SourceSHA: "successor"})
			case "native-owner":
				nativeMultihopOwners.Store(a, &nativeMultihopRuntime{})
			case "home-proof":
				homeExitProofs.Store(a, &homeExitProof{SessionID: "successor"})
			case "legacy-owner":
				desktopNodeOwners.Store(a, c.host.launch)
				defer desktopNodeOwners.Delete(a)
			case "intent":
				disconnect = false
			case "copy":
				candidate = &desktopNodeStopCapture{app: a, session: s, host: c.host, operation: c.operation, command: c.command, completion: c.completion}
			}
			before := a.state
			dns := a.dnsMeasurements
			latency := a.latencyMeasurements
			registryValues := make([]any, len(c.completion.registries))
			registryPresent := make([]bool, len(registryValues))
			for i, row := range c.completion.registries {
				registryValues[i], registryPresent[i] = row.registry.Load(a)
			}
			if err := candidate.Retire(context.Background(), nil, disconnect); err == nil {
				t.Fatal("replacement gained old completion")
			}
			if a.state != before || a.dnsMeasurements != dns || a.latencyMeasurements != latency || c.completion.published.Load() || s.stopCompletion != c {
				t.Fatal("rejected completion changed successor or discarded original retry")
			}
			for i, row := range c.completion.registries {
				value, present := row.registry.Load(a)
				if present != registryPresent[i] || value != registryValues[i] {
					t.Fatal("rejected completion altered runtime registry")
				}
			}
		})
	}
}

func TestDesktopLinuxNodeStopCompletionNeverInfersJoinFromEmptyFields(t *testing.T) {
	for _, fault := range []string{"no-receipt", "journal-error", "retired-parent", "lost-registration"} {
		t.Run(fault, func(t *testing.T) {
			c := linuxStopCompletedModel(t, false)
			s := c.session
			switch fault {
			case "no-receipt":
				c.completion.joined.Store(false)
			case "journal-error":
				s.journalErr = errors.New("original constructor failed")
			case "retired-parent":
				s.closed = true
			case "lost-registration":
				delete(s.parent.parent.dependents, s)
			}
			if err := s.unclaimedStopLocked(context.Background()); err == nil {
				t.Fatal("pending completion became empty legacy dispatch")
			}
			if err := c.publishCompletion(context.Background(), nil); err == nil || c.completion.published.Load() || s.stopCompletion != c {
				t.Fatal("empty active/command fields fabricated terminal completion", err)
			}
		})
	}
}

func TestDesktopLinuxNodeStopCompletionParentClosePreservesPendingPublication(t *testing.T) {
	for _, boundary := range []string{"application", "dns-operation", "replacement"} {
		t.Run(boundary, func(t *testing.T) {
			c := linuxStopCompletedModel(t, true)
			s, a := c.session, c.app
			p := s.parent.parent
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			p.ctx, p.joined = lifetime, make(chan struct{})
			s.parent.lifetime = lifetime
			var cancelOnce sync.Once
			p.cancel = func() { cancelOnce.Do(func() { cancelLifetime(); close(p.joined) }) }
			a.closing = true
			p.stopping = true
			if err := s.Close(context.Background()); err == nil || s.closed || s.released || s.stopCompletion != c {
				t.Fatal("dependent Close discarded joined publication authority", err)
			}
			if boundary == "replacement" {
				a.connectionContext = context.Background()
				if err := p.Close(context.Background()); err == nil || lifetime.Err() != nil || s.closed || s.released || c.completion.published.Load() {
					t.Fatal("terminal parent adopted replacement or revoked retry lifetime", err)
				}
				a.connectionContext = c.operation
			} else {
				held := &a.mu
				if boundary == "dns-operation" {
					held = &c.completion.dnsOperation.mu
				}
				held.Lock()
				locked := true
				defer func() {
					if locked {
						held.Unlock()
					}
				}()
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx := &linuxStopWaitingContext{Context: parent, waiting: make(chan struct{})}
				result := make(chan error, 1)
				go func() { result <- p.Close(ctx) }()
				select {
				case <-ctx.waiting:
				case err := <-result:
					t.Fatal("parent did not wait at original publication", err)
				case <-time.After(2 * time.Second):
					cancel()
					held.Unlock()
					locked = false
					<-result
					t.Fatal("parent publication did not enter bounded lock")
				}
				cancel()
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						t.Fatal("parent lost original cancellation", err)
					}
				case <-time.After(time.Second):
					held.Unlock()
					locked = false
					<-result
					t.Fatal("parent cancellation abandoned its bound")
				}
				held.Unlock()
				locked = false
				if lifetime.Err() != nil || s.closed || s.released || s.stopCompletion != c || c.completion.published.Load() {
					t.Fatal("cancelled parent revoked pending completion")
				}
			}
			if err := p.Close(context.Background()); err != nil {
				t.Fatal("original parent completion retry failed", err)
			}
			if lifetime.Err() == nil || !p.closed || !s.closed || !s.released || s.stopCompletion != nil || !c.completion.published.Load() || a.state.Phase != "off" {
				t.Fatal("actual parent dependent loop did not finish before lifetime revocation")
			}
		})
	}
}

func TestDesktopLinuxNodeStopCompletionFailedConstructorRetainsOriginalError(t *testing.T) {
	c := linuxStopCompletedModel(t, false)
	s := c.session
	original := errors.New("original journal constructor refused")
	c.completion.joined.Store(false)
	c.completion.hostReleased, c.completion.failedConstructor = true, original
	s.journalErr = original
	fresh, err := c.app.captureDesktopNodeStopContext(context.Background())
	if fresh != nil || err != original || s.stopCompletion != c || c.completion.published.Load() {
		t.Fatal("failed closed host became successful empty dispatch", err)
	}
	if err := c.Retire(context.Background(), nil, true); err != original || s.active != nil || s.stopCompletion != c || c.completion.joined.Load() || c.completion.published.Load() {
		t.Fatal("retry forgot original constructor error or invented completion", err)
	}
}
