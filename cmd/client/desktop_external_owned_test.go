//go:build go1.25

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

// These models execute the public app, real compiler, private mailbox parsing,
// protection slot and durable journal transitions. Only controller/package,
// child/Job/BFE and native DNS/exit/TUN observations are modeled. They are not
// Windows networking, installed-package or physical-device acceptance.
type desktopWindowsExternalFixture struct {
	base        *desktopNodeConnectionFixture
	store       *desktopNodeJournalFixtureStore
	profiles    map[string]common.RouterProfile
	children    []*desktopWindowsExternalChild
	onStart     func(*desktopWindowsExternalChild)
	onAdmit     func(*desktopWindowsExternalChild) error
	proofFault  func(*desktopExternalProof)
	releaseFail bool
}

type desktopWindowsExternalChild struct {
	fixture                     *desktopWindowsExternalFixture
	launch                      *desktopNodeLaunch
	underlying                  desktopNodeProcess
	slot                        *desktopNodeProtectionSlot
	attempt                     *desktopNodeProtectionAttempt
	target                      mobiletor.DesktopWindowsProtectionTarget
	outcome                     windowsprotection.JournalRecord
	stop, done                  chan struct{}
	once                        sync.Once
	mu                          sync.Mutex
	closeErr                    error
	closed, committed, admitted bool
	checkedAt                   int64
	proof                       desktopExternalProof
}

type desktopWindowsExternalRelease struct {
	f       *desktopWindowsExternalFixture
	target  mobiletor.DesktopWindowsProtectionTarget
	barrier mobiletor.DesktopWindowsProtectionCommitBarrier
	closed  bool
}

func (r *desktopWindowsExternalRelease) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	if ctx.Err() != nil || r.f.releaseFail {
		return errors.Join(ctx.Err(), errors.New("modeled exact native release is still pending"))
	}
	k := r.f.base.kernel
	if k.target == nil || *k.target != r.target || !k.locked {
		return errors.New("modeled release changed its exact original target")
	}
	if r.target.Policy == "on-connect" {
		if err := r.barrier(ctx, mobiletor.DesktopWindowsProtectionCommit{Action: "release", Previous: copyDesktopNodeProtectionTarget(&r.target)}); err != nil {
			return err
		}
		if r.f.store.head.Phase != "intent" || r.f.store.head.Intent.Action != "release" {
			return errors.New("modeled removal preceded its durable intent")
		}
		k.target = nil
	}
	k.locked, r.closed = false, true
	return nil
}

func newDesktopWindowsExternalFixture(t *testing.T, policy string) *desktopWindowsExternalFixture {
	t.Helper()
	f := &desktopWindowsExternalFixture{base: newDesktopNodeConnectionFixture(t, policy, ""), profiles: map[string]common.RouterProfile{}}
	controller := windowsprotection.Controller{PID: 101, StartTimeUTCTicks: 638000000000000000, SID: "S-1-5-21-100-200-300-1001", AuthenticationID: 123, SessionID: 2}
	f.store = &desktopNodeJournalFixtureStore{head: windowsprotection.JournalRecord{Schema: 1, Kind: windowsprotection.JournalRecordKind, JournalID: strings.Repeat("a", 32), Sequence: 1, Controller: controller, Phase: "settled"}}
	a, k := f.base.a, f.base.kernel
	a.nodeProtection.journal = f.store
	a.nodeProtection.backend.releaseWithBarrier = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget, barrier mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error) {
		if ctx.Err() != nil || barrier == nil || k.locked || k.target == nil || *k.target != target {
			return nil, errors.New("modeled release did not capture its joined target")
		}
		k.locked = true
		return &desktopWindowsExternalRelease{f: f, target: target, barrier: barrier}, nil
	}
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5"} {
		profile, _ := desktopExternalNativeFixture(t, protocol)
		profile.ID = "external-" + protocol
		profile.Name = protocol
		profile.KillSwitch, profile.KillSwitchPolicy = true, policy
		profile.MTUPolicy, profile.ManualMTU, profile.EffectiveMTU = "manual", 1360, 9000
		profile.StartLayer, profile.MultihopExecution = "", "local"
		if err := common.NormalizeRouterProfile(&profile); err != nil {
			t.Fatal(err)
		}
		f.profiles[protocol] = profile
		a.profiles.Profiles = append(a.profiles.Profiles, profile)
	}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	priorCapture := a.nodeConnectionHost.capture
	a.nodeConnectionHost.capture = func(a *app) (desktopOwnedNodePreparation, error) {
		capture, err := priorCapture(a)
		capture.retainedController = f // Explicit modeled original controller capability.
		return capture, err
	}
	a.nodeConnectionHost.externalPreflight = func(ctx context.Context, binary string, args, env []string, dir string) error {
		if ctx.Err() != nil || binary != filepath.Join(f.base.packageDir, "runtime", "native", nativeBinaryName()) {
			return errors.New("preflight changed its captured package")
		}
		body, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
		var graph map[string]any
		if err != nil || json.Unmarshal(body, &graph) != nil || graph["route"] == nil {
			return errors.Join(err, errors.New("preflight omitted the real compiled graph"))
		}
		if len(args) == 4 && args[0] == "routervpn-external" && args[1] == "--help" && args[2] == "--physical-source-sha256" {
			outbounds, _ := graph["outbounds"].([]any)
			for _, raw := range outbounds {
				outbound, _ := raw.(map[string]any)
				if outbound["type"] == mobilemultihop.DesktopExternalPhysicalType && outbound["source_sha256"] == args[3] && len(args[3]) == 64 {
					return nil
				}
			}
			return errors.New("preflight lost its captured physical source")
		}
		if !reflect.DeepEqual(args, []string{"check", "-D", dir, "-c", filepath.Join(dir, "sing-box.json")}) {
			return errors.New("preflight attempted a runtime mutation")
		}
		return nil
	}
	a.nodeConnectionHost.startExternal = f.startExternal
	priorStart := a.nodeConnectionHost.start
	a.nodeConnectionHost.start = func(ctx context.Context, a *app, l *desktopNodeLaunch, args, env []string, dir string) (desktopNodeProcess, error) {
		underlying, err := priorStart(ctx, a, l, args, env, dir)
		if underlying == nil {
			return nil, err
		}
		child := f.newChild(l, l.ownedNode.slot, l.ownedNode.attempt)
		child.underlying = underlying
		return child, err
	}
	t.Cleanup(func() {
		for _, child := range f.children {
			child.mu.Lock()
			child.closeErr = nil
			child.mu.Unlock()
		}
		if raw, ok := desktopExternalRetainedLaunches.Load(a); ok {
			if l, ok := raw.(*desktopNodeLaunch); ok && l.external != nil && l.external.windows != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := l.external.windows.Close(ctx); err != nil {
					t.Error("external fixture retained cleanup", err)
				}
				cancel()
			}
		}
		if err := a.retryDesktopWindowsExternalPreparations(); err != nil {
			t.Error(err)
		}
		for _, child := range f.children {
			if child.underlying == nil {
				child.once.Do(func() { close(child.stop) })
				<-child.done
			}
		}
	})
	return f
}

func (f *desktopWindowsExternalFixture) newChild(l *desktopNodeLaunch, slot *desktopNodeProtectionSlot, attempt *desktopNodeProtectionAttempt) *desktopWindowsExternalChild {
	selection, _ := attempt.selection()
	child := &desktopWindowsExternalChild{fixture: f, launch: l, slot: slot, attempt: attempt, stop: make(chan struct{}), done: make(chan struct{}),
		target: mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: selection.session, SourceSHA256: selection.source, NetworkID: strings.Repeat("d", 32)}, Policy: selection.policy, BaselineSHA256: strings.Repeat("e", 64)}}
	child.outcome, _ = copyDesktopNodeJournalRecord(f.store.head)
	f.children = append(f.children, child)
	return child
}

func (f *desktopWindowsExternalFixture) startExternal(ctx context.Context, a *app, l *desktopNodeLaunch, args, env []string, dir string) (desktopNodeProcess, error) {
	if a != f.base.a || l.external == nil || l.external.windows == nil || l.ownedNode != nil || l.command.Process != nil || dir != l.directory || ctx.Err() != nil ||
		l.external.windows.host.capture.retainedController != f {
		return nil, errors.New("external host changed its original typed controller")
	}
	owner := l.external.windows
	want, err := desktopWindowsExternalArguments(l)
	if err != nil || !reflect.DeepEqual(args, want) || !reflect.DeepEqual(env, l.command.Env) ||
		!reflect.DeepEqual(owner.attempt.transfer.Predecessor, f.base.kernel.target) || f.base.kernel.locked {
		return nil, errors.Join(err, errors.New("external command lost its exact predecessor or private argv"))
	}
	if _, old := desktopNodeOwners.Load(a); old {
		return nil, errors.New("external engine was placed in the legacy registry")
	}
	child := f.newChild(l, owner.slot, owner.attempt)
	go child.serve()
	if f.onStart != nil {
		f.onStart(child)
	}
	return child, nil
}

func (p *desktopWindowsExternalChild) publish(name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	p.launch.workspaceMu.Lock()
	defer p.launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(p.launch); err != nil {
		return err
	}
	return atomicWritePrivate(filepath.Join(p.launch.directory, name), body)
}

func (p *desktopWindowsExternalChild) AdmitProtection(ctx context.Context) error {
	f := p.fixture
	selection, err := p.attempt.selection()
	if err != nil {
		return err
	}
	capture := windowsprotection.JournalCommitCapture{Schema: 1, Kind: windowsprotection.JournalCommitCaptureKind, Head: f.store.head, ProfileID: selection.profileID, ProfileRevision: p.attempt.profileRevision, Transfer: p.attempt.transfer}
	body, err := windowsprotection.CanonicalJournalCommitCapture(capture)
	if err != nil {
		return err
	}
	digest, _ := windowsprotection.JournalCommitCaptureSHA256(body)
	request := windowsprotection.JournalCommitRequest{Schema: 1, Kind: windowsprotection.JournalCommitRequestKind, CaptureSHA256: digest, Nonce: strings.Repeat("b", 64), Candidate: p.target}
	engine := capture.Head.Controller
	engine.PID += uint32(len(f.children))
	engine.StartTimeUTCTicks += int64(len(f.children))
	intent, err := windowsprotection.DeriveJournalCommitIntent(capture, request, engine)
	if err != nil {
		return err
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if _, err = f.store.Append(ctx, before.SHA256, intent); err != nil {
		return err
	}
	p.outcome = intent
	f.base.kernel.target, f.base.kernel.locked = copyDesktopNodeProtectionTarget(&p.target), true
	p.mu.Lock()
	p.committed = true
	p.mu.Unlock()
	if f.onAdmit != nil {
		if err := f.onAdmit(p); err != nil {
			return err
		}
	}
	settled, err := windowsprotection.DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		return err
	}
	before, err = f.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if _, err = f.store.Append(ctx, before.SHA256, settled); err != nil {
		return err
	}
	p.outcome = settled
	current := func() bool {
		if p.launch.external != nil {
			return p.launch.external.windows.current(true) == nil
		}
		return f.base.a.desktopOwnedNodeCurrent(p.launch, true)
	}
	if err := p.slot.captureJournalPrepared(ctx, p.attempt, settled, current); err != nil {
		return err
	}
	if p.underlying != nil {
		return nil
	}
	meta := p.launch.external.physical.Metadata()
	receipt, err := desktopnetwork.CanonicalDesktopNetworkReceipt(desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: "windows", Incarnation: strings.Repeat("1", 32), Name: "routervpn-external", Index: 71, LUID: 710, MTU: 1360, Addresses: []string{"172.19.0.1/30"}, Objects: []desktopnetwork.DesktopNetworkObject{}})
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.checkedAt = time.Now().UnixMilli()
	p.proof = desktopExternalProof{ExternalProofResult: p.launch.external.expected, Healthy: true, HeartbeatAt: p.checkedAt, Physical: &meta, NetworkReceipt: receipt}
	p.proof.CheckedAt, p.proof.Execution = p.checkedAt, "local"
	p.proof.DNSProven = true
	if f.proofFault != nil {
		f.proofFault(&p.proof)
	}
	p.admitted = true
	proof := p.proof
	p.mu.Unlock()
	for name, value := range map[string]any{
		"proof.json":       proof,
		"mtu-status.json":  desktopMTURecord{Schema: 1, Session: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Status: mobilemtu.Status{EffectiveMTU: 1360, Complete: true, Source: "fixed"}},
		"path-status.json": desktopPathRecord{desktopPathRequest: desktopPathRequest{Schema: 1, Session: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256}, Complete: true},
	} {
		if err := p.publish(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *desktopWindowsExternalChild) serve() {
	defer close(p.done)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-tick.C:
		}
		if raw, err := readDesktopRuntimeFile(p.launch, "stop.json", 4096); err == nil {
			var q desktopExternalStop
			if json.Unmarshal(raw, &q) != nil || q.Schema != 1 || q.Closed || q.SessionID != p.launch.external.session || q.SourceSHA256 != p.launch.external.expected.SourceSHA256 {
				return
			}
			q.Closed = true
			p.mu.Lock()
			committed := p.committed
			p.mu.Unlock()
			target := p.attempt.transfer.Predecessor
			if committed {
				target = &p.target
			}
			if p.publish("external-protection-retired.json", desktopNodeProtectionRetired(p.attempt, target)) != nil {
				return
			}
			_ = p.publish("stopped.json", q)
			return
		}
		p.mu.Lock()
		admitted := p.admitted
		proof := p.proof
		p.mu.Unlock()
		if !admitted {
			continue
		}
		proof.HeartbeatAt = time.Now().UnixMilli()
		if p.publish("proof.json", proof) != nil {
			return
		}
		for _, name := range []string{"path-request.json", "path-cancel.json"} {
			raw, err := readDesktopRuntimeFile(p.launch, name, 4096)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return
			}
			var q desktopPathRequest
			meta := p.launch.external.physical.Metadata()
			if json.Unmarshal(raw, &q) != nil || q.Session != meta.SessionID || q.SourceSHA256 != meta.SourceSHA256 || q.ConfigSHA256 != meta.ConfigSHA256 || q.Generation == 0 || !desktopMTURequestPattern.MatchString(q.Request) {
				return
			}
			out := desktopPathRecord{desktopPathRequest: q, Complete: true, Verified: name == "path-request.json", Cancelled: name == "path-cancel.json"}
			if out.Verified {
				out.CheckedAt = time.Now().UnixMilli()
			}
			if p.publish("path-status.json", out) != nil {
				return
			}
			p.launch.workspaceMu.Lock()
			err = p.launch.directoryRoot.Remove(name)
			p.launch.workspaceMu.Unlock()
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return
			}
		}
	}
}

func (p *desktopWindowsExternalChild) Started() bool {
	if p.underlying != nil {
		return p.underlying.Started()
	}
	return true
}
func (p *desktopWindowsExternalChild) Alive() error {
	if p.underlying != nil {
		return p.underlying.Alive()
	}
	select {
	case <-p.done:
		return errors.New("modeled exact child exited")
	default:
		return nil
	}
}
func (p *desktopWindowsExternalChild) Wait(ctx context.Context) (uint32, error) {
	if p.underlying != nil {
		return p.underlying.Wait(ctx)
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-p.done:
		return 0, nil
	}
}
func (p *desktopWindowsExternalChild) Close(ctx context.Context) error {
	p.mu.Lock()
	closed, err := p.closed, p.closeErr
	p.mu.Unlock()
	if closed {
		return nil
	}
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if p.underlying != nil {
		if err := p.underlying.Close(ctx); err != nil {
			return err
		}
	} else {
		p.once.Do(func() { close(p.stop) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
		}
		k := p.fixture.base.kernel
		if k.locked && (k.target == nil || *k.target != p.target) {
			return errors.New("modeled child cannot join another protection owner")
		}
		k.locked = false
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}
func (p *desktopWindowsExternalChild) JournalOutcome() (windowsprotection.JournalRecord, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if !closed {
		return windowsprotection.JournalRecord{}, errors.New("modeled journal preceded exact child join")
	}
	return copyDesktopNodeJournalRecord(p.outcome)
}

func (f *desktopWindowsExternalFixture) connect(t *testing.T, protocol string) *desktopNodeLaunch {
	t.Helper()
	profile := f.profiles[protocol]
	body, _ := json.Marshal(externalProfileConnectRequest{ProfileID: profile.ID})
	response := httptest.NewRecorder()
	f.base.a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external/connect", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatal("public external Connect failed", response.Code, response.Body.String())
	}
	raw, ok := desktopExternalRetainedLaunches.Load(f.base.a)
	if !ok {
		t.Fatal("public external Connect did not retain its own registry")
	}
	l, ok := raw.(*desktopNodeLaunch)
	if !ok || l.external == nil || l.external.windows == nil || l.ownedNode != nil || l.command.Process != nil || !f.base.a.state.Connected {
		t.Fatal("public external connection manufactured a Node or exec.Cmd process")
	}
	if _, old := desktopNodeOwners.Load(f.base.a); old {
		t.Fatal("ordinary external exit acquired the Router registry")
	}
	return l
}

func TestDesktopWindowsExternalPublicConnectAndDisconnect(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5"} {
			t.Run(policy+"/"+protocol, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newDesktopWindowsExternalFixture(t, policy)
					l := f.connect(t, protocol)
					if err := l.external.windows.current(true); err != nil {
						t.Fatal(err)
					}
					if f.store.head.Committed.Engine == nil || f.store.head.Committed.ProfileID != f.profiles[protocol].ID || f.base.a.nodeProtection.active.external != l.external.physical {
						t.Fatal("Connected preceded its typed live journal checkpoint")
					}
					proof, err := f.base.a.readDesktopExternalProof(l)
					if err != nil || proof.EntryProven || proof.SourceSHA256 != l.external.physical.Metadata().OriginalSourceSHA256 {
						t.Fatal("external proof acquired Router or physical proof identity", err)
					}
					response := httptest.NewRecorder()
					f.base.a.disconnect(response, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
					if response.Code != http.StatusOK || f.base.a.state.Connected || f.base.a.cmd != nil || f.base.a.state.Mode != "off" {
						t.Fatal("public Disconnect did not join the retained external child", response.Code, response.Body.String())
					}
					if _, ok := desktopExternalRetainedLaunches.Load(f.base.a); ok {
						t.Fatal("retired external registry remains")
					}
					if (f.base.kernel.target != nil) != (policy == "always") || f.base.kernel.locked || f.store.head.Committed.Engine != nil {
						t.Fatal("ordinary external Disconnect changed Always or retained a live owner")
					}
					if _, err := os.Lstat(l.directory); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("retired private workspace retained", err)
					}
				})
			})
		}
	}
}

func TestDesktopWindowsExternalRetirementRetriesExactOwner(t *testing.T) {
	for _, fault := range []string{"child-join", "journal-flush", "release", "foreign-receipt", "private-file"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "on-connect")
				l := f.connect(t, "http-connect")
				owner := l.external.windows
				child := f.children[len(f.children)-1]
				marker := filepath.Join(l.directory, "unowned-marker")
				switch fault {
				case "child-join":
					child.mu.Lock()
					child.closeErr = errors.New("modeled child not joined")
					child.mu.Unlock()
				case "journal-flush":
					f.store.failWrite = true
				case "release":
					f.releaseFail = true
				case "private-file":
					if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
						t.Fatal(err)
					}
				case "foreign-receipt":
					if err := child.publish("external-protection-retired.json", mobiletor.DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: strings.Repeat("f", 64)}); err != nil {
						t.Fatal(err)
					}
					child.once.Do(func() { close(child.stop) })
					<-child.done
				}
				response := httptest.NewRecorder()
				f.base.a.disconnect(response, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
				if response.Code == http.StatusOK || f.base.a.state.Connected {
					t.Fatal("failed retirement reported success", fault, response.Body.String())
				}
				if actual, ok := desktopExternalRetainedLaunches.Load(f.base.a); !ok || actual != l || l.external.windows != owner {
					t.Fatal("failed retirement lost its original external owner")
				}
				switch fault {
				case "child-join":
					child.mu.Lock()
					child.closeErr = nil
					child.mu.Unlock()
				case "journal-flush":
					f.store.failWrite = false
				case "release":
					f.releaseFail = false
				case "private-file":
					if err := os.Remove(marker); err != nil {
						t.Fatal(err)
					}
				case "foreign-receipt":
					if err := os.Remove(filepath.Join(l.directory, "external-protection-retired.json")); err != nil {
						t.Fatal(err)
					}
				}
				retry := httptest.NewRecorder()
				f.base.a.disconnect(retry, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
				if retry.Code != http.StatusOK || f.base.a.cmd != nil || f.base.kernel.target != nil || f.base.kernel.locked {
					t.Fatal("same retained owner failed cleanup retry", fault, retry.Code, retry.Body.String())
				}
			})
		})
	}
}

func TestDesktopWindowsExternalInvalidProofCannotConnect(t *testing.T) {
	for _, fault := range []string{"router-proof", "physical-source", "physical-config", "foreign-session", "dns", "exit", "receipt", "dead-child", "cancel", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				f.proofFault = func(p *desktopExternalProof) {
					switch fault {
					case "router-proof":
						p.EntryProven = true
					case "physical-source":
						p.SourceSHA256 = p.Physical.SourceSHA256
					case "physical-config":
						p.ConfigSHA256 = p.Physical.ConfigSHA256
					case "foreign-session":
						p.SessionID = strings.Repeat("f", 32)
					case "dns":
						p.DNSProven = false
					case "exit":
						p.IP = "198.51.100.99"
					case "receipt":
						p.NetworkReceipt = "{}"
					}
				}
				f.onAdmit = func(child *desktopWindowsExternalChild) error {
					switch fault {
					case "dead-child":
						child.once.Do(func() { close(child.stop) })
						<-child.done
					case "cancel":
						f.base.a.cancelConnectionOperation()
					case "replacement":
						f.base.a.mu.Lock()
						f.base.a.cmd = exec.Command("replacement-owner")
						f.base.a.state.RouterID = "replacement"
						f.base.a.mu.Unlock()
						return errors.New("modeled replacement after intent")
					}
					return nil
				}
				body, _ := json.Marshal(externalProfileConnectRequest{ProfileID: f.profiles["http-connect"].ID})
				response := httptest.NewRecorder()
				f.base.a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external/connect", bytes.NewReader(body)))
				if len(f.children) != 1 {
					t.Fatal("proof negative did not reach its actual modeled child", fault, response.Code, response.Body.String())
				}
				if response.Code == http.StatusOK || f.base.a.state.Connected {
					t.Fatal("invalid proof reported Connected", fault, response.Body.String())
				}
				if fault == "replacement" {
					if f.base.a.cmd == nil || f.base.a.cmd.Path != "replacement-owner" || f.base.a.state.RouterID != "replacement" {
						t.Fatal("old completion altered replacement")
					}
					// Retire only the fixture's named replacement before retrying the old
					// private cleanup. This is test cleanup, never a source fallback.
					f.base.a.mu.Lock()
					f.base.a.cmd = f.children[0].launch.command
					f.base.a.state.RouterID = f.children[0].launch.profileID
					f.base.a.mu.Unlock()
				}
			})
		})
	}
}

func TestDesktopWindowsExternalStagesBeforeStoppingPrevious(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "always")
		prior := f.connect(t, "http-connect")
		if _, err := waitForSpeedLabConnectedIdentity(f.base.a, time.Second); err != nil {
			t.Fatal(err)
		}
		_, _, finish, err := f.base.a.beginSpeedLabTemporaryOperation()
		if err != nil {
			t.Fatal(err)
		}
		defer finish()
		profile := f.profiles["https-connect"]
		exit, err := standardExitFromExternalProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		l, err := prepareDesktopExternalLaunch(f.base.a, profile, common.RouterProfile{}, exit, true, "")
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := prepareDesktopRetainedExternalForLaunch(f.base.a, l)
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Stage(f.base.a.connectionOperationContextOrBackground()); err != nil {
			t.Fatal(err)
		}
		if f.base.a.cmd != prior.command || prior.external.windows.current(true) != nil || f.base.a.nodeProtection.active != prior.external.windows.attempt || l.external.windows.attempt != nil {
			t.Fatal("private staging stopped or consumed the previous path")
		}
		marker := filepath.Join(l.directory, "unowned-marker")
		if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := adapter.Close(context.Background()); err == nil {
			t.Fatal("unknown private input was deleted")
		}
		if _, ok := desktopWindowsExternalPreparations.Load(l.external.windows); !ok || f.base.a.cmd != prior.command {
			t.Fatal("failed unstarted cleanup displaced active connection or lost retry ownership")
		}
		if err := f.base.a.retryDesktopWindowsExternalPreparations(); err == nil {
			t.Fatal("pending unknown input was forgotten")
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if err := f.base.a.retryDesktopWindowsExternalPreparations(); err != nil {
			t.Fatal(err)
		}
		if f.base.a.cmd != prior.command || prior.external.windows.current(true) != nil {
			t.Fatal("retiring unstarted staging altered original protection")
		}
	})
}

func TestDesktopWindowsExternalPolicyFamiliesStayDistinct(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5"} {
		l := desktopExternalPhysicalLaunchFixture(t, protocol, "always", "off", false)
		if err := prepareDesktopExternalPhysical(l, "windows"); err != nil {
			t.Fatal(err)
		}
		selected, err := desktopProtectionSelectionFor(nil, l.external.physical)
		if err != nil || selected.profileID != l.external.expected.ExitID || selected.source == l.external.expected.SourceSHA256 || selected.config == l.external.expected.ConfigSHA256 {
			t.Fatal("ordinary policy lost its domain-separated capture", protocol, err)
		}
		if _, err := desktopProtectionSelectionFor(desktopNodeProtectionPolicy(t, "1", "always", 0), l.external.physical); err == nil {
			t.Fatal("mixed Node/external ownership was accepted")
		}
	}
}

// The deliberately absent generic package stops this dispatch check at the
// original verifier. It proves selection and absence of retained-owner effects,
// not an unprotected connection or any native networking behavior.
func TestDesktopWindowsExternalOffUsesOriginalGenericPreparation(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	t.Setenv("HOMEVPN_PORTABLE", "0")
	_, genericFailure := verifyBundledNative(desktopAmneziaPackageRoot())
	if genericFailure == nil {
		t.Fatal("Off dispatch fixture unexpectedly has a verified native package")
	}
	captured := 0
	a := &app{nodeConnectionHost: &desktopNodeConnectionHost{
		capture: func(*app) (desktopOwnedNodePreparation, error) {
			captured++
			return desktopOwnedNodePreparation{}, errors.New("Off entered retained Windows capture")
		},
	}}
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn", "start-layer"} {
		t.Run(protocol, func(t *testing.T) {
			var profile common.RouterProfile
			if protocol == "start-layer" {
				profile = desktopLayerProfile(t, "https-connect", common.StartLayerAES256GCM)
			} else {
				profile, _ = desktopExternalNativeFixture(t, protocol)
			}
			profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal("Off fixture has an invalid original import", err)
			}
			before := cloneRouterProfile(profile)
			launch, err := prepareDesktopExternalLaunch(a, profile, common.RouterProfile{}, exit, true, "")
			if launch != nil || err == nil || err.Error() != genericFailure.Error() || captured != 0 {
				t.Fatal("Off did not retain the original generic preparation boundary", err, captured)
			}
			if !reflect.DeepEqual(before, profile) || a.cmd != nil || a.nodeProtection != nil {
				t.Fatal("Off dispatch changed the saved source or captured an owner")
			}
			if _, exists := desktopExternalRetainedLaunches.Load(a); exists {
				t.Fatal("Off dispatch acquired a retained external registry owner")
			}
		})
	}
}

func TestDesktopWindowsExternalProtectionKeepsCapturedController(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "on-connect")
		a := f.base.a
		originalSlot := a.nodeProtection
		calls := 0
		previous := a.nodeConnectionHost.capture
		a.nodeConnectionHost.capture = func(a *app) (desktopOwnedNodePreparation, error) {
			capture, err := previous(a)
			capture.protectionBackend = func() (desktopNodeProtectionBackend, error) {
				calls++
				return f.base.kernel.backend(), nil
			}
			return capture, err
		}
		captured, err := captureDesktopWindowsExternalHost(a, a.nodeConnectionHost)
		if err != nil {
			t.Fatal(err)
		}
		replacement := *a.nodeConnectionHost
		replacement.capture = func(*app) (desktopOwnedNodePreparation, error) {
			t.Fatal("protection selected a replacement controller capture")
			return desktopOwnedNodePreparation{}, nil
		}
		a.mu.Lock()
		a.nodeConnectionHost, a.nodeProtection = &replacement, nil
		a.mu.Unlock()
		defer func() { a.nodeProtection = originalSlot }() // No modeled kernel state was mutated.
		slot, err := captured.protectionSlot()
		if err != nil || slot == nil || slot == originalSlot || calls != 1 || slot.backend.read(context.Background(), nil) != nil {
			t.Fatal("empty protection slot was not recreated from its original capture", err, calls)
		}
		if again, err := captured.protectionSlot(); err != nil || again != slot || calls != 1 {
			t.Fatal("retained slot was reselected", err, calls)
		}
		f.base.controller.Store(true)
		if _, err := captured.protectionSlot(); err == nil || calls != 1 || a.nodeProtection != slot {
			t.Fatal("retired original controller acquired another protection slot", err)
		}
		f.base.controller.Store(false)
	})
}

func TestDesktopWindowsExternalProcessArgumentsRemainExact(t *testing.T) {
	directory, original := desktopNodeProcessArgumentsFixture(t)
	original[0] = "routervpn-external"
	copy, err := validateDesktopExternalProcessArguments(original, directory)
	if err != nil {
		t.Fatal(err)
	}
	original[4] = strings.Repeat("e", 32)
	if copy[4] == original[4] {
		t.Fatal("external arguments retained mutable caller storage")
	}
	for _, fault := range []string{"router-command", "missing-transfer", "physical-mtu", "early-journal", "another-directory", "invalid-source"} {
		t.Run(fault, func(t *testing.T) {
			args := append([]string(nil), copy...)
			switch fault {
			case "router-command":
				args[0] = "routervpn-node"
			case "missing-transfer":
				args = args[:9]
			case "physical-mtu":
				args = append(args, "--physical-mtu", "1360")
			case "early-journal":
				args = append(args, "--journal-parent-handle", "123")
			case "another-directory":
				args[2] = filepath.Join(directory, "replacement")
			case "invalid-source":
				args[8] = strings.Repeat("z", 64)
			}
			if _, err := validateDesktopExternalProcessArguments(args, directory); err == nil {
				t.Fatal("external command accepted substituted or incomplete authority")
			}
		})
	}
}

func TestDesktopWindowsExternalUnsupportedGraphPreservesPrevious(t *testing.T) {
	for _, protocol := range []string{"https-connect", "socks5"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				original := f.connect(t, "http-connect")
				if _, err := waitForSpeedLabConnectedIdentity(f.base.a, time.Second); err != nil {
					t.Fatal(err)
				}
				_, _, finish, err := f.base.a.beginSpeedLabTemporaryOperation()
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				for _, change := range []string{"server", "compare", "start-layer", "entry", "wireguard"} {
					profile := cloneRouterProfile(f.profiles[protocol])
					direct := true
					entry := common.RouterProfile{}
					switch change {
					case "server":
						profile.MultihopExecution = "server"
					case "compare":
						profile.MultihopExecution = "auto"
					case "start-layer":
						profile = desktopLayerProfile(t, protocol, common.StartLayerAES256GCM)
						profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
					case "entry":
						direct, entry = false, f.base.profile
					case "wireguard":
						profile, _ = desktopExternalNativeFixture(t, "wireguard")
						profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
					}
					exit, err := standardExitFromExternalProfile(profile)
					if err != nil {
						t.Fatal("fixture import", change, err)
					}
					if _, err := prepareDesktopExternalLaunch(f.base.a, profile, entry, exit, direct, ""); err == nil || !strings.Contains(err.Error(), "no captured native controller successor") {
						t.Fatal("unsupported graph entered a legacy launch path", change, err)
					}
					if len(f.children) != 1 || f.base.a.cmd != original.command || original.external.windows.current(true) != nil || f.base.a.nodeProtection.active != original.external.windows.attempt {
						t.Fatal("unsupported graph changed its original live owner", change)
					}
				}
			})
		})
	}
}

func TestDesktopWindowsExternalUnenteredRetirementRequiresOriginalJournal(t *testing.T) {
	for _, fault := range []string{"unchanged", "journal-head", "kernel-target", "constructor-entered"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				a := f.base.a
				ctx, finish, err := a.beginConnectionOperation()
				if err != nil {
					t.Fatal(err)
				}
				defer finish()
				profile := f.profiles["http-connect"]
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				l, err := prepareDesktopExternalLaunch(a, profile, common.RouterProfile{}, exit, true, "")
				if err != nil {
					t.Fatal(err)
				}
				adapter, err := prepareDesktopRetainedExternalForLaunch(a, l)
				if err != nil {
					t.Fatal(err)
				}
				owner := l.external.windows
				if err := adapter.Stage(ctx); err != nil {
					t.Fatal(err)
				}
				// An already-owned private input forces the real exclusive write to
				// fail after beginExternal but before any native constructor is called.
				if err := writeDesktopRuntimeFile(l, "external-protection-transfer.json", []byte("captured fixture input"), false); err != nil {
					t.Fatal(err)
				}
				if err := adapter.Start(ctx); err == nil || owner.attempt == nil || owner.startEntered || len(f.children) != 0 || a.cmd != nil {
					t.Fatal("unentered failure did not preserve its exact original attempt", err)
				}
				head, err := copyDesktopNodeJournalRecord(f.store.head)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "journal-head":
					f.store.head.JournalID = strings.Repeat("f", 32)
				case "kernel-target":
					f.base.kernel.target = &mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: strings.Repeat("f", 32), SourceSHA256: strings.Repeat("e", 64), NetworkID: strings.Repeat("d", 32)}, Policy: "always", BaselineSHA256: strings.Repeat("c", 64)}
				case "constructor-entered":
					// A missing process after entering a constructor is not the
					// same evidence as the proved unentered failure above.
					owner.startEntered = true
				}
				err = adapter.Close(context.Background())
				if fault == "unchanged" {
					if err != nil || a.nodeProtection.active != nil || f.store.head.Sequence != head.Sequence || !owner.finished {
						t.Fatal("exact unchanged unentered owner did not retire", err)
					}
				} else {
					if err == nil || a.nodeProtection.active != owner.attempt || owner.retired || owner.closed {
						t.Fatal("unentered retirement inferred unknown absence", fault, err)
					}
					if _, err := os.Stat(l.directory); err != nil {
						t.Fatal("failed unentered retirement lost its private inputs", err)
					}
					// Restore only the explicitly injected model boundary; production
					// never repairs a foreign head/target or infers a missing process.
					f.store.head, f.base.kernel.target, owner.startEntered = head, nil, false
					if err := adapter.Close(context.Background()); err != nil {
						t.Fatal("original unentered cleanup retry", err)
					}
				}
				if f.base.kernel.target != nil || f.base.kernel.locked || len(f.children) != 0 {
					t.Fatal("unentered cleanup created or adopted native protection")
				}
			})
		})
	}
}

func TestDesktopWindowsExternalDNSUsesOnlyOriginalNativeProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopWindowsExternalFixture(t, "always")
		l := f.connect(t, "https-connect")
		observed := sessionTrackerFor(f.base.a).capture()
		lookups := 0
		lookup := func(context.Context, string) ([]string, error) {
			lookups++
			return nil, errors.New("ambient resolver is not retained external proof")
		}
		if proof := proveSelectedDNSWithLookup(context.Background(), f.base.a, observed, l.mode, lookup); proof.Status != "passed" || proof.LatencyMs != 0 || lookups != 0 {
			t.Fatal("selected DNS observation borrowed another query or measurement", proof, lookups)
		}
		for _, change := range []string{"credential", "resolver", "base", "mode", "cancelled", "retired-child"} {
			candidate := observed
			candidate.Profile = cloneRouterProfile(observed.Profile)
			ctx := context.Background()
			switch change {
			case "credential":
				candidate.Profile.External.HTTPSConnect.Password += "changed"
			case "resolver":
				candidate.Profile.DNSHost = "9.9.9.9"
			case "base":
				candidate.Base = "wrong-base"
			case "mode":
				candidate.Mode = "wrong-mode"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "retired-child":
				child := f.children[0]
				child.once.Do(func() { close(child.stop) })
				<-child.done
			}
			if proof := proveSelectedDNSWithLookup(ctx, f.base.a, candidate, l.mode, lookup); proof.Status == "passed" || lookups != 0 {
				t.Fatal("changed DNS observation reused original authority", change, proof, lookups)
			}
		}
	})
}

func TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost(t *testing.T) {
	for _, direction := range []string{"router-external-router", "external-router-external", "external-router-original-host", "external-router-retired-controller", "router-hysteria2-router", "hysteria2-router-hysteria2", "router-socks5-router", "socks5-router-socks5"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				a := f.base.a
				protocol := "https-connect"
				if strings.Contains(direction, "hysteria2") {
					protocol = "hysteria2"
				}
				if strings.Contains(direction, "socks5") {
					protocol = "socks5"
				}
				routerFirst := direction == "router-external-router" || direction == "router-hysteria2-router" || direction == "router-socks5-router"
				var original *desktopNodeLaunch
				if routerFirst {
					response := httptest.NewRecorder()
					a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
					if response.Code != http.StatusOK {
						t.Fatal("original Router connect", response.Code, response.Body.String())
					}
					original = f.base.children[0].launch
				} else {
					original = f.connect(t, protocol)
				}
				for deadline := time.Now().Add(time.Second); ; {
					if _, _, err := captureSpeedLabIdentity(a); err == nil {
						break
					} else if !time.Now().Before(deadline) {
						t.Fatal("original session observation", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
				var source []byte
				if original.ownedNode != nil {
					source = bytes.Clone(original.ownedNode.source)
				} else {
					source = bytes.Clone(original.external.source)
				}
				privateBefore, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request := speedLabRequest{Scope: "temporary", DurationMode: "custom", MinSeconds: 1, MaxSeconds: 1}
				if routerFirst {
					request.Topology, request.NodeID, request.Execution = "external", f.profiles[protocol].ID, "local"
					f.onAdmit = func(child *desktopWindowsExternalChild) error {
						if child.launch.external != nil {
							cancel()
							return context.Canceled
						}
						return nil
					}
				} else {
					request.Topology, request.NodeID, request.Mode = "router", f.base.profile.ID, "wg"
					f.base.onHTTP = func(child *desktopNodeConnectionChild) {
						if direction == "external-router-original-host" {
							replacement := *a.nodeConnectionHost
							replacement.capture = func(*app) (desktopOwnedNodePreparation, error) {
								t.Error("restoration selected a replacement controller/package")
								return desktopOwnedNodePreparation{}, errors.New("replacement host has no original authority")
							}
							a.nodeConnectionHost = &replacement
						}
						if direction == "external-router-retired-controller" {
							f.base.controller.Store(true)
						}
						cancel()
					}
				}
				body, _ := json.Marshal(request)
				response := httptest.NewRecorder()
				a.speedLabRun(response, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", bytes.NewReader(body)).WithContext(ctx))
				if direction == "external-router-retired-controller" {
					if response.Code != http.StatusConflict || ctx.Err() == nil || a.state.Connected || len(f.children) != 2 {
						t.Fatal("retired original controller was reselected for restoration", response.Code, response.Body.String(), len(f.children))
					}
					if f.base.kernel.target == nil || *f.base.kernel.target != f.children[1].target || f.base.kernel.locked {
						t.Fatal("failed original-host restoration changed the joined trial protection")
					}
					f.base.controller.Store(false) // Restore only the fixture cancellation for exact cleanup.
					return
				}
				if response.Code != http.StatusConflict || ctx.Err() == nil || !a.state.Connected || len(f.children) != 3 {
					t.Fatal("cancelled public test did not restore its original typed host", direction, response.Code, response.Body.String(), a.state, len(f.children))
				}
				trial, restored := f.children[1], f.children[2]
				if restored.attempt.transfer.Predecessor == nil || *restored.attempt.transfer.Predecessor != trial.target || restored.launch.command == original.command || restored.Alive() != nil {
					t.Fatal("restoration reused an old predecessor or child")
				}
				if routerFirst {
					if restored.launch.ownedNode == nil || restored.launch.external != nil || restored.launch.ownedNode.host != original.ownedNode.host || !bytes.Equal(source, restored.launch.ownedNode.source) {
						t.Fatal("Router restoration acquired external proof identity or reselected its host/source")
					}
				} else {
					if restored.launch.ownedNode != nil || restored.launch.external == nil || restored.launch.external.windowsHost != original.external.windowsHost ||
						!bytes.Equal(source, restored.launch.external.source) || restored.launch.external.selection != "local" || restored.launch.external.windows.policy.Metadata().Protocol != protocol {
						t.Fatal("ordinary restoration acquired Router proof identity or reselected its host/source/winner")
					}
					if mtu, err := captureDesktopMTURestore(restored.launch); err != nil || mtu != 1360 {
						t.Fatal("restored external live MTU changed", mtu, err)
					}
				}
				privateAfter, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil || !bytes.Equal(privateBefore, privateAfter) || a.connectionContext != nil {
					t.Fatal("temporary succession changed saved private source or retained the operation", err)
				}
			})
		})
	}
}

var _ desktopExternalRetainedRuntime = (*desktopWindowsExternalRuntime)(nil)
var _ desktopNodeJournalAdmission = (*desktopWindowsExternalChild)(nil)
