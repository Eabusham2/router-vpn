//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/common"
	"sync/atomic"
	"testing"
	"time"
)

// This child models only the stock DNS router boundary. Socket creation,
// original pidfd transfer, SOCKS/TCP framing, process/config ownership and
// cancellation are real. The separate pinned-core test exercises DNS routing.
const legacyDNSEngineFixture = `#!/usr/bin/env python3
import os,sys,time,pathlib,socket,struct,signal
if sys.argv[1]=='check':sys.exit(0)
root=pathlib.Path(os.environ['HOMEVPN_ROOT'])
signal.signal(signal.SIGINT,lambda *_:sys.exit(0))
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
def exact(c,n):
 b=b''
 while len(b)<n:
  p=c.recv(n-len(b))
  if not p:raise EOFError()
  b+=p
 return b
mode=(root/'dns-mode').read_text()
if mode=='no-listener':
 (root/'engine-started').write_text(str(os.getpid()))
 while True:time.sleep(.02)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',1099));s.listen();s.settimeout(.05)
(root/'engine-started').write_text(str(os.getpid()))
while True:
 if (root/'close-listener').exists():
  s.close();(root/'listener-closed').write_text('closed')
  while True:time.sleep(.02)
 try:c,_=s.accept()
 except socket.timeout:continue
 try:
  c.settimeout(5)
  if exact(c,3)!=bytes([5,1,0]):raise ValueError('greeting')
  c.sendall(bytes([5,0]))
  if exact(c,10)!=bytes([5,1,0,1,198,18,0,53,0,53]):raise ValueError('destination')
  c.sendall(bytes([5,0,0,1,127,0,0,1,0,0]))
  q=exact(c,struct.unpack('!H',exact(c,2))[0]);(root/'dns-query').write_bytes(q)
  if mode=='pause':
   while not (root/'release-dns').exists():time.sleep(.005)
  answer=q[:2]+bytes.fromhex('81800001000100000000')+q[12:]+bytes.fromhex('c00c000100010000003c0004cb007114')
  if mode=='wrong-id':answer=bytes([answer[0]^1])+answer[1:]
  if mode=='wrong-question':answer=answer[:13]+b'X'+answer[14:]
  if mode=='nxdomain':answer=q[:2]+bytes.fromhex('81830001000000000000')+q[12:]
  if mode=='no-answers':answer=q[:2]+bytes.fromhex('81800001000000000000')+q[12:]
  if mode=='private-answer':answer=answer[:-4]+bytes([127,0,0,1])
  if mode=='trailing-data':answer+=b'extra'
  if mode=='socket-reused':
   fd=s.fileno();s.close();replacement=os.open('/dev/null',os.O_RDONLY)
   if replacement!=fd:os.dup2(replacement,fd)
  if mode=='oversized':c.sendall(bytes.fromhex('ffff'))
  elif mode=='truncated':c.sendall(struct.pack('!H',len(answer))+answer[:10])
  elif mode=='refused':pass
  else:c.sendall(struct.pack('!H',len(answer))+answer)
 except (OSError,EOFError):pass
 finally:c.close()
 if mode=='socket-reused':
  while True:time.sleep(.02)
`

func installLegacyDNSEngine(t *testing.T, f *legacyExitFixture, mode string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, "bin", "sing-box"), []byte(legacyDNSEngineFixture), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "dns-mode"), []byte(mode), 0600); err != nil {
		t.Fatal(err)
	}
}

func legacyDNSFixture(t *testing.T, mode string) (*legacyExitFixture, *linuxLegacyStandardExitOwner, context.Context, *atomic.Value) {
	t.Helper()
	f := newLegacyExitFixture(t, "off")
	installLegacyDNSEngine(t, f, mode)
	o, operation := f.prepareOff(t)
	var network atomic.Value
	network.Store("captured-test-network")
	// This workspace denies net.Interfaces' netlink inventory. Only that
	// physical-network observation and nft/TUN absence are modeled here.
	o.dns.network = func() string { return network.Load().(string) }
	if err := o.Start(operation); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	return f, o, operation, &network
}

func waitLegacyDNSFile(t *testing.T, root, name string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("original child did not reach DNS fixture stage", name)
}

func TestLegacyStandardDNSOriginalListenerAndReceipt(t *testing.T) {
	f, o, operation, _ := legacyDNSFixture(t, "valid")
	if err := o.ProveSelectedDNS(operation); err != nil {
		t.Fatal(err)
	}
	if o.dns.proof == nil || o.dns.proof.listener.cookie == 0 {
		t.Fatal("real query has no original socket receipt")
	}
	f.a.mu.Lock()
	f.a.state = state{Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: o.runtimeMode, Base: o.base, RouterID: o.routerID, Connected: true, Phase: "connected"}
	profile := f.a.profiles.Profiles[0]
	f.a.mu.Unlock()
	observed := observedConnection{Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: o.runtimeMode, Base: o.base, RouterID: o.routerID, Connected: true, Phase: "connected", Profile: profile}
	lookups := 0
	lookup := func(context.Context, string) ([]string, error) { lookups++; return []string{"203.0.113.20"}, nil }
	if proof := proveSelectedDNSWithLookup(context.Background(), f.a, observed, o.runtimeMode, lookup); proof.Status != "passed" || lookups != 0 {
		t.Fatal("captured DNS receipt was replaced by ambient resolution", proof, lookups)
	}
	if err := os.WriteFile(filepath.Join(f.root, "close-listener"), []byte("close"), 0600); err != nil {
		t.Fatal(err)
	}
	waitLegacyDNSFile(t, f.root, "listener-closed")
	if proof := proveSelectedDNSWithLookup(context.Background(), f.a, observed, o.runtimeMode, lookup); proof.Status == "passed" || lookups != 0 {
		t.Fatal("retired original listener borrowed an ambient answer", proof, lookups)
	}
}

func TestLegacyStandardDNSRejectsResponsesAndListenerReuse(t *testing.T) {
	for _, mode := range []string{"wrong-id", "wrong-question", "nxdomain", "no-answers", "private-answer", "trailing-data", "oversized", "truncated", "refused", "socket-reused"} {
		t.Run(mode, func(t *testing.T) {
			f, o, operation, _ := legacyDNSFixture(t, mode)
			if err := o.ProveSelectedDNS(operation); err == nil || o.dns.proof != nil {
				t.Fatal("unusable response or replaced original listener became proof", err)
			}
			waitLegacyDNSFile(t, f.root, "dns-query")
		})
	}
}

func TestLegacyStandardDNSRejectsForeignListenerAndPIDFD(t *testing.T) {
	f, o, operation, _ := legacyDNSFixture(t, "no-listener")
	foreign, err := net.Listen("tcp4", "127.0.0.1:1099")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	ctx, cancel := context.WithTimeout(operation, time.Second)
	defer cancel()
	if l, err := captureLegacyDNSListener(ctx, o.originalPIDFD, netip.MustParseAddrPort("127.0.0.1:1099")); err == nil {
		l.Close()
		t.Fatal("foreign process listener became the original child socket")
	}
	duplicate, err := os.Open(filepath.Join(f.root, "dns-mode"))
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	if l, err := captureLegacyDNSListener(ctx, duplicate, netip.MustParseAddrPort("127.0.0.1:1099")); err == nil {
		l.Close()
		t.Fatal("ordinary descriptor was accepted as a creation pidfd")
	}
}

func TestLegacyStandardDNSRejectsLateOwnershipChanges(t *testing.T) {
	for _, fault := range []string{"cancel", "network", "profile", "config-bytes", "config-inode", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			f, o, operation, network := legacyDNSFixture(t, "pause")
			done := make(chan error, 1)
			go func() { done <- o.ProveSelectedDNS(operation) }()
			waitLegacyDNSFile(t, f.root, "dns-query")
			switch fault {
			case "cancel":
				f.a.mu.Lock()
				cancel := f.a.connectionCancel
				f.a.mu.Unlock()
				cancel()
			case "network":
				network.Store("replacement-network")
			case "profile":
				f.a.mu.Lock()
				f.a.profiles.Profiles[0].DNSPort = 5353
				f.a.mu.Unlock()
			case "config-bytes":
				p := filepath.Join(o.launch.directory, "sing-box.json")
				if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "config-inode":
				p := filepath.Join(o.launch.directory, "sing-box.json")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(p, p+".original"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				foreign := exec.Command("python3", "-c", "import time;time.sleep(60)")
				if err := foreign.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { foreign.Process.Kill(); foreign.Wait() })
				f.a.mu.Lock()
				f.a.cmd = foreign
				f.a.mu.Unlock()
			}
			if err := os.WriteFile(filepath.Join(f.root, "release-dns"), []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil || o.dns.proof != nil {
					t.Fatal("late original DNS success was adopted", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancelled DNS worker did not join")
			}
		})
	}
}

func TestLegacyStandardDNSFailurePrecedesPublicProofAndConnected(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	installLegacyDNSEngine(t, f, "refused")
	public := 0
	adapter := platformStandardExitRuntime{
		prepareLegacy: func(a *app, cmd *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
			captured, err := prepareLegacyStandardExitOwnerWithObservers(a, cmd, mode, base, id, func() error { return nil }, func() string { return "captured-test-network" })
			if err != nil || captured == nil {
				return captured, err
			}
			o := captured.(*linuxLegacyStandardExitOwner)
			o.dns.network = func() string { return "captured-test-network" }
			o.offProtectionCheck = func(ctx context.Context) error {
				lease, err := acquireLegacyExitMutationLease(ctx, f.root)
				if err != nil {
					return err
				}
				defer lease.Close()
				return legacyExitStateAbsent(lease)
			}
			return o, nil
		},
		proveDNS: func(ctx context.Context, owner legacyStandardExitLaunch) error {
			return owner.(*linuxLegacyStandardExitOwner).ProveSelectedDNS(ctx)
		},
		prove:   func(*app, string) error { public++; return nil },
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	}
	body, _ := json.Marshal(standardExitConnectRequest{StandardExitID: f.exit.ID, Direct: true})
	response := httptest.NewRecorder()
	f.a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body)), adapter)
	if response.Code != http.StatusBadGateway || public != 0 || f.a.state.Connected {
		t.Fatal("working public proof bypassed failing selected DNS", response.Code, public, f.a.state.Connected, response.Body.String())
	}
	waitLegacyDNSFile(t, f.root, "dns-query")
	if _, exists := legacyStandardExitOwners.Load(f.a); exists {
		t.Fatal("failed DNS retained an unjoined original runtime")
	}
}

func TestLegacyStandardDNSGraphRejectsPolicyAndCacheMutations(t *testing.T) {
	f := newLegacyExitFixture(t, "off")
	command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(command.Args[3], "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := expectedDNSSelection(f.a.profiles.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"cache", "resolver", "port", "transport", "detour", "interception", "listener"} {
		t.Run(fault, func(t *testing.T) {
			var graph map[string]any
			if err := json.Unmarshal(raw, &graph); err != nil {
				t.Fatal(err)
			}
			dns := graph["dns"].(map[string]any)
			server := dns["servers"].([]any)[0].(map[string]any)
			switch fault {
			case "cache":
				dns["rules"].([]any)[0].(map[string]any)["disable_cache"] = false
			case "resolver":
				server["server"] = "9.9.9.9"
			case "port":
				server["server_port"] = 5353
			case "transport":
				server["type"] = "tcp"
			case "detour":
				server["detour"] = "direct"
			case "interception":
				graph["route"].(map[string]any)["rules"] = []any{}
			case "listener":
				graph["inbounds"].([]any)[1].(map[string]any)["listen"] = "0.0.0.0"
			}
			mutated, _ := json.Marshal(graph)
			if err := validateLegacyStandardDNSGraph(mutated, selected); err == nil {
				t.Fatal("changed DNS proof graph was admitted")
			}
		})
	}
	if err := validateLegacyStandardDNSGraph(raw, selected); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyStandardDNSObserverRetainsProtectionAfterRequestFinishes(t *testing.T) {
	f := newLegacyExitFixture(t, "on-connect")
	installLegacyDNSEngine(t, f, "valid")
	model := newLegacyProtectionModel()
	owner, operation, finish := f.prepareProtected(t, model)
	owner.dns.network = func() string { return "captured-test-network" }
	if err := owner.Start(operation); err != nil {
		t.Fatal(err)
	}
	waitLegacyOffEngine(t, f)
	if err := owner.ProveSelectedDNS(operation); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state = state{Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: owner.runtimeMode, Base: owner.base, RouterID: owner.routerID, Connected: true, Phase: "connected"}
	profile := f.a.profiles.Profiles[0]
	f.a.mu.Unlock()
	observed := observedConnection{Mode: "standard-exit", LogicalMode: "standard-exit", RuntimeMode: owner.runtimeMode, Base: owner.base, RouterID: owner.routerID, Connected: true, Phase: "connected", Profile: profile}
	finish()
	if operation.Err() == nil {
		t.Fatal("original activation request did not finish")
	}
	lookups := 0
	lookup := func(context.Context, string) ([]string, error) { lookups++; return []string{"203.0.113.20"}, nil }
	if proof := proveSelectedDNSWithLookup(context.Background(), f.a, observed, owner.runtimeMode, lookup); proof.Status != "passed" || lookups != 0 {
		t.Fatal("current protected receipt could not outlive its completed activation request", proof, lookups)
	}
	model.mu.Lock()
	original := model.tables[owner.session]
	delete(model.tables, owner.session)
	model.mu.Unlock()
	if proof := proveSelectedDNSWithLookup(context.Background(), f.a, observed, owner.runtimeMode, lookup); proof.Status == "passed" || lookups != 0 {
		t.Fatal("DNS observer ignored missing original native protection", proof, lookups)
	}
	model.mu.Lock()
	model.tables[owner.session] = original
	model.mu.Unlock()
}

func TestLegacyStandardDNSRejectsNetworkChangedBeforeFirstProof(t *testing.T) {
	for _, stage := range []string{"before-start", "before-first-proof", "after-dns-before-adoption"} {
		t.Run(stage, func(t *testing.T) {
			f := newLegacyExitFixture(t, "off")
			installLegacyDNSEngine(t, f, "valid")
			// prepareOff supplies its explicit physical-network observer at the same
			// preparation boundary as production; the mutable observer below starts
			// with that exact captured identity and only then simulates replacement.
			owner, operation := f.prepareOff(t)
			var network atomic.Value
			network.Store("captured-test-network")
			owner.dns.network = func() string { return network.Load().(string) }
			if stage == "before-start" {
				network.Store("replacement-network")
				if err := owner.Start(operation); err == nil || owner.command.Process != nil || owner.started || owner.registered {
					t.Fatal("network replacement before Start created the original engine", err)
				}
			} else {
				if err := owner.Start(operation); err != nil {
					t.Fatal(err)
				}
				waitLegacyOffEngine(t, f)
				if stage == "after-dns-before-adoption" {
					if err := owner.ProveSelectedDNS(operation); err != nil {
						t.Fatal(err)
					}
					network.Store("replacement-network")
					if err := owner.Current(operation); err == nil {
						t.Fatal("final owner admission accepted a changed network after DNS proof")
					}
				} else {
					network.Store("replacement-network")
					if err := owner.ProveSelectedDNS(operation); err == nil || owner.dns.proof != nil {
						t.Fatal("first DNS proof adopted the replacement physical network", err)
					}
				}
			}
			if owner.dns.networkID != "captured-test-network" {
				t.Fatal("later observation replaced the preparation network identity")
			}
			if stage != "after-dns-before-adoption" {
				if _, err := os.Stat(filepath.Join(f.root, "dns-query")); !os.IsNotExist(err) {
					t.Fatal("changed physical network reached selected DNS exchange", err)
				}
			}
		})
	}
}

func TestLegacyStandardDNSPreparationRequiresPhysicalNetwork(t *testing.T) {
	for _, observe := range []func() string{nil, func() string { return "" }} {
		f := newLegacyExitFixture(t, "off")
		installLegacyDNSEngine(t, f, "valid")
		command, err := nativeStandardExitCommand(f.a, f.a.profiles.Profiles[0], common.RouterProfile{}, f.exit, true)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := prepareLegacyStandardExitOwnerWithObservers(f.a, command, "standard-socks5", "external", "standard:"+f.exit.ID, func() error { return nil }, observe)
		if err == nil || owner != nil {
			t.Fatal("unavailable original physical network admitted a launch", err)
		}
		if _, err := os.Stat(filepath.Join(f.root, "engine-started")); !os.IsNotExist(err) {
			t.Fatal("unavailable preparation network executed the engine", err)
		}
	}
}
