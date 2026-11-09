package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mtuprobe"
	"router-vpn/internal/nativeopenvpn"
)

type desktopImportedMTUFixture struct {
	*desktopNodeMTUFixture
	owner   *desktopImportedMTUOwner
	profile common.RouterProfile
	current atomic.Bool
}

// Only the platform reader, physical-network observer and kernel socket boundary
// are controlled here. The actual private mailbox, shared authenticated proof,
// packet/transfer controller, host finalization and cache transactions execute.
func newDesktopImportedMTUFixture(t *testing.T, openVPN bool) *desktopImportedMTUFixture {
	t.Helper()
	f := &desktopImportedMTUFixture{desktopNodeMTUFixture: newDesktopNodeMTUFixture(t)}
	f.current.Store(true)
	f.launch.importedEntry = true
	f.profile = common.RouterProfile{ID: "paired-final", NodeKind: "router-vpn", NodeProofID: strings.Repeat("a", 64),
		RouterAPI: "http://10.77.0.1:8787", APIToken: "private-imported-mtu-fixture", DAITAHost: "10.77.0.1", DAITAPort: 45999,
		MTUPolicy: "auto", DNSMode: "home", AdGuardIPv4: "10.77.0.1", IPv6Mode: "on"}
	graph := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true,"strict_route":true,"mtu":1420}],"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"192.0.2.2","server_port":8388,"password":"captured-final-key","method":"2022-blake3-aes-256-gcm","detour":"entry-wg"}],"endpoints":[{"type":"wireguard","tag":"entry-wg","mtu":1500}],"route":{"final":"proxy","rules":[{"protocol":"dns","action":"hijack-dns"}]},"dns":{"final":"selected","servers":[{"type":"udp","tag":"selected","server":"10.77.0.1","detour":"proxy"}]}}`
	if openVPN {
		graph = strings.Replace(graph, `"type":"wireguard","tag":"entry-wg","mtu":1500`, `"type":"openvpn-client","tag":"entry-wg","mtu":1500,"system":false,"server":"203.0.113.24","server_port":1194,"network":"udp"`, 1)
		f.base.OpenVPN = nativeopenvpn.PacketObservation{Remote: nativeopenvpn.RemoteReceipt{
			Remote: nativeopenvpn.Remote{Host: "203.0.113.24", Port: 1194, Network: "udp"}, Generation: 3, ConnectedAt: time.Now().UnixMilli()}, MTU: 1500}
		original := f.base.OpenVPN
		f.launch.importedOpenVPN = &desktopImportedOpenVPNRuntime{original: &original,
			spec: desktopImportedOpenVPNSpec{Remote: original.Remote.Remote, Minimum: original.MTU}, notBefore: original.Remote.ConnectedAt}
	}
	digest := sha256.Sum256([]byte(graph))
	f.base.Config, f.launch.configSHA256 = hex.EncodeToString(digest[:]), hex.EncodeToString(digest[:])
	if err := writeDesktopRuntimeFile(f.launch, "sing-box.json", []byte(graph), false); err != nil {
		t.Fatal(err)
	}
	if err := f.publish(f.base, false); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mobilemtu.ReadProfile(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &nativeMultihopRuntime{launch: f.launch, network: strings.Repeat("7", 64), selection: multihopSelection{Control: f.profile, Exit: f.profile}}
	f.owner = &desktopImportedMTUOwner{launch: f.launch, runtime: runtime, policy: policy, config: graph, record: f.base, openVPN: f.base.OpenVPN,
		dial: dialDesktopImportedMTUSocket, current: func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !f.current.Load() {
				return errors.New("fixture original physical path or runtime replaced")
			}
			return nil
		}}
	return f
}

func importedMTUTestOperation(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, finish, err := mobilemtu.WithOperationContext(context.Background(), 10*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finish)
	work, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	return work, cancel
}

func importedMTUTestCleanup(t *testing.T, original context.Context) context.Context {
	t.Helper()
	ctx, err := mobilemtu.OperationCleanupContext(original)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func importedMTUClose(t *testing.T, owner *desktopImportedMTUOwner, cleanup context.Context) {
	t.Helper()
	owner.mu.Lock()
	err := owner.closeLocked(cleanup)
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func importedMTUCommands(t *testing.T, commands <-chan desktopNodeMTUCommand, actions ...string) {
	t.Helper()
	for _, action := range actions {
		select {
		case got := <-commands:
			if got.Action != action {
				t.Fatal("native command changed captured sequence", got.Action, action)
			}
		case <-time.After(time.Second):
			t.Fatal("native fixture did not consume", action)
		}
	}
	select {
	case got := <-commands:
		t.Fatal("unowned additional native command", got.Action)
	default:
	}
}

func TestDesktopImportedMTUOwnedCommitRollbackAndLateCommitCancellation(t *testing.T) {
	for _, protocol := range []string{"packet", "openvpn"} {
		for _, ending := range []string{"commit", "rollback", "late-commit-cancel"} {
			t.Run(protocol+"/"+ending, func(t *testing.T) {
				f := newDesktopImportedMTUFixture(t, protocol == "openvpn")
				ctx, cancel := importedMTUTestOperation(t)
				commands := startDesktopNodeMTUFixtureChild(t, f.desktopNodeMTUFixture, func(command desktopNodeMTUCommand, _ *desktopNodeMTURecord) {
					if ending == "late-commit-cancel" && command.Action == "commit" {
						cancel()
					}
				})
				original, err := f.owner.CaptureContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.owner.prepare(ctx, strings.Repeat("a", 32)); err != nil {
					t.Fatal(err)
				}
				if f.launch.importedDNSMu.TryLock() {
					f.launch.importedDNSMu.Unlock()
					t.Fatal("active imported MTU lease did not exclude ordinary DNS/measurements")
				}
				next, err := f.owner.ChangeMTU(ctx, original, 1380)
				if err != nil || next.MTU != 1380 || next.Interface == original.Interface || next.Session != original.Session || next.Path != original.Path {
					t.Fatal("retained native change lost original ownership", next, err)
				}
				if ending != "rollback" {
					err = f.owner.finish(ctx, true)
					if ending == "commit" && err != nil || ending != "commit" && err == nil {
						t.Fatal("late commit bypassed original cancellation", err)
					}
				} else {
					cancel()
				}
				cleanup := importedMTUTestCleanup(t, ctx)
				importedMTUClose(t, f.owner, cleanup)
				live, err := f.owner.CaptureContext(cleanup)
				if err != nil || f.owner.mailboxHeld || f.owner.sockets.Load() != 0 {
					t.Fatal("original native lease did not join", live, err)
				}
				if !f.launch.importedDNSMu.TryLock() {
					t.Fatal("closed native lease retained ordinary DNS mailbox")
				}
				f.launch.importedDNSMu.Unlock()
				if ending == "commit" {
					if !f.owner.committed.Load() || live.MTU != 1380 {
						t.Fatal("native commit was not actually retained", live)
					}
					if _, err := f.owner.FinalizedRollbackContext(cleanup, original); err == nil {
						t.Fatal("accepted commit was relabelled as restored")
					}
					importedMTUCommands(t, commands, "begin", "set", "commit")
				} else {
					restored, err := f.owner.FinalizedRollbackContext(cleanup, original)
					if err != nil || restored != live || live.MTU != original.MTU || f.owner.committed.Load() {
						t.Fatal("exact original rollback was not observed", restored, live, err)
					}
					if ending == "rollback" {
						importedMTUCommands(t, commands, "begin", "set", "rollback")
					} else {
						importedMTUCommands(t, commands, "begin", "set", "commit", "revert-unconfirmed-commit")
					}
				}
			})
		}
	}
}

func TestDesktopImportedMTURejectsForeignOperationReaderAndProbe(t *testing.T) {
	f := newDesktopImportedMTUFixture(t, false)
	commands := startDesktopNodeMTUFixtureChild(t, f.desktopNodeMTUFixture, nil)
	ctx, _ := importedMTUTestOperation(t)
	if err := f.owner.prepare(ctx, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	state, err := f.owner.CaptureContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := importedMTUTestOperation(t)
	if _, err := f.owner.ChangeMTU(other, state, 1380); err == nil {
		t.Fatal("another operation mutated the retained MTU lease")
	}
	for _, fault := range []string{"session", "path", "interface", "mtu"} {
		wrong := state
		switch fault {
		case "session":
			wrong.Session = "replacement"
		case "path":
			wrong.Path = "replacement"
		case "interface":
			wrong.Interface = "replacement"
		case "mtu":
			wrong.MTU++
		}
		if _, err := f.owner.ChangeMTU(ctx, wrong, 1380); err == nil {
			t.Fatal("foreign expected reader changed native MTU", fault)
		}
	}
	var dials atomic.Int32
	f.owner.dial = func(context.Context, string, string, desktopNodeMTURecord, func(context.Context) error) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("fixture forbids socket creation")
	}
	for _, target := range []struct{ network, address string }{
		{"tcp", "1.1.1.1:8787"}, {"tcp", "localhost:8787"}, {"tcp", "127.0.0.1:8787"}, {"tcp", "10.77.0.2:8787"},
		{"tcp", "10.77.0.1:443"}, {"udp", "10.77.0.2:45999"}, {"udp", "10.77.0.1:46000"}, {"udp4", "10.77.0.1:45999"},
	} {
		if conn, err := f.owner.DialThroughTunnel(ctx, state, target.network, target.address); err == nil || conn != nil {
			t.Fatal("uncaptured probe target was admitted", target)
		}
	}
	if dials.Load() != 0 {
		t.Fatal("invalid destination reached native socket binding")
	}
	cleanup := importedMTUTestCleanup(t, ctx)
	if _, err := f.owner.ChangeMTU(cleanup, state, 1380); err == nil {
		t.Fatal("cleanup admitted a different target")
	}
	if conn, err := f.owner.DialThroughTunnel(cleanup, state, "tcp", "10.77.0.1:8787"); err == nil || conn != nil {
		t.Fatal("cleanup admitted new measurements")
	}
	importedMTUClose(t, f.owner, cleanup)
	importedMTUCommands(t, commands, "begin", "rollback")
}

type desktopImportedMTUPartialDialConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *desktopImportedMTUPartialDialConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func TestDesktopImportedMTUFailedDialClosesPartialConnection(t *testing.T) {
	f := newDesktopImportedMTUFixture(t, false)
	commands := startDesktopNodeMTUFixtureChild(t, f.desktopNodeMTUFixture, nil)
	ctx, _ := importedMTUTestOperation(t)
	if err := f.owner.prepare(ctx, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	state, err := f.owner.CaptureContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	partial := &desktopImportedMTUPartialDialConn{Conn: local}
	dialFailure := errors.New("captured native dial failed after opening a socket")
	f.owner.dial = func(context.Context, string, string, desktopNodeMTURecord, func(context.Context) error) (net.Conn, error) {
		return partial, dialFailure
	}
	connection, err := f.owner.DialThroughTunnel(ctx, state, "tcp", "10.77.0.1:8787")
	if connection != nil || !errors.Is(err, dialFailure) || partial.closed.Load() != 1 || f.owner.sockets.Load() != 0 {
		t.Fatal("failed native dial leaked or adopted its partial connection", connection, err, partial.closed.Load(), f.owner.sockets.Load())
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("partial native socket remained usable after failed dial", err)
	}
	f.owner.connections.Range(func(_, _ any) bool { t.Error("partial socket entered retained connection ownership"); return false })
	importedMTUClose(t, f.owner, importedMTUTestCleanup(t, ctx))
	importedMTUCommands(t, commands, "begin", "rollback")
}

func TestDesktopImportedMTUOpenVPNReplacementCannotAuthorizeRollback(t *testing.T) {
	for _, fault := range []string{"generation", "capacity", "remote", "path", "retired"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, true)
			commands := startDesktopNodeMTUFixtureChild(t, f.desktopNodeMTUFixture, nil)
			ctx, _ := importedMTUTestOperation(t)
			if err := f.owner.prepare(ctx, strings.Repeat("a", 32)); err != nil {
				t.Fatal(err)
			}
			original, err := f.owner.CaptureContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			live := f.owner.kernel.record
			switch fault {
			case "generation":
				live.OpenVPN.Remote.Generation++
			case "capacity":
				live.OpenVPN.MTU++
			case "remote":
				live.OpenVPN.Remote.Port++
			case "path":
				f.current.Store(false)
			case "retired":
				f.launch.importedOpenVPN.retired.Store(true)
			}
			if err := f.publish(live, false); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.CaptureContext(ctx); err == nil {
				t.Fatal("replacement retained MTU measurement authority")
			}
			cleanup := importedMTUTestCleanup(t, ctx)
			if _, err := f.owner.RollbackStateContext(cleanup, original); err == nil {
				t.Fatal("replacement authorized original native rollback")
			}
			f.owner.mu.Lock()
			err = f.owner.closeLocked(cleanup)
			f.owner.mu.Unlock()
			if err == nil || !f.owner.mailboxHeld {
				t.Fatal("unconfirmed cleanup was labelled closed", err)
			}
			stopped, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: f.launch.mtuSession, SourceSHA256: f.launch.configSHA256, Closed: true})
			if err := writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false); err != nil {
				t.Fatal(err)
			}
			importedMTUClose(t, f.owner, cleanup)
			if _, restored, err := f.owner.kernel.CleanupRestoredContext(cleanup); err != nil || restored {
				t.Fatal("original child retirement invented a successful MTU rollback", err)
			}
			importedMTUCommands(t, commands, "begin")
		})
	}
}

func TestDesktopImportedMTULeaseKeepsOrdinaryOpenVPNMailboxUnentered(t *testing.T) {
	f := newDesktopImportedMTUFixture(t, true)
	commands := startDesktopNodeMTUFixtureChild(t, f.desktopNodeMTUFixture, nil)
	ctx, _ := importedMTUTestOperation(t)
	if err := f.owner.prepare(ctx, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ordinary := &desktopNodeMTUWaitingContext{Context: parent, waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- exchangeDesktopImportedOpenVPN(ordinary, f.launch, f.owner.current) }()
	select {
	case <-ordinary.waiting:
	case <-time.After(time.Second):
		t.Fatal("ordinary observer did not reach the held MTU mailbox")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("ordinary observer lost its original cancellation", err)
	}
	if _, err := readDesktopRuntimeFile(f.launch, "node-dns-request.json", 4096); !errors.Is(err, os.ErrNotExist) || f.launch.importedDNSGeneration != 0 || f.launch.importedOpenVPN.retired.Load() {
		t.Fatal("ordinary proof entered active native lease or retired healthy endpoint", err)
	}
	importedMTUClose(t, f.owner, importedMTUTestCleanup(t, ctx))
	importedMTUCommands(t, commands, "begin", "rollback")
}

type desktopImportedMTUPrivatePeer struct {
	f         *desktopImportedMTUFixture
	server    *httptest.Server
	mode      string
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
	proofs    atomic.Int32
	datagrams atomic.Int32
	download  atomic.Int64
	upload    atomic.Int64
}

func newDesktopImportedMTUPrivatePeer(t *testing.T, f *desktopImportedMTUFixture, mode string) *desktopImportedMTUPrivatePeer {
	t.Helper()
	p := &desktopImportedMTUPrivatePeer{f: f, mode: mode, entered: make(chan struct{}), release: make(chan struct{})}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.profile.APIToken {
			t.Error("private MTU used another node credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/health":
			p.proofs.Add(1)
			proof := f.profile.NodeProofID
			if mode == "wrong-proof" {
				proof = strings.Repeat("b", 64)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "node_id": proof, "proof": "router-vpn-private-agent-v1"})
		case "/api/benchmark/download":
			if mode == "cancel-download" {
				p.once.Do(func() { close(p.entered) })
				<-r.Context().Done()
				return
			}
			size, err := strconv.Atoi(r.URL.Query().Get("bytes"))
			if err != nil || size != 256<<10 {
				t.Error("private download lost bounded byte count")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(size))
			w.Header().Set("X-Routervpn-Benchmark", "download-v1")
			w.Header().Set("X-Routervpn-Benchmark-Bytes", strconv.Itoa(size))
			if mode == "held-download" {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				p.once.Do(func() {
					close(p.entered)
					select {
					case <-p.release:
					case <-r.Context().Done():
					}
				})
				if r.Context().Err() != nil {
					return
				}
			}
			n, _ := w.Write(make([]byte, size))
			p.download.Add(int64(n))
		case "/api/benchmark/upload":
			n, err := io.Copy(io.Discard, io.LimitReader(r.Body, (256<<10)+1))
			if r.Context().Err() != nil {
				return
			}
			if err != nil || n != 256<<10 || r.ContentLength != n || len(r.TransferEncoding) != 0 {
				t.Error("private upload did not actually transfer its bounded bytes", n, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			p.upload.Add(n)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "direction": "upload", "bytes": n, "server_receive_ms": 1, "peer": "10.77.0.2", "proof": "authenticated tunnel-peer private throughput sink"})
		default:
			t.Error("private MTU opened another API", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(p.server.Close)
	f.owner.dial = func(ctx context.Context, network, address string, record desktopNodeMTURecord, current func(context.Context) error) (net.Conn, error) {
		if err := current(ctx); err != nil || !record.Active || record.Session != f.base.Session || record.Config != f.base.Config {
			return nil, errors.Join(err, errors.New("fixture kernel socket lost exact active native reader"))
		}
		if network == "tcp4" && address == "10.77.0.1:8787" {
			return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(p.server.URL, "http://"))
		}
		if network != "udp4" || address != "10.77.0.1:45999" {
			return nil, errors.New("fixture received another native socket target")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			packet := make([]byte, 9001)
			for {
				n, err := server.Read(packet)
				if err != nil || n != record.MTU-28 {
					return
				}
				reply, err := mtuprobe.Reply(packet[:n], f.profile.APIToken, f.profile.NodeProofID, time.Now())
				if err != nil {
					return
				}
				p.datagrams.Add(1)
				if mode == "blind-echo" {
					copy(reply, packet[:n])
				}
				if _, err := server.Write(reply); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	return p
}

func importedMTUTestUI(t *testing.T, f *desktopImportedMTUFixture) *desktopImportedMTUUI {
	t.Helper()
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "profiles.json")}, cmd: f.launch.command,
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: f.profile.ID, Profiles: []common.RouterProfile{f.profile}}}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	u := &desktopImportedMTUUI{a: a, runtime: f.owner.runtime, owner: f.owner,
		identity: mtuViewIdentity{Session: f.base.Session, Profile: f.profile.ID, Native: true}}
	u.cache = &desktopImportedMTUCache{ui: u}
	raw, _ := json.Marshal(f.profile)
	controller, err := mobilemtu.NewContext(context.Background(), f.owner, f.owner.config, string(raw), u.cache)
	if err != nil {
		t.Fatal(err)
	}
	u.controller = controller
	t.Cleanup(func() { _ = controller.Close(); mtuViewSlots.Delete(a) })
	return u
}

func TestDesktopImportedMTUSharedPrivateControllerAndFinalization(t *testing.T) {
	for _, mode := range []string{"success", "cached-auto", "cached-retest", "wrong-proof", "blind-echo", "cancel-download", "cancel-at-commit"} {
		t.Run(mode, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, true)
			u := importedMTUTestUI(t, f)
			peer := newDesktopImportedMTUPrivatePeer(t, f, mode)
			parent, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			call := context.Context(parent)
			if strings.HasPrefix(mode, "cached-") {
				plan, err := mobilemtu.NewPlan(f.owner.config, f.base.MTU)
				if err != nil {
					t.Fatal(err)
				}
				profile := &u.a.profiles.Profiles[0]
				profile.EffectiveMTU, profile.EffectiveMTUSource = 1300, "measured-private-system-tun"
				profile.EffectiveMTUPathKey = plan.PathKey(f.owner.policy, f.owner.state(f.base).Path)
				profile.EffectiveMTUNetworkFingerprint = u.runtime.network
				profile.EffectiveMTUProfileFingerprint = mtuProfileSnapshotToken(*profile)
				profile.EffectiveMTUTestedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
				if mode == "cached-auto" {
					call = context.WithValue(parent, mtuAutomaticContextKey{}, true)
				}
			}
			ctx, operation, err := beginMTUViewOperation(u.a, call, mtuViewRequest{Request: strings.Repeat("a", 32)}, u.identity)
			if err != nil {
				t.Fatal(err)
			}
			var cancelled atomic.Bool
			startDesktopNodeMTUFixtureChildWithHeartbeat(t, f.desktopNodeMTUFixture, func(command desktopNodeMTUCommand, _ *desktopNodeMTURecord) {
				if mode == "cancel-at-commit" && command.Action == "commit" && cancelled.CompareAndSwap(false, true) {
					operation.cancel()
				}
			}, true)
			before := u.controller.Config()
			type outcome struct {
				status mobilemtu.Status
				err    error
			}
			done := make(chan outcome, 1)
			go func() { status, err := u.run(ctx, operation); done <- outcome{status, err} }()
			if mode == "cancel-download" {
				select {
				case <-peer.entered:
				case ended := <-done:
					t.Fatal("MTU operation did not enter private transfer", ended.err, ended.status)
				case <-parent.Done():
					t.Fatal("private transfer never started")
				}
				response := httptest.NewRecorder()
				if !cancelMTUViewOperation(parent, u.a, response, mtuViewRequest{Request: operation.request, Session: u.identity.Session, Profile: u.identity.Profile}) || response.Code != http.StatusOK {
					t.Fatal("public Cancel did not reach retained original operation", response.Body.String())
				}
			}
			result := <-done
			success := mode == "success" || strings.HasPrefix(mode, "cached-")
			if success != (result.err == nil) || f.owner.mailboxHeld || f.owner.sockets.Load() != 0 {
				t.Fatal("private controller did not join its real native closure", result.err, result.status)
			}
			live, err := f.owner.CaptureContext(parent)
			if err != nil {
				t.Fatal(err)
			}
			if !success {
				if result.status.Measured || !result.status.Restored || live.MTU != f.base.MTU || u.controller.Config() != before || u.cache.written != "" {
					t.Fatal("failed private measurement or commit did not restore exact original config/history", result.status, live)
				}
			} else {
				if !result.status.Measured || result.status.EffectiveMTU != live.MTU || !result.status.Complete || result.status.Running || peer.proofs.Load() < 3 || peer.datagrams.Load() < 12 || peer.download.Load() < 256<<10 || peer.upload.Load() < 256<<10 {
					t.Fatal("measured result omitted original private proof, datagrams or transferred bytes", result.status)
				}
				for _, candidate := range result.status.Candidates {
					if !candidate.Working || candidate.PacketsReceived != 6 || candidate.PacketsSent != 6 || candidate.DatagramBytes != candidate.MTU-28 || candidate.Upload == nil || candidate.Download == nil || candidate.Upload.Bytes != 256<<10 || candidate.Download.Bytes != 256<<10 {
						t.Fatal("candidate invented private packet or transfer evidence", candidate)
					}
				}
				if strings.HasPrefix(mode, "cached-") {
					found := false
					for _, candidate := range result.status.Candidates {
						found = found || candidate.MTU == 1300
					}
					if found != (mode == "cached-auto") {
						t.Fatal("Auto cache suggestion or Retest bypass changed", mode, result.status.Candidates)
					}
				}
				stored, ok := u.a.profileByIDLocked(f.profile.ID)
				if !ok || stored.EffectiveMTU != live.MTU || stored.EffectiveMTUSource != "measured-private-system-tun" || mtuProfileSnapshotToken(stored) != mtuProfileSnapshotToken(f.profile) {
					t.Fatal("historical result changed credentials, DNS or captured policy")
				}
			}
			if mode == "cancel-at-commit" {
				// The second Retest uses the retained controller and its exact
				// restored config, not a new controller hiding stale adoption.
				ctx, next, err := beginMTUViewOperation(u.a, parent, mtuViewRequest{Request: strings.Repeat("b", 32)}, u.identity)
				if err != nil {
					t.Fatal(err)
				}
				if status, err := u.run(ctx, next); err != nil || !status.Measured {
					t.Fatal("second imported Retest could not measure restored original state", err, status)
				}
			}
		})
	}
}

func TestDesktopImportedMTULongTransferRequiresNativeHeartbeat(t *testing.T) {
	for _, heartbeat := range []bool{true, false} {
		name := "original-periodic-reader"
		if !heartbeat {
			name = "missing-periodic-reader"
		}
		t.Run(name, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, true)
			u := importedMTUTestUI(t, f)
			peer := newDesktopImportedMTUPrivatePeer(t, f, "held-download")
			_, joinChild := startDesktopNodeMTUFixtureChildWithHeartbeat(t, f.desktopNodeMTUFixture, nil, heartbeat)
			parent, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			ctx, operation, err := beginMTUViewOperation(u.a, parent, mtuViewRequest{Request: strings.Repeat("a", 32)}, u.identity)
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				status mobilemtu.Status
				err    error
			}
			done := make(chan outcome, 1)
			go func() { status, err := u.run(ctx, operation); done <- outcome{status, err} }()
			select {
			case <-peer.entered:
			case result := <-done:
				t.Fatal("real private transfer did not enter", result.err, result.status)
			case <-parent.Done():
				t.Fatal("private transfer did not reach its bounded body")
			}
			record, err := readDesktopNodeMTUContext(parent, f.launch)
			if err != nil {
				t.Fatal(err)
			}
			// Hold an actual HTTP body beyond this precise receipt's existing
			// two-second validity. No native or production timeout is changed.
			delay := time.NewTimer(time.Until(time.UnixMilli(record.Heartbeat).Add(2100 * time.Millisecond)))
			select {
			case <-delay.C:
			case <-parent.Done():
				delay.Stop()
				t.Fatal("held private transfer outlived its original caller")
			}
			close(peer.release)
			result := <-done
			if heartbeat {
				if result.err != nil || !result.status.Measured || f.owner.mailboxHeld || f.owner.sockets.Load() != 0 || peer.download.Load() < 256<<10 || peer.upload.Load() < 256<<10 {
					t.Fatal("fresh original periodic reader did not retain its real transfer", result.err, result.status)
				}
			} else {
				if result.err == nil || result.status.Measured || result.status.Restored || !operation.cleanupPending || !f.owner.mailboxHeld {
					t.Fatal("missing native heartbeat fabricated a current result or joined rollback", result.err, result.status)
				}
				// The fixture child really joins before emitting its terminal
				// receipt. The host can release retirement, never invent MTU.
				joinChild()
				stopped, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: f.launch.mtuSession, SourceSHA256: f.launch.configSHA256, Closed: true})
				if err := writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false); err != nil {
					t.Fatal(err)
				}
				if err := u.releaseObserved(parent); err != nil || f.owner.mailboxHeld || operation.cleanupPending || operation.status.Restored || operation.status.Measured {
					t.Fatal("checked failed-heartbeat child did not retire without a fabricated result", err)
				}
			}
		})
	}
}

func TestDesktopImportedMTUHistoricalSuggestionRequiresOriginalPathAndAge(t *testing.T) {
	for _, fault := range []string{"valid", "expired", "future", "network", "path", "profile", "source", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, false)
			u := importedMTUTestUI(t, f)
			key := strings.Repeat("8", 64)
			profile := &u.a.profiles.Profiles[0]
			profile.EffectiveMTU, profile.EffectiveMTUSource, profile.EffectiveMTUPathKey = 1380, "measured-private-system-tun", key
			profile.EffectiveMTUNetworkFingerprint, profile.EffectiveMTUProfileFingerprint = u.runtime.network, mtuProfileSnapshotToken(*profile)
			profile.EffectiveMTUTestedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			switch fault {
			case "expired":
				profile.EffectiveMTUTestedAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano)
			case "future":
				profile.EffectiveMTUTestedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "network":
				profile.EffectiveMTUNetworkFingerprint = "replacement"
			case "path":
				profile.EffectiveMTUPathKey = strings.Repeat("9", 64)
			case "profile":
				profile.APIToken = "replacement credential reference"
			case "source":
				profile.EffectiveMTUSource = "saved-unmeasured"
			case "oversized":
				profile.EffectiveMTU = 9001
			}
			_, found, err := u.cache.LookupContext(context.Background(), key)
			if fault == "valid" && (!found || err != nil) || fault != "valid" && found {
				t.Fatal("historical hint borrowed another path, policy or age", found, err)
			}
		})
	}
}

func TestDesktopImportedMTUHistoryRollbackKeepsNewerState(t *testing.T) {
	for _, fault := range []string{"owned", "credential", "new-result", "foreign-operation", "expired-cleanup"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, false)
			u := importedMTUTestUI(t, f)
			work, finish, err := mobilemtu.WithOperationContext(context.Background(), time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			u.owner.operation = work
			u.cache.before = f.profile
			profile := &u.a.profiles.Profiles[0]
			profile.EffectiveMTU, profile.EffectiveMTUSource, profile.EffectiveMTUPathKey = 1380, "measured-private-system-tun", strings.Repeat("8", 64)
			u.cache.written = mtuMeasurementFieldsDigest(*profile)
			cleanup := importedMTUTestCleanup(t, work)
			switch fault {
			case "credential":
				profile.APIToken = "replacement credential reference"
			case "new-result":
				profile.EffectiveMTU = 1360
			case "foreign-operation":
				other, _ := importedMTUTestOperation(t)
				cleanup = importedMTUTestCleanup(t, other)
			case "expired-cleanup":
				finish()
			}
			before, _ := json.Marshal(*profile)
			err = u.cache.restore(cleanup)
			after, _ := json.Marshal(*profile)
			if fault == "owned" {
				if err != nil || u.cache.written != "" || profile.EffectiveMTU != f.profile.EffectiveMTU || mtuProfileSnapshotToken(*profile) != mtuProfileSnapshotToken(f.profile) {
					t.Fatal("owned historical rollback changed original settings or credentials", err)
				}
			} else if err == nil || string(before) != string(after) || u.cache.written == "" {
				t.Fatal("old historical rollback overwrote newer or unowned state", err)
			}
		})
	}
}

func TestDesktopImportedMTUClosedLeaseNeedsFreshProofToReportRestored(t *testing.T) {
	for _, fault := range []string{"original", "reader", "network", "openvpn-generation", "retired-child"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, true)
			u := importedMTUTestUI(t, f)
			kernel := f.desktopNodeMTUFixture.owner(true)
			kernel.record.Active, kernel.record.Restored = false, true
			kernel.closed, kernel.committed = true, true
			f.owner.kernel, f.owner.originalMTU = kernel, f.base.MTU
			f.launch.importedDNSMu.Lock()
			f.owner.mailboxHeld = true
			u.operation = &mtuViewOperation{cleanupPending: true, status: mobilemtu.Status{Running: true, EffectiveMTU: f.base.MTU}}
			live := kernel.record
			switch fault {
			case "reader":
				live.Reader++
			case "network":
				f.current.Store(false)
			case "openvpn-generation":
				live.OpenVPN.Remote.Generation++
			case "retired-child":
				stopped, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: f.launch.mtuSession, SourceSHA256: f.launch.configSHA256, Closed: true})
				if err := writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.publish(live, false); err != nil {
				t.Fatal(err)
			}
			if err := u.releaseObserved(context.Background()); err != nil || f.owner.mailboxHeld || u.operation.cleanupPending {
				t.Fatal("closed original lease did not release its retained mailbox", err)
			}
			status := u.operation.status
			if fault == "original" {
				if !status.Restored || status.EffectiveMTU != f.base.MTU {
					t.Fatal("fresh original rollback was not reported", status)
				}
			} else if status.Restored || status.Measured || status.EffectiveMTU != 0 {
				t.Fatal("numeric MTU match borrowed replacement or retired runtime", status)
			}
		})
	}
}

func TestDesktopImportedMTUCheckedRetirementReleasesOnlyItsRemovedWorkspace(t *testing.T) {
	for _, fault := range []string{"verified-retirement", "missing-closed", "missing-retired"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopImportedMTUFixture(t, true)
			u := importedMTUTestUI(t, f)
			kernel := f.desktopNodeMTUFixture.owner(true)
			f.owner.kernel, f.owner.originalMTU = kernel, f.base.MTU
			f.launch.importedDNSMu.Lock()
			f.owner.mailboxHeld = true
			t.Cleanup(func() {
				if f.owner.mailboxHeld {
					f.owner.mailboxHeld = false
					f.launch.importedDNSMu.Unlock()
				}
			})
			u.operation = &mtuViewOperation{cleanupPending: true, status: mobilemtu.Status{Running: true, EffectiveMTU: f.base.MTU}}
			stopped, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: f.launch.mtuSession, SourceSHA256: f.launch.configSHA256, Closed: true})
			if err := writeDesktopRuntimeFile(f.launch, "stopped.json", stopped, false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := kernel.CloseContext(ctx); err != nil || !kernel.closed || !kernel.runtimeRetired || !f.launch.nodeStopAcknowledged {
				t.Fatal("fixture did not verify original native retirement", err)
			}
			// Use the real owned cleanup after the checked stop, as a monitor
			// may do before the host's late mailbox release is admitted.
			if err := cleanupDesktopNodeLaunch(f.launch); err != nil {
				t.Fatal(err)
			}
			f.current.Store(false)
			switch fault {
			case "missing-closed":
				kernel.closed = false
			case "missing-retired":
				kernel.runtimeRetired = false
			}
			err := u.releaseObserved(ctx)
			if fault == "verified-retirement" {
				if err != nil || f.owner.mailboxHeld || u.operation.cleanupPending || !f.launch.importedDNSMu.TryLock() {
					t.Fatal("checked original retirement stranded its old mailbox after workspace cleanup", err)
				}
				f.launch.importedDNSMu.Unlock()
				status := u.operation.status
				if status.Measured || status.Restored || status.Running || !status.Complete || status.EffectiveMTU != 0 || status.Source != "unavailable-stale-owner" {
					t.Fatal("retired original child manufactured a live MTU or rollback proof", status)
				}
			} else {
				if err == nil || !f.owner.mailboxHeld || !u.operation.cleanupPending {
					t.Fatal("incomplete retirement receipt released an unproved native owner", err)
				}
				if f.launch.importedDNSMu.TryLock() {
					f.launch.importedDNSMu.Unlock()
					t.Fatal("one retained retirement flag unlocked the old mailbox")
				}
			}
			if _, err := os.Stat(f.launch.directory); !os.IsNotExist(err) {
				t.Fatal("late retirement release recreated or borrowed a native workspace", err)
			}
		})
	}
}

func TestDesktopImportedMTUMissingNativeOwnerCannotStartAuto(t *testing.T) {
	a := &app{}
	owner := &nativeMultihopRuntime{selection: multihopSelection{Native: &nativeMultihopCapture{imported: true}}}
	nativeMultihopOwners.Store(a, owner)
	t.Cleanup(func() { nativeMultihopOwners.Delete(a); routerNodeAutomaticMTUs.Delete(a) })
	if !a.startDesktopImportedAutomaticMTU() {
		t.Fatal("imported runtime silently fell through to another optimizer")
	}
	if _, found := routerNodeAutomaticMTUs.Load(a); found {
		t.Fatal("Auto admitted an absent native owner")
	}
	if _, handled, err := desktopImportedMTURuntime(context.Background(), a); !handled || err == nil {
		t.Fatal("missing imported owner retained MTU dispatch authority", handled, err)
	}
}

func TestDesktopImportedMTUNewRequestCannotBorrowPreviousCommitDuringAdmission(t *testing.T) {
	f := newDesktopImportedMTUFixture(t, true)
	u := importedMTUTestUI(t, f)
	newDesktopImportedMTUPrivatePeer(t, f, "success")
	startDesktopNodeMTUFixtureChildWithHeartbeat(t, f.desktopNodeMTUFixture, nil, true)
	parent, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	first, previous, err := beginMTUViewOperation(u.a, parent, mtuViewRequest{Request: strings.Repeat("a", 32)}, u.identity)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := u.run(first, previous); err != nil || !status.Measured || !f.owner.committed.Load() {
		t.Fatal("fixture did not retain a real prior measured commit", err)
	}
	entered := make(chan struct{})
	var once sync.Once
	before := f.owner.current
	f.owner.current = func(ctx context.Context) error {
		if mobilemtu.SameOperationContext(ctx, ctx) {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return ctx.Err()
		}
		return before(ctx)
	}
	work, operation, err := beginMTUViewOperation(u.a, parent, mtuViewRequest{Request: strings.Repeat("b", 32)}, u.identity)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := u.run(work, operation); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("new request did not enter its own native admission", err)
	case <-parent.Done():
		t.Fatal("new request did not reach its bounded admission")
	}
	response := httptest.NewRecorder()
	if !cancelMTUViewOperation(parent, u.a, response, mtuViewRequest{Request: operation.request}) || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"phase":"canceling"`) || strings.Contains(response.Body.String(), `"committed":true`) {
		operation.cancel()
		<-done
		t.Fatal("previous commit suppressed cancellation of the new admission", response.Body.String())
	}
	if err := <-done; err == nil || f.owner.committed.Load() {
		t.Fatal("cancelled new admission inherited previous accepted winner", err)
	}
}
