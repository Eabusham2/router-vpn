package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

const testControllerOwner = "0123456789abcdef0123456789abcdef"

func waitControllerShutdown(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("checked controller shutdown did not drain")
	}
}

func controllerShutdownBody(c *controllerShutdown) string {
	data, _ := json.Marshal(controllerShutdownRequest{Schema: 1, ProcessID: c.processID, OwnerToken: c.ownerToken})
	return string(data)
}

func TestControllerShutdownCancelsBeforeWaitingAndClosesEveryAdmission(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	ctx, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(finish) }
	defer release()
	startup, cancelStartup := context.WithCancel(context.Background())
	startupPolicyCancels.Store(a, context.CancelFunc(cancelStartup))
	defer cancelPendingStartupPolicy(a)
	c := newControllerShutdown(a, testControllerOwner)
	c.begin()
	if ctx.Err() == nil || startup.Err() == nil || !a.controllerClosing() || !mtuSuspended(a) {
		t.Fatal("shutdown waited for a connection transaction before canceling its owners")
	}
	if err := a.checkConnectionOperation(); !errors.Is(err, errConnectionOperationCancelled) {
		t.Fatal("late runtime adoption was not canceled", err)
	}
	select {
	case <-c.done:
		t.Fatal("shutdown acknowledged before the existing transaction released ownership")
	default:
	}
	release()
	waitControllerShutdown(t, c.done)
	if _, _, err := a.beginConnectionOperation(); !errors.Is(err, errControllerClosing) {
		t.Fatal("new connection accepted after terminal cleanup", err)
	}
	if _, err := a.beginNodeBoundOperation(); !errors.Is(err, errControllerClosing) {
		t.Fatal("new node-bound operation accepted after terminal cleanup", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/profile/save", nil)
	for _, request := range []*http.Request{request, withInternalMutationContext(request)} {
		if _, err := a.beginMutationOperation(request); !errors.Is(err, errControllerClosing) {
			t.Fatal("new settings mutation accepted after terminal cleanup", err)
		}
	}
	if _, _, finish, err := a.beginSpeedLabTemporaryOperation(); err == nil || finish != nil {
		t.Fatal("temporary Speed Lab acquired a replacement shutdown owner")
	}
	if a.state.Mode != "off" || a.state.Phase != "off" || a.connectionContext != nil || a.cmd != nil {
		t.Fatal("terminal drain left an active connection", a.state)
	}
	called := false
	handler := c.handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "/api/connect", nil))
		if w.Code != http.StatusServiceUnavailable || called {
			t.Fatal("queued HTTP work crossed the terminal admission barrier")
		}
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if !called {
		t.Fatal("terminal cleanup hid its read-only status")
	}
}

func TestControllerShutdownCancelsSpeedLabIntentWithoutRestoringConnection(t *testing.T) {
	a, snapshot, finish := speedLabRestorationFixture(t, false)
	var once sync.Once
	release := func() { once.Do(finish) }
	defer release()
	c := newControllerShutdown(a, testControllerOwner)
	c.begin()
	if snapshot.Owner.intent.Err() == nil || snapshot.Owner.test.Err() == nil {
		t.Fatal("controller exit canceled only the HTTP probe instead of its restore intent")
	}
	select {
	case <-c.done:
		t.Fatal("controller forgot the live Speed Lab operation")
	default:
	}
	release()
	waitControllerShutdown(t, c.done)
	if snapshot.Owner.restored || a.cmd != nil || a.state.Connected {
		t.Fatal("controller shutdown restored a VPN after its owner exited")
	}
}

func TestControllerShutdownRejectsForeignAndAmbiguousOwnersWithoutMutation(t *testing.T) {
	valid := controllerShutdownBody(newControllerShutdown(&app{}, testControllerOwner))
	cases := map[string]string{
		"duplicate":  strings.TrimSuffix(valid, "}") + `,"schema":1}`,
		"unknown":    strings.TrimSuffix(valid, "}") + `,"closed":true}`,
		"case-alias": strings.Replace(valid, `"schema"`, `"Schema"`, 1),
		"null":       `null`,
		"array":      `[]`,
		"trailing":   valid + `{}`,
		"bounded":    strings.Repeat(" ", 1024) + valid,
		"pid":        strings.Replace(valid, fmt.Sprint(os.Getpid()), fmt.Sprint(os.Getpid()+1), 1),
		"pid-null":   strings.Replace(valid, fmt.Sprint(os.Getpid()), `null`, 1),
		"pid-string": strings.Replace(valid, fmt.Sprint(os.Getpid()), fmt.Sprintf(`"%d"`, os.Getpid()), 1),
		"token":      strings.Replace(valid, testControllerOwner, strings.Repeat("a", 32), 1),
		"uppercase":  strings.Replace(valid, testControllerOwner, strings.ToUpper(testControllerOwner), 1),
		"schema":     strings.Replace(valid, `"schema":1`, `"schema":2`, 1),
		"missing":    strings.Replace(valid, `"schema":1,`, "", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			a := &app{state: state{Mode: "off", Phase: "off"}}
			c := newControllerShutdown(a, testControllerOwner)
			w := httptest.NewRecorder()
			c.shutdownHTTP(w, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(body)))
			if w.Code == http.StatusOK || a.controllerClosing() || strings.Contains(w.Body.String(), testControllerOwner) {
				t.Fatal("foreign, malformed, or ambiguous shutdown changed ownership", w.Code, w.Body.String())
			}
		})
	}
	for _, token := range []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("g", 32)} {
		a := &app{}
		c := newControllerShutdown(a, token)
		w := httptest.NewRecorder()
		c.shutdownHTTP(w, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(valid)))
		if w.Code != http.StatusForbidden || a.controllerClosing() {
			t.Fatal("absent or invalid launch capability enabled HTTP shutdown")
		}
	}
	c := newControllerShutdown(&app{}, testControllerOwner)
	w := httptest.NewRecorder()
	c.shutdownHTTP(w, httptest.NewRequest(http.MethodGet, controllerShutdownPath, strings.NewReader(valid)))
	if w.Code != http.StatusMethodNotAllowed || c.a.controllerClosing() {
		t.Fatal("GET initiated shutdown")
	}
}

type controllerFailedReceiptWriter struct{ header http.Header }

func (w *controllerFailedReceiptWriter) Header() http.Header { return w.header }
func (*controllerFailedReceiptWriter) WriteHeader(int)       {}
func (*controllerFailedReceiptWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestControllerShutdownRetainsTerminalReceiptAfterTimeoutAndWriteFailure(t *testing.T) {
	privateOperationRoot(t)
	a := &app{state: state{Mode: "off", Phase: "off"}}
	_, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(finish) }
	defer release()
	c := newControllerShutdown(a, testControllerOwner)
	c.responseWait = 15 * time.Millisecond
	body := controllerShutdownBody(c)
	w := httptest.NewRecorder()
	c.shutdownHTTP(w, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(body)))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), `"closed"`) {
		t.Fatal("pending transaction received a successful close receipt", w.Code, w.Body.String())
	}
	release()
	waitControllerShutdown(t, c.done)
	select {
	case <-c.exit:
		t.Fatal("controller exited between a pending response and the owner's retry")
	default:
	}
	c.shutdownHTTP(&controllerFailedReceiptWriter{header: make(http.Header)}, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(body)))
	select {
	case <-c.exit:
		t.Fatal("failed receipt write retired controller ownership")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.shutdownHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(body)).WithContext(ctx))
	select {
	case <-c.exit:
		t.Fatal("abandoned request consumed the completed receipt")
	default:
	}
	w = httptest.NewRecorder()
	c.shutdownHTTP(w, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(body)))
	var receipt controllerShutdownReceipt
	if w.Code != http.StatusOK || decodeRelayControlJSON(w.Body.Bytes(), &receipt) != nil ||
		receipt.Schema != 1 || receipt.ProcessID != os.Getpid() || receipt.OwnerToken != c.ownerToken || !receipt.Closed || !w.Flushed {
		t.Fatal("exact terminal owner did not receive a flushed close receipt", w.Code, w.Body.String())
	}
	select {
	case <-c.exit:
	default:
		t.Fatal("delivered close receipt did not request graceful HTTP exit")
	}
}

func TestControllerShutdownActualHTTPFlushesReceiptBeforeServerExit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &app{state: state{Mode: "off", Phase: "off"}}
	c := newControllerShutdown(a, testControllerOwner)
	finished := make(chan error, 1)
	go func() { finished <- serveClientHTTP(c, listener, http.NotFoundHandler(), make(chan os.Signal)) }()
	t.Cleanup(func() {
		c.begin()
		c.requestExit()
		_ = listener.Close()
	})
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	response, err := client.Post("http://"+listener.Addr().String()+controllerShutdownPath, "application/json", strings.NewReader(controllerShutdownBody(c)))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	var receipt controllerShutdownReceipt
	if err != nil || response.StatusCode != http.StatusOK || decodeRelayControlJSON(data, &receipt) != nil || !receipt.Closed || receipt.OwnerToken != c.ownerToken || receipt.ProcessID != os.Getpid() {
		t.Fatal("server exit truncated or substituted the terminal receipt", string(data), err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not exit after response delivery")
	}
}

func TestControllerShutdownCancelsActualForwardingRequestBeforeJoiningOperation(t *testing.T) {
	arrived, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Consume the command as the Router API does. HTTP/1 can only begin its
		// independent connection-close watcher after the request body is drained.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 8192))
		_ = r.Body.Close()
		close(arrived)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	a := &app{state: state{Mode: "off", Phase: "off"}, profiles: common.RouterProfileStore{
		SelectedID: "home", Profiles: []common.RouterProfile{{ID: "home", Endpoint: "203.0.113.7", RouterAPI: upstream.URL, APIToken: "fixture-owned-token"}},
	}}
	c := newControllerShutdown(a, testControllerOwner)
	h := http.NewServeMux()
	h.HandleFunc("/api/forward", a.forward)
	server := httptest.NewServer(c.handler(h))
	defer func() {
		close(release) // Drain the broken cancellation case before joining HTTP.
		server.Close()
		upstream.Close()
	}()
	responseDone := make(chan error, 1)
	go func() {
		response, err := server.Client().Post(server.URL+"/api/forward", "application/json", strings.NewReader(`{}`))
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		responseDone <- err
	}()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("owned forwarding fixture did not reach its captured upstream")
	}
	c.begin()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("controller shutdown left the active forwarding socket detached from cancellation")
	}
	waitControllerShutdown(t, c.done)
	select {
	case err := <-responseDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forwarding operation retained its transaction after upstream cancellation")
	}
}

func TestControllerShutdownBindFailureCannotReleaseAnotherControllerGuard(t *testing.T) {
	root := privateOperationRoot(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	a := &app{state: state{Mode: "off", Phase: "off"}}
	// No firewall helper belongs to this new process. Trying the ordinary
	// off-state Disconnect release would fail here instead of retiring cleanly.
	a.cfg.ScriptsDir = root
	result := make(chan error, 1)
	go func() { result <- runClientHTTP(a, listener.Addr().String(), http.NotFoundHandler()) }()
	select {
	case err := <-result:
		var addressError *net.OpError
		if !errors.As(err, &addressError) || !a.controllerClosing() || a.state.Mode != "off" {
			t.Fatal("bind failure lost its original error or changed unowned state", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unowned controller attempted firewall cleanup after failing to bind")
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("failed controller retired another listener", err)
	}
	_ = connection.Close()
}

func controllerNativeShutdownFixture(t *testing.T) (*app, *desktopNodeLaunch, string) {
	t.Helper()
	a, launch := desktopExternalRunningFixture(t, "waiting")
	a.state = state{Mode: "external-direct", RuntimeMode: "external-direct", Phase: "checking"}
	if err := os.MkdirAll(a.cfg.ScriptsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.cfg.ScriptsDir, "kill-switch-platform.py"), []byte("# Fixture: no host firewall is installed.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	clientDir := filepath.Join(launch.root, "client")
	if err := os.MkdirAll(clientDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "windows-kill-switch.ps1"), []byte("exit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	permit := filepath.Join(t.TempDir(), "permit-owned-stop")
	launch.stop = []string{os.Args[0], "-test.run=^TestControllerNativeStopFixture$"}
	launch.command.Env = append(launch.command.Env, "ROUTERVPN_CONTROLLER_STOP_PERMIT="+permit)
	return a, launch, permit
}

func TestControllerNativeStopFixture(t *testing.T) {
	permit := os.Getenv("ROUTERVPN_CONTROLLER_STOP_PERMIT")
	if permit == "" {
		return
	}
	if _, err := os.Stat(permit); err != nil {
		os.Exit(47)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("ROUTERVPN_DESKTOP_EXTERNAL_DIRECTORY"), "stopped.json"))
	var receipt desktopExternalStop
	if err != nil || decodeRelayControlJSON(data, &receipt) != nil || !receipt.Closed || receipt.Schema != 1 {
		os.Exit(48)
	}
}

func TestControllerShutdownKeepsFailedNativeCleanupOwnerUntilCheckedRetry(t *testing.T) {
	a, launch, permit := controllerNativeShutdownFixture(t)
	c := newControllerShutdown(a, testControllerOwner)
	c.responseWait, c.retryDelay = 20*time.Millisecond, 20*time.Millisecond
	c.begin()
	t.Cleanup(func() {
		_ = os.WriteFile(permit, []byte("ready\n"), 0600)
		waitControllerShutdown(t, c.done)
	})
	deadline := time.Now().Add(6 * time.Second)
	for {
		a.mu.Lock()
		failed := a.state.Phase == "failed"
		a.mu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native failed cleanup did not retain its retry identity")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if owner, present := desktopNodeOwners.Load(a); !present || owner != launch {
		t.Fatal("failed cleanup discarded the captured native owner")
	}
	if _, err := os.Stat(launch.directory); err != nil {
		t.Fatal("failed native cleanup deleted its private workspace", err)
	}
	w := httptest.NewRecorder()
	c.shutdownHTTP(w, httptest.NewRequest(http.MethodPost, controllerShutdownPath, strings.NewReader(controllerShutdownBody(c))))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("failed native cleanup was acknowledged", w.Code)
	}
	if err := os.WriteFile(permit, []byte("ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitControllerShutdown(t, c.done)
	if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("checked retry failed to retire the exact workspace", err)
	}
	if _, exists := desktopNodeOwners.Load(a); exists || a.cmd != nil || a.state.Mode != "off" || a.state.Phase != "off" {
		t.Fatal("native shutdown did not commit its checked retirement")
	}
}

// These are actual separate controller and native helper processes. The parent
// sends OS signals only to its own exec.Cmd.Process. A private result proves the
// captured native acknowledgement and workspace retirement preceded process exit.
func TestControllerShutdownSignalProcessFixture(t *testing.T) {
	address := os.Getenv("ROUTERVPN_CONTROLLER_SIGNAL_ADDRESS")
	if address == "" {
		return
	}
	a, launch, permit := controllerNativeShutdownFixture(t)
	if err := os.WriteFile(permit, []byte("ready\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := http.NewServeMux()
	h.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, os.Getenv("ROUTERVPN_CONTROLLER_SIGNAL_NONCE"))
	})
	if err := runClientHTTP(a, address, h); err != nil {
		t.Fatal(err)
	}
	_, workspaceErr := os.Lstat(launch.directory)
	launch.external.mu.Lock()
	acknowledged := launch.external.stopAcknowledged
	launch.external.mu.Unlock()
	_, stillOwned := desktopNodeOwners.Load(a)
	data, _ := json.Marshal(map[string]any{"acknowledged": acknowledged, "retired": errors.Is(workspaceErr, os.ErrNotExist), "still_owned": stillOwned, "mode": a.state.Mode})
	if err := os.WriteFile(os.Getenv("ROUTERVPN_CONTROLLER_SIGNAL_RESULT"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestControllerShutdownRealSignalsDrainNativeChildAndWorkspace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows launchers use the checked HTTP shutdown capability")
	}
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reserved.Addr().String()
			_ = reserved.Close()
			result := filepath.Join(t.TempDir(), "closed.json")
			nonce := filepath.Base(filepath.Dir(result)) + signal.String()
			command := exec.Command(os.Args[0], "-test.run=^TestControllerShutdownSignalProcessFixture$")
			command.Env = append(os.Environ(), "ROUTERVPN_CONTROLLER_SIGNAL_ADDRESS="+address, "ROUTERVPN_CONTROLLER_SIGNAL_NONCE="+nonce, "ROUTERVPN_CONTROLLER_SIGNAL_RESULT="+result)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := make(chan error, 1)
			go func() { waited <- command.Wait() }()
			t.Cleanup(func() { _ = command.Process.Kill() })
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 300 * time.Millisecond}
			deadline := time.Now().Add(6 * time.Second)
			for {
				response, requestErr := client.Get("http://" + address + "/ready")
				if requestErr == nil {
					body, _ := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if string(body) == nonce {
						break
					}
				}
				select {
				case err := <-waited:
					t.Fatal("controller fixture exited before the signal", err, output.String())
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("controller fixture did not start")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err := command.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-waited:
				if err != nil {
					t.Fatal("controller exited before checked native cleanup", err, output.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("signal cleanup did not complete")
			}
			data, err := os.ReadFile(result)
			var receipt struct {
				Acknowledged bool   `json:"acknowledged"`
				Retired      bool   `json:"retired"`
				StillOwned   bool   `json:"still_owned"`
				Mode         string `json:"mode"`
			}
			if err != nil || json.Unmarshal(data, &receipt) != nil || !receipt.Acknowledged || !receipt.Retired || receipt.StillOwned || receipt.Mode != "off" {
				t.Fatal("OS signal abandoned its native owner", string(data), err)
			}
		})
	}
}
