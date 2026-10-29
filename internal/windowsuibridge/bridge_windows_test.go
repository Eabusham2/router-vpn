//go:build windows

package windowsuibridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowscontroller"
)

type nativeBridgeHost struct {
	client    *controllertransport.Client
	image     *windowscontroller.Image
	requests  atomic.Uint32
	entered   chan struct{}
	drained   chan struct{}
	enterOnce sync.Once
	drainOnce sync.Once
}

func nativeBridgeContext(t *testing.T, duration time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	t.Cleanup(cancel)
	return ctx
}

func nativeBridgeTestHost(t *testing.T, wrongPin bool) *nativeBridgeHost {
	t.Helper()
	binary := os.Getenv("ROUTERVPN_GUI_BRIDGE_FIXTURE")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("actual native C# bridge executable is required")
	}
	image, err := windowscontroller.PinImage(binary)
	if err != nil {
		t.Fatal("actual native C# fixture image is not pinned", err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	host := &nativeBridgeHost{image: image, entered: make(chan struct{}), drained: make(chan struct{})}
	identity, err := controllertransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	config, err := identity.Config()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:8788")
	if err != nil {
		t.Fatal("exact captured loopback fixture listener", err)
	}
	access, shutdown := strings.Repeat("a", 64), strings.Repeat("b", 32)
	server := &http.Server{TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:8788" || r.Header.Get("Authorization") != "Bearer "+access {
			http.Error(w, "missing exact captured authority", http.StatusForbidden)
			return
		}
		host.requests.Add(1)
		switch r.URL.Path {
		case "/api/status":
			_, _ = io.WriteString(w, "captured")
		case "/api/profile/import":
			body, err := io.ReadAll(io.LimitReader(r.Body, 32770))
			if err != nil || len(body) != 32769 {
				http.Error(w, "wrong exact body", 400)
				return
			}
			for index, value := range body {
				if value != byte((index*29+7)&255) {
					http.Error(w, "changed exact bytes", 400)
					return
				}
			}
			w.WriteHeader(207)
			_, _ = w.Write(body)
		case "/api/hold":
			host.enterOnce.Do(func() { close(host.entered) })
			<-r.Context().Done()
			host.drainOnce.Do(func() { close(host.drained) })
			_, _ = io.WriteString(w, "private late response must never publish")
		case "/api/entered":
			select {
			case <-host.entered:
				_, _ = io.WriteString(w, "entered")
			case <-r.Context().Done():
			}
		case "/api/drained":
			select {
			case <-host.drained:
				_, _ = io.WriteString(w, "drained")
			case <-r.Context().Done():
			}
		default:
			http.Error(w, "unrecognized fixture target", 404)
		}
	})}
	served := make(chan error, 1)
	go func() { served <- server.Serve(tls.NewListener(listener, config)) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	owner, err := windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	pin := identity.Pin()
	if wrongPin {
		other, err := controllertransport.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		pin = other.Pin()
	}
	host.client, err = controllertransport.NewClient(owner, pin, access, shutdown)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := host.client.Close(); err != nil {
			t.Error(err)
		}
	})
	return host
}

type nativeBridgeGUI struct {
	child    *windowscontroller.GUIChild
	pipe     *windowscontroller.Pipe
	report   string
	cancel   context.CancelFunc
	done     chan struct{}
	serveErr error
}

func nativeBridgeLaunch(t *testing.T, host *nativeBridgeHost, mode, address string, invalidParent bool) *nativeBridgeGUI {
	t.Helper()
	gui := &nativeBridgeGUI{report: filepath.Join(t.TempDir(), "result.txt")}
	ctx := nativeBridgeContext(t, 20*time.Second)
	var err error
	gui.child, err = windowscontroller.LaunchGUIChild(ctx, host.image, func(parent uint64) ([]string, error) {
		if invalidParent {
			// Windows reserves low handle bits; adding one to a valid handle
			// would not independently prove a different kernel object.
			parent = 1
		}
		return []string{mode, address, fmt.Sprint(parent), gui.report}, nil
	}, []string{"SystemRoot=" + os.Getenv("SystemRoot"), "TEMP=" + filepath.Dir(gui.report), "TMP=" + filepath.Dir(gui.report)}, filepath.Dir(gui.report))
	t.Cleanup(func() {
		if gui.cancel != nil {
			gui.cancel()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if gui.child != nil {
			if err := gui.child.Close(cleanup); err != nil {
				t.Error("native C# GUI did not retire its exact Job", err)
			}
		}
		if gui.pipe != nil {
			_ = gui.pipe.Close()
		}
		if gui.done != nil {
			select {
			case <-gui.done:
			case <-cleanup.Done():
				t.Error("native GUI channel did not join its owner")
			}
		}
	})
	if err != nil {
		t.Fatal("actual original-user C# GUI did not start", err)
	}
	return gui
}

func nativeBridgeServe(t *testing.T, host *nativeBridgeHost, gui *nativeBridgeGUI, pipe *windowscontroller.Pipe, expected *windowscontroller.GUIChild) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	gui.cancel, gui.pipe, gui.done = cancel, pipe, make(chan struct{})
	go func() { defer close(gui.done); gui.serveErr = Serve(ctx, pipe, expected, host.image, host.client) }()
}

func nativeBridgeStart(t *testing.T, host *nativeBridgeHost, mode string) *nativeBridgeGUI {
	t.Helper()
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipe.Close() })
	gui := nativeBridgeLaunch(t, host, mode, pipe.Name(), false)
	nativeBridgeServe(t, host, gui, pipe, gui.child)
	return gui
}

func nativeBridgeReport(t *testing.T, gui *nativeBridgeGUI, expected string) {
	t.Helper()
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := os.ReadFile(gui.report)
		if err == nil && string(raw) == expected {
			return
		}
		if err == nil && strings.HasPrefix(string(raw), "FAIL ") {
			t.Fatal("actual C# bridge failed:", string(raw))
		}
		select {
		case <-deadline.C:
			t.Fatal("native C# bridge did not report its actual boundary:", expected, string(raw), err)
		case <-ticker.C:
		}
	}
}

func nativeBridgeFinished(t *testing.T, gui *nativeBridgeGUI, expected string) {
	t.Helper()
	code, err := gui.child.Wait(nativeBridgeContext(t, 15*time.Second))
	if err != nil || code != 0 {
		raw, _ := os.ReadFile(gui.report)
		t.Fatal("actual C# bridge process failed", code, err, string(raw))
	}
	nativeBridgeReport(t, gui, expected)
	if gui.done != nil {
		select {
		case <-gui.done:
		case <-time.After(3 * time.Second):
			t.Fatal("exited C# GUI left its forwarding channel alive")
		}
	}
}

func TestWindowsUIBridgeActualCSharpAndPinnedTLS(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	gui := nativeBridgeStart(t, host, "roundtrip")
	nativeBridgeFinished(t, gui, "PASS ROUNDTRIP")
	if host.requests.Load() != 3 {
		t.Fatal("actual C# requests did not traverse the exact pinned TLS controller", host.requests.Load())
	}
}

func TestWindowsUIBridgeActualCancellationAndDrain(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	gui := nativeBridgeStart(t, host, "cancel")
	nativeBridgeFinished(t, gui, "PASS CANCEL")
	select {
	case <-host.drained:
	default:
		t.Fatal("actual C# cancellation did not drain the captured HTTP request")
	}
}

func TestWindowsUIBridgeRetiredGUIRevokesPendingHTTP(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	gui := nativeBridgeStart(t, host, "pending")
	nativeBridgeReport(t, gui, "READY")
	select {
	case <-host.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("C# held request never reached its pinned controller")
	}
	if err := gui.child.Close(nativeBridgeContext(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gui.done:
	case <-time.After(3 * time.Second):
		t.Fatal("retired original-user GUI left its actual channel alive")
	}
	select {
	case <-host.drained:
	case <-time.After(3 * time.Second):
		t.Fatal("GUI death retained its old HTTP request")
	}
	before := host.requests.Load()
	forward := capturedForwarder{child: gui.child, client: host.client}
	if _, err := forward.Request(nativeBridgeContext(t, time.Second), "GET", "/api/status", nil, 256); err == nil || host.requests.Load() != before {
		t.Fatal("retired GUI forwarded a new request using another owner's shared TLS client")
	}
	response, err := host.client.Request(nativeBridgeContext(t, 3*time.Second), "GET", "/api/status", nil, 256)
	if err != nil || string(response.Body) != "captured" {
		t.Fatal("one GUI retirement destroyed the shared controller lifetime", err)
	}
}

func TestWindowsUIBridgeOneGUIClosePreservesOther(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	old := nativeBridgeStart(t, host, "hold")
	current := nativeBridgeStart(t, host, "second-stage")
	nativeBridgeReport(t, old, "READY")
	nativeBridgeReport(t, current, "READY")
	if err := old.child.Close(nativeBridgeContext(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	case <-time.After(3 * time.Second):
		t.Fatal("old GUI channel did not join")
	}
	if err := os.WriteFile(current.report+".continue", []byte("continue"), 0600); err != nil {
		t.Fatal(err)
	}
	nativeBridgeFinished(t, current, "PASS SECOND STAGE")
	if host.requests.Load() != 3 {
		t.Fatal("old GUI cleanup changed another exact request owner", host.requests.Load())
	}
}

func TestWindowsUIBridgeWrongChildNeverForwards(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	expected := nativeBridgeStart(t, host, "hold")
	nativeBridgeReport(t, expected, "READY")
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipe.Close() })
	impostor := nativeBridgeLaunch(t, host, "reject-peer", pipe.Name(), false)
	nativeBridgeServe(t, host, impostor, pipe, expected.child)
	nativeBridgeFinished(t, impostor, "REJECTED PEER")
	if impostor.serveErr == nil || !strings.Contains(impostor.serveErr.Error(), "different retained process") || host.requests.Load() != 1 {
		t.Fatal("same-user unowned C# process acquired another GUI's private bridge", impostor.serveErr)
	}
	if err := expected.child.Alive(); err != nil {
		t.Fatal("rejecting another process retired the captured GUI", err)
	}
}

func TestWindowsUIBridgeWrongParentHandleSendsNoHello(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipe.Close() })
	gui := nativeBridgeLaunch(t, host, "reject-peer", pipe.Name(), true)
	nativeBridgeServe(t, host, gui, pipe, gui.child)
	nativeBridgeFinished(t, gui, "REJECTED PEER")
	if host.requests.Load() != 0 || gui.serveErr == nil {
		t.Fatal("unproved inherited parent admitted private C# traffic", gui.serveErr)
	}
}

func TestWindowsUIBridgeWrongTLSPinSendsNoBearer(t *testing.T) {
	host := nativeBridgeTestHost(t, true)
	gui := nativeBridgeStart(t, host, "reject-request")
	nativeBridgeFinished(t, gui, "REJECTED REQUEST")
	if host.requests.Load() != 0 {
		t.Fatal("C# request sent private authority to an unpinned listener")
	}
}

type foreignServerReport struct {
	Pipe string
	Read string
}

// An independently launched real server process lets the public C# constructor
// prove the kernel's server PID differs from its inherited actual parent. The
// foreign server consumes no private bytes and receives no credentials.
func TestWindowsUIBridgeForeignServerFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 1 || !filepath.IsAbs(arguments[0]) {
		t.Fatal("foreign fixture has no owned report")
	}
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	write := func(value foreignServerReport) {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(arguments[0], raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(foreignServerReport{Pipe: pipe.Name()})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	frame, err := pipe.ReadFrame(ctx)
	if len(frame) != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("foreign pipe received public or private C# bytes", len(frame), err)
	}
	write(foreignServerReport{Pipe: pipe.Name(), Read: "EOF WITHOUT HELLO"})
}

func TestWindowsUIBridgeWrongServerSendsNoHello(t *testing.T) {
	host := nativeBridgeTestHost(t, false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := windowscontroller.PinImage(executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	report := filepath.Join(t.TempDir(), "foreign.json")
	server, err := windowscontroller.LaunchGUIChild(nativeBridgeContext(t, 20*time.Second), image, func(uint64) ([]string, error) {
		return []string{"-test.run=^TestWindowsUIBridgeForeignServerFixture$", "-test.timeout=20s", "--", report}, nil
	}, []string{"SystemRoot=" + os.Getenv("SystemRoot"), "TEMP=" + filepath.Dir(report), "TMP=" + filepath.Dir(report)}, filepath.Dir(report))
	if server != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Close(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	var observed foreignServerReport
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(report)
		if err == nil && json.Unmarshal(raw, &observed) == nil && observed.Pipe != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed.Pipe == "" {
		t.Fatal("actual foreign server did not report its public pipe")
	}
	gui := nativeBridgeLaunch(t, host, "reject-peer", observed.Pipe, false)
	nativeBridgeFinished(t, gui, "REJECTED PEER")
	code, err := server.Wait(nativeBridgeContext(t, 5*time.Second))
	raw, readErr := os.ReadFile(report)
	if err != nil || code != 0 || readErr != nil || json.Unmarshal(raw, &observed) != nil || observed.Read != "EOF WITHOUT HELLO" || host.requests.Load() != 0 {
		t.Fatal("C# disclosed handshake bytes before authenticating its actual parent server", code, err, readErr, string(raw))
	}
}
