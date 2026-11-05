//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/mobilemtu"
)

// This controller models only public operation ownership and joining. It never
// opens a socket or supplies a successful physical network measurement.
type linuxStandardMTUIViewController struct {
	status      mobilemtu.Status
	afterStatus func()
	closes      atomic.Int32
}

func (*linuxStandardMTUIViewController) Requested() bool { return true }
func (*linuxStandardMTUIViewController) RunContext(context.Context, string, bool) error {
	return errors.New("view model cannot measure a network")
}
func (c *linuxStandardMTUIViewController) StatusJSONContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c.status)
	if c.afterStatus != nil {
		c.afterStatus()
	}
	return string(raw), err
}
func (c *linuxStandardMTUIViewController) CloseContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.closes.Add(1)
	return nil
}

func standardMTUIViewFixture(t *testing.T) (*standardMonitorFixture, *linuxStandardServiceMTUUI, *linuxStandardMTUIViewController) {
	t.Helper()
	f := newStandardMonitorFixture(t)
	f.start(t, func(context.Context) error { return nil }, nil)
	f.finish() // A successful activation survives the completed Connect request.
	token, err := linuxStandardProfileDigest(f.a.profiles.Profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	controller := &linuxStandardMTUIViewController{}
	u := &linuxStandardServiceMTUUI{launch: f.o, controller: controller, identity: mtuViewIdentity{Session: f.o.request.Session, Profile: f.o.request.ProfileID, Native: true}, activation: f.m, lifetime: f.m.ctx, profileToken: token}
	linuxStandardServiceMTUUIs.Store(f.o, u)
	t.Cleanup(func() { linuxStandardServiceMTUUIs.Delete(f.o); mtuViewSlots.Delete(f.a) })
	return f, u, controller
}

func TestLinuxStandardMTUUIPublicProgressAndCancelDuringNativeMutation(t *testing.T) {
	for _, test := range []string{"original", "foreign-request", "changed-profile", "replacement-activation", "replacement-during-status"} {
		t.Run(test, func(t *testing.T) {
			f, u, c := standardMTUIViewFixture(t)
			request := strings.Repeat("a", 32)
			ctx, op, err := beginMTUViewOperation(f.a, context.Background(), mtuViewRequest{Request: request}, u.identity)
			if err != nil {
				t.Fatal(err)
			}
			defer op.cancel()
			u.running, u.active = true, op
			c.status = mobilemtu.Status{Request: request, Phase: "throughput", Running: true, EffectiveMTU: 1400, Measured: true, Complete: true}
			if test == "foreign-request" {
				request = strings.Repeat("b", 32)
			}
			if test == "changed-profile" {
				f.a.mu.Lock()
				f.a.profiles.Profiles[0].Name = "replacement"
				f.a.mu.Unlock()
			}
			if test == "replacement-activation" {
				linuxStandardServiceMonitors.Store(f.o, &linuxStandardServiceMonitor{})
				defer linuxStandardServiceMonitors.Store(f.o, f.m)
			}
			if test == "replacement-during-status" {
				c.afterStatus = func() { f.a.mu.Lock(); f.a.cmd = nil; f.a.mu.Unlock() }
			}
			// Native candidate acceptance owns this lock; GET and cancellation must not
			// wait for it, and GET must not advertise the candidate as verified readback.
			f.o.mu.Lock()
			defer f.o.mu.Unlock()
			deadline, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			response := httptest.NewRecorder()
			f.a.desktopMTUStatus(response, httptest.NewRequest(http.MethodGet, "/api/mtu/status?request_id="+request+"&session_id="+u.identity.Session, nil).WithContext(deadline))
			if test != "original" {
				if response.Code != http.StatusConflict {
					t.Fatalf("stale progress accepted: %d %s", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("progress blocked by mutation: %d %s", response.Code, response.Body.String())
			}
			var body struct {
				Status  mobilemtu.Status `json:"status"`
				Session string           `json:"session_id"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Session != u.identity.Session || !body.Status.Running || body.Status.Complete || body.Status.Measured || body.Status.EffectiveMTU != 0 || body.Status.Source != "unmeasured" {
				t.Fatalf("candidate advertised as verified: %+v", body)
			}
			canceled := httptest.NewRecorder()
			f.a.cancelDesktopMTURoute(canceled, httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+request+`","session_id":"`+u.identity.Session+`"}`)))
			if canceled.Code != http.StatusOK || ctx.Err() == nil {
				t.Fatalf("original cancellation did not signal worker: %d %s", canceled.Code, canceled.Body.String())
			}
			if c.closes.Load() != 0 || f.m.ctx.Err() != nil {
				t.Fatal("cancellation closed the healthy connection")
			}
		})
	}
}

func TestLinuxStandardMTUUIStopJoinsOriginalAutomaticAdmission(t *testing.T) {
	for _, test := range []string{"join", "deadline", "replacement-owner"} {
		t.Run(test, func(t *testing.T) {
			f, u, c := standardMTUIViewFixture(t)
			automatic, cancel := context.WithCancel(context.Background())
			defer cancel()
			u.autoCancel = cancel
			u.autoDone = make(chan struct{})
			worker, stopWorker := context.WithCancel(context.Background())
			defer stopWorker()
			u.cancel = stopWorker
			u.done = make(chan struct{})
			if test == "replacement-owner" {
				linuxStandardServiceOwners.Store(f.a, &linuxStandardServiceLaunch{app: f.a})
				defer linuxStandardServiceOwners.Store(f.a, f.o)
			}
			deadline, finish := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer finish()
			result := make(chan error, 1)
			go func() { result <- stopLinuxStandardServiceMTUUI(deadline, f.o) }()
			if test == "replacement-owner" {
				if err := <-result; err == nil {
					t.Fatal("replacement owner allowed Stop")
				}
				if automatic.Err() != nil || worker.Err() != nil {
					t.Fatal("stale Stop canceled original work")
				}
				return
			}
			select {
			case <-automatic.Done():
			case <-deadline.Done():
				t.Fatal("Stop did not cancel automatic admission")
			}
			select {
			case <-worker.Done():
			case <-deadline.Done():
				t.Fatal("Stop did not cancel original measurement")
			}
			if test == "deadline" {
				if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost caller deadline: %v", err)
				}
				if c.closes.Load() != 0 {
					t.Fatal("closed controller before original worker joined")
				}
				if _, ok := linuxStandardServiceMTUUIs.Load(f.o); !ok {
					t.Fatal("lost retained pending cleanup")
				}
				return
			}
			select {
			case err := <-result:
				t.Fatalf("Stop escaped before admission joined: %v", err)
			default:
			}
			close(u.autoDone)
			select {
			case err := <-result:
				t.Fatalf("Stop escaped before measurement joined: %v", err)
			default:
			}
			close(u.done)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if c.closes.Load() != 1 {
				t.Fatal("joined controller was not closed exactly once")
			}
			if _, ok := linuxStandardServiceMTUUIs.Load(f.o); ok {
				t.Fatal("joined original UI was retained")
			}
		})
	}
}

func TestLinuxStandardMTUUILateResumeCannotRecreateStoppedOwner(t *testing.T) {
	for _, test := range []string{"stopped", "replacement-ui"} {
		t.Run(test, func(t *testing.T) {
			f, u, controller := standardMTUIViewFixture(t)
			// The same original owner still records a legitimate deferred resume.
			u.autoWaiting = true
			u.resumeAutomatic()
			if !u.resume {
				t.Fatal("live original UI lost its requested automatic resume")
			}
			u.autoWaiting, u.resume = false, false
			// Capture the original completion callback, then pause it after its
			// old worker's join boundary and before automatic admission resumes.
			paused, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				close(paused)
				<-release
				u.resumeAutomatic()
				close(done)
			}()
			<-paused
			var replacement *linuxStandardServiceMTUUI
			if test == "stopped" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := stopLinuxStandardServiceMTUUI(ctx, f.o); err != nil {
					close(release)
					t.Fatal(err)
				}
				if controller.closes.Load() != 1 {
					t.Fatal("original controller was not joined and closed")
				}
			} else {
				// Even an unstopped delayed predecessor cannot borrow the next
				// registry entry's automatic admission or controller.
				replacement = &linuxStandardServiceMTUUI{launch: f.o, lifetime: f.m.ctx}
				linuxStandardServiceMTUUIs.Store(f.o, replacement)
			}
			// A retired callback must reject from its original UI gate. Looking
			// up a fresh native owner here would queue behind this held mutex.
			f.o.mu.Lock()
			defer f.o.mu.Unlock()
			close(release)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("late resume attempted fresh native owner capture")
			}
			if u.autoWaiting || u.autoDone != nil || u.resume {
				t.Fatal("late callback admitted automatic work on retired UI")
			}
			actual, found := linuxStandardServiceMTUUIs.Load(f.o)
			if test == "stopped" && found || test == "replacement-ui" && (!found || actual != replacement || replacement.autoWaiting || replacement.autoDone != nil) {
				t.Fatal("late callback recreated or modified another UI owner")
			}
		})
	}
}

type standardMTUCloseProbe struct {
	net.Conn
	calls            atomic.Int32
	entered, release chan struct{}
}

func (c *standardMTUCloseProbe) Close() error {
	c.calls.Add(1)
	close(c.entered)
	<-c.release
	return c.Conn.Close()
}

func TestLinuxStandardMTUSocketCloseDoesNotWaitForLaunchGate(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	native := &standardMTUCloseProbe{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	owner := &linuxStandardServiceMTUOwner{launch: &linuxStandardServiceLaunch{}}
	owner.sockets.Add(1)
	connection := &linuxStandardMTUConn{Conn: native, owner: owner}
	owner.launch.mu.Lock()
	defer owner.launch.mu.Unlock()
	done := make(chan error, 2)
	go func() { done <- connection.Close() }()
	<-native.entered
	go func() { done <- connection.Close() }()
	if owner.sockets.Load() != 1 {
		t.Fatal("socket left mutation admission before native close joined")
	}
	close(native.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("socket retirement waited behind launch gate")
		}
	}
	if native.calls.Load() != 1 || owner.sockets.Load() != 0 {
		t.Fatal("socket native close/accounting did not join exactly once")
	}
}
