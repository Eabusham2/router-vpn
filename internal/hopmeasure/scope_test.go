package hopmeasure

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type scopedMeasurementFixture struct {
	privateLateDialEngine
	begin func() (func(), error)
}

func (f *scopedMeasurementFixture) BeginMeasurement() (func(), error) { return f.begin() }

func TestNativeMeasurementScopeRemainsOwnedUntilCanceledDialAndCloseDrain(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	closing, finishClose := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	var claims, releases atomic.Int32
	engine := &scopedMeasurementFixture{begin: func() (func(), error) { claims.Add(1); return func() { releases.Add(1) }, nil }}
	engine.dial = func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-resume
		return &publicGateConn{Conn: left, closeStarted: closing, closeRelease: finishClose}, nil
	}
	service, err := New(engine, []Hop{{ID: "entry", Role: "entry", Tag: "external-entry", API: "http://10.77.0.1:8787", Token: "owned-token", Proof: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("f", 32)
	if err = service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	<-entered
	service.Cancel(id)
	if claims.Load() != 1 || releases.Load() != 0 {
		t.Fatal("cancellation prematurely released the native scope")
	}
	if err = service.Start(strings.Repeat("e", 32), 65536); err == nil || claims.Load() != 1 {
		t.Fatal("second request acquired the same undrained owner")
	}
	close(resume)
	<-closing
	if releases.Load() != 0 {
		t.Fatal("scope released before real close")
	}
	close(finishClose)
	if err = service.Drain(id); err != nil {
		t.Fatal(err)
	}
	if releases.Load() != 1 {
		t.Fatal("actual drain did not release exactly one scope")
	}
	if err = service.Close(); err != nil || releases.Load() != 1 {
		t.Fatal("close released a foreign or repeated scope")
	}
}

func TestNativeMeasurementScopeFailureCannotOpenOrPublishWork(t *testing.T) {
	for _, mode := range []string{"busy", "nil-release", "partially-acquired"} {
		t.Run(mode, func(t *testing.T) {
			var dials, releases atomic.Int32
			engine := &scopedMeasurementFixture{begin: func() (func(), error) {
				if mode == "nil-release" {
					return nil, nil
				}
				if mode == "partially-acquired" {
					return func() { releases.Add(1) }, errors.New("retired during capture")
				}
				return nil, errors.New("MTU owns the interface")
			}}
			engine.dial = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected")
			}
			service, err := New(engine, []Hop{{ID: "exit", Role: "exit", Tag: "custom-exit", Kind: "public-path"}})
			if err != nil {
				t.Fatal(err)
			}
			if err = service.Start(strings.Repeat("a", 32), 65536); err == nil {
				t.Fatal("unowned native activity started")
			}
			if dials.Load() != 0 || service.state.Request != "" {
				t.Fatal("rejected scope opened or published measurement")
			}
			if (releases.Load() == 1) != (mode == "partially-acquired") {
				t.Fatal("partial native scope was not cleaned exactly")
			}
			if err = service.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeMeasurementScopeReleasesOnOrdinaryFailure(t *testing.T) {
	var releases atomic.Int32
	engine := &scopedMeasurementFixture{begin: func() (func(), error) { return func() { releases.Add(1) }, nil }}
	engine.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("isolated failure") }
	service, err := New(engine, []Hop{{ID: "exit", Role: "exit", Tag: "custom-exit", Kind: "public-path"}})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	if err = service.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- service.Drain(id) }()
	select {
	case err = <-joined:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed request did not drain")
	}
	if releases.Load() != 1 {
		t.Fatal("failed request retained its native activity scope")
	}
}
