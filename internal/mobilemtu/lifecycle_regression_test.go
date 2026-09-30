package mobilemtu

import (
	"context"
	"errors"
	"math"
	"net"
	"router-vpn/internal/hopmeasure"
	"strings"
	"sync"
	"testing"
	"time"
)

func awaitMTU(t *testing.T, c *Controller) {
	t.Helper()
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done == nil {
		t.Fatal("no published operation")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("measurement did not drain")
	}
}
func runMTU(t *testing.T, c *Controller, async bool, request string) error {
	t.Helper()
	if !async {
		return c.Run(request, true)
	}
	err := c.Start(request, true)
	if err != nil {
		return err
	}
	awaitMTU(t, c)
	status := readStatus(t, c)
	if !status.Measured {
		return errors.New(status.Phase)
	}
	return nil
}
func TestCompletedMeasurementInvalidatesWithItsOwner(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, action := range []string{"network", "stop"} {
			t.Run(action+map[bool]string{false: "/Run", true: "/Start"}[async], func(t *testing.T) {
				c, _, _ := fixtureController(t)
				if err := runMTU(t, c, async, strings.Repeat("1", 32)); err != nil {
					t.Fatal(err)
				}
				before := readStatus(t, c)
				if action == "network" {
					c.Invalidate()
				} else if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				after := readStatus(t, c)
				if after.Measured || after.Restored || after.EffectiveMTU != 0 || after.Source == "measured-private-system-tun" {
					t.Fatalf("stale result retained: %+v", after)
				}
				if after.Request != before.Request || len(after.Candidates) != len(before.Candidates) {
					t.Fatal("historical samples lost")
				}
				phase := "invalidated"
				if action == "stop" {
					phase = "stopped"
				}
				if after.Phase != phase {
					t.Fatalf("want %s; got %s", phase, after.Phase)
				}
			})
		}
	}
}

type callbackOwner struct {
	Owner
	mu           sync.Mutex
	afterCapture func()
}

func (o *callbackOwner) Capture() (State, error) {
	state, err := o.Owner.Capture()
	o.mu.Lock()
	hook := o.afterCapture
	o.afterCapture = nil
	o.mu.Unlock()
	if hook != nil {
		hook()
	}
	return state, err
}
func (o *callbackOwner) onCapture(hook func()) { o.mu.Lock(); o.afterCapture = hook; o.mu.Unlock() }

type callbackCache struct{ afterSave func() }

func (*callbackCache) Lookup(string) (int, bool) { return 0, false }
func (c *callbackCache) Save(_ string, _ int, valid func() bool) error {
	if !valid() {
		return errors.New("lost path")
	}
	c.afterSave()
	return nil
}
func TestInvalidationDuringFinalReadbackCannotBeAdopted(t *testing.T) {
	for _, async := range []bool{false, true} {
		_, base, _ := fixtureController(t)
		owner := &callbackOwner{Owner: base}
		cache := &callbackCache{}
		c, err := New(owner, encoded(fixtureGraph()), encoded(fixtureProfile()), cache)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		cache.afterSave = func() { owner.onCapture(c.Invalidate) }
		if err := runMTU(t, c, async, strings.Repeat("2", 32)); err == nil {
			t.Fatal("adopted after final-readback invalidation")
		}
		status := readStatus(t, c)
		if status.Measured || status.EffectiveMTU != 0 || status.Phase != "invalidated" {
			t.Fatalf("completion overwrote invalidation: %+v", status)
		}
	}
}

type failingPacketOwner struct {
	Owner
	bad net.Conn
}

func (o *failingPacketOwner) DialThroughTunnel(ctx context.Context, s State, network, address string) (net.Conn, error) {
	if network == "udp" {
		return o.bad, nil
	}
	return o.Owner.DialThroughTunnel(ctx, s, network, address)
}

type deadlineConn struct {
	net.Conn
	writes int
}

func (*deadlineConn) SetDeadline(time.Time) error   { return errors.New("deadline unsupported") }
func (c *deadlineConn) Write(p []byte) (int, error) { c.writes++; return len(p), nil }
func (*deadlineConn) Read([]byte) (int, error)      { return 0, errors.New("would block") }
func (*deadlineConn) Close() error                  { return nil }
func TestPacketProbeRequiresAnEnforcedDeadline(t *testing.T) {
	_, base, _ := fixtureController(t)
	bad := &deadlineConn{}
	owner := &failingPacketOwner{Owner: base, bad: bad}
	c, err := New(owner, encoded(fixtureGraph()), encoded(fixtureProfile()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	state, _ := owner.Capture()
	candidate := Candidate{MTU: state.MTU}
	if err = c.packets(context.Background(), &probeEngine{controller: c, state: state}, &candidate); err == nil || bad.writes != 0 {
		t.Fatal("sent a packet without enforced timeout")
	}
}
func TestChooserDoesNotReturnInvalidOrUnmeasuredCandidate(t *testing.T) {
	row := func(mtu int, rtt float64) Candidate {
		return Candidate{MTU: mtu, Working: true, MedianRTT: rtt, Download: &hopmeasure.Transfer{Mbps: 100}, Upload: &hopmeasure.Transfer{Mbps: 100}}
	}
	good := row(1380, 2)
	cases := []Candidate{row(1280, math.NaN()), row(1280, math.Inf(1)), row(1280, -1), row(1280, 0), row(1279, 1), row(9001, 1)}
	bad := row(1280, 1)
	bad.Download.Mbps = math.Inf(1)
	cases = append(cases, bad)
	bad = row(1280, 1)
	bad.Working = false
	cases = append(cases, bad)
	for _, bad := range cases {
		if got := Choose([]Candidate{bad}, 1380); got.Working {
			t.Fatalf("invalid row selected: %+v", got)
		}
		if got := Choose([]Candidate{bad, good}, 1280); got.MTU != 1380 {
			t.Fatalf("invalid baseline suppressed valid measurement: %+v", got)
		}
	}
}
func TestAsyncInvalidationCannotBeReplacedByWorkerFailure(t *testing.T) {
	for _, action := range []string{"network", "stop"} {
		c, owner, _ := fixtureController(t)
		entered := make(chan struct{})
		owner.blockDownload = entered
		if err := c.Start(strings.Repeat("3", 32), true); err != nil {
			t.Fatal(err)
		}
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("measurement did not start")
		}
		phase := "invalidated"
		if action == "network" {
			c.Invalidate()
		} else {
			phase = "stopped"
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		awaitMTU(t, c)
		status := readStatus(t, c)
		if status.Phase != phase || status.Running || status.Measured || status.EffectiveMTU != 0 {
			t.Fatalf("async completion revived stale status: %+v", status)
		}
	}
}
