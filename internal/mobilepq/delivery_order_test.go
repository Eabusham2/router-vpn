package mobilepq

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// This tests the production publication order, not the cryptography. The native
// Go/C/Rust traffic test separately exercises authenticated packets and rekeys.
type acknowledgementTarget struct {
	installed atomic.Bool
	applies   atomic.Int32
	revoked   atomic.Bool
	apply     func() error
}

func (p *acknowledgementTarget) ApplyPQKey([]byte) error {
	p.applies.Add(1)
	if p.apply != nil {
		if err := p.apply(); err != nil {
			return err
		}
	}
	p.installed.Store(true)
	return nil
}
func (p *acknowledgementTarget) RevokePQKey() error { p.revoked.Store(true); return nil }

type acknowledgementConn struct {
	net.Conn
	write  func([]byte) (int, error)
	writes atomic.Int32
}

func (c *acknowledgementConn) SetWriteDeadline(time.Time) error { return nil }
func (c *acknowledgementConn) Write(b []byte) (int, error)      { c.writes.Add(1); return c.write(b) }
func (*acknowledgementConn) Close() error                       { return nil }

func acknowledgementController(t *testing.T) (*Controller, *acknowledgementTarget, *acknowledgementConn) {
	t.Helper()
	target, conn := &acknowledgementTarget{}, &acknowledgementConn{}
	conn.write = func(b []byte) (int, error) { return len(b), nil }
	c, err := New(context.Background(), &testProtocol{}, target, func(context.Context) (net.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	c.conn = conn
	t.Cleanup(func() { _ = c.Close() })
	return c, target, conn
}

func TestAcknowledgementWaitsForInstalledPQKey(t *testing.T) {
	c, target, conn := acknowledgementController(t)
	conn.write = func(b []byte) (int, error) {
		if !target.installed.Load() {
			t.Error("acknowledgement escaped before the peer installed its key")
		}
		if c.Ready() {
			t.Error("initial readiness published before acknowledgement delivery")
		}
		return len(b), nil
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err := c.deliver(Event{Key: key, Packet: []byte("authenticated protocol reply")}); err != nil {
		t.Fatal(err)
	}
	if !c.Ready() || conn.writes.Load() != 1 || target.applies.Load() != 1 {
		t.Fatal("successful key/packet delivery did not become ready")
	}
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("temporary key was retained")
	}
}

func TestUninstalledOrCancelledKeyCannotSendAcknowledgement(t *testing.T) {
	for _, kind := range []string{"invalid-key", "peer-rejection", "cancel-during-install"} {
		t.Run(kind, func(t *testing.T) {
			c, target, conn := acknowledgementController(t)
			key := bytes.Repeat([]byte{8}, 32)
			switch kind {
			case "invalid-key":
				clear(key)
			case "peer-rejection":
				target.apply = func() error { return errors.New("private native details") }
			case "cancel-during-install":
				target.apply = func() error { c.cancel(); return nil }
			}
			if err := c.deliver(Event{Key: key, Packet: []byte("must not be sent")}); err == nil {
				t.Fatal("failed key adoption succeeded")
			}
			if conn.writes.Load() != 0 || c.Ready() {
				t.Fatal("uninstalled or cancelled key was acknowledged")
			}
			if !bytes.Equal(key, make([]byte, 32)) {
				t.Fatal("failed key was not erased")
			}
		})
	}
}

func TestFailedAcknowledgementDoesNotPublishReadiness(t *testing.T) {
	for _, kind := range []string{"write-error", "short-write", "cancel-after-write"} {
		t.Run(kind, func(t *testing.T) {
			c, target, conn := acknowledgementController(t)
			conn.write = func(b []byte) (int, error) {
				if !target.installed.Load() {
					t.Error("reply reached the transport before key installation")
				}
				switch kind {
				case "write-error":
					return 0, errors.New("socket failure")
				case "short-write":
					return len(b) - 1, nil
				default:
					c.cancel()
					return len(b), nil
				}
			}
			if err := c.deliver(Event{Key: bytes.Repeat([]byte{9}, 32), Packet: []byte("reply")}); err == nil {
				t.Fatal("failed delivery succeeded")
			}
			if c.Ready() {
				t.Fatal("failed reply retained health")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if !target.revoked.Load() {
				t.Fatal("failed acknowledgement did not revoke its installed key")
			}
		})
	}
}
