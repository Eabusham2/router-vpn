//go:build go1.25

package mobilepq

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// These tests exercise the real controller and net.Pipe I/O under Go's virtual
// clock. They verify transport ownership, not cryptography; the native Rust
// exchange and rekey gates exercise the actual pinned protocol separately.
type admissionProtocol struct{ testProtocol }

func (p *admissionProtocol) Step(kind uint32, packet []byte) (Event, error) {
	event, err := p.testProtocol.Step(kind, packet)
	if kind == 0 {
		event.Wait = time.Second
	} else if len(event.Key) != 0 {
		event.Packet = append([]byte("ack:"), packet...)
	}
	return event, err
}

func admissionRoundTrip(t *testing.T, wire net.Conn, packet string) {
	t.Helper()
	if err := wire.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := wire.Write([]byte(packet)); err != nil || n != len(packet) {
		t.Fatalf("controller input: wrote %d bytes, error %v", n, err)
	}
	want := []byte("ack:" + packet)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(wire, got); err != nil {
		t.Fatalf("controller acknowledgement: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("controller acknowledgement changed the captured packet")
	}
}

func TestDialAdmissionRetainsTransportForPostAdmissionIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, wire := net.Pipe()
		defer wire.Close()
		protocol, target := &admissionProtocol{}, &testTarget{}
		captured := make(chan context.Context, 1)
		released := make(chan struct{})
		controller, err := New(context.Background(), protocol, target, func(ctx context.Context) (net.Conn, error) {
			context.AfterFunc(ctx, func() {
				local.Close()
				close(released)
			})
			captured <- ctx
			return local, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer controller.Close()
		started := begin(controller)
		owner := <-captured
		admissionRoundTrip(t, wire, "first")
		await(t, started, false)
		// Advancing past the actual five-second admission budget must leave an
		// already admitted native transport available for later rekey traffic.
		time.Sleep(5*time.Second + time.Nanosecond)
		synctest.Wait()
		if owner.Err() != nil || !controller.Ready() {
			t.Fatal("successful admission revoked its live native transport")
		}
		admissionRoundTrip(t, wire, "second")
		synctest.Wait()
		target.mu.Lock()
		keys := append([][]byte(nil), target.keys...)
		target.mu.Unlock()
		if len(keys) != 2 || bytes.Equal(keys[0], keys[1]) {
			t.Fatal("post-admission I/O did not install a distinct captured rekey")
		}
		if err := controller.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if owner.Err() != context.Canceled || controller.Ready() {
			t.Fatal("controller shutdown retained the admitted owner")
		}
		select {
		case <-released:
		default:
			t.Fatal("controller shutdown did not close the context-owned transport")
		}
		if protocol.closes != 1 || target.revokes != 1 {
			t.Fatal("controller did not join and revoke exactly once")
		}
	})
}

func TestDialAdmissionRejectsFiveSecondLateSuccessfulSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, wire := net.Pipe()
		defer wire.Close()
		protocol, target := &testProtocol{}, &testTarget{}
		captured := make(chan context.Context, 1)
		returned := make(chan struct{})
		controller, err := New(context.Background(), protocol, target, func(ctx context.Context) (net.Conn, error) {
			captured <- ctx
			<-ctx.Done()
			// A cancellation-aware native dial can still hand back its newly
			// allocated socket while unwinding. It must never be adopted.
			close(returned)
			return local, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer controller.Close()
		started := begin(controller)
		owner := <-captured
		time.Sleep(5*time.Second - time.Nanosecond)
		synctest.Wait()
		if owner.Err() != nil {
			t.Fatal("dial admission ended before the five-second bound")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if owner.Err() != context.Canceled {
			t.Fatal("dial admission exceeded the five-second bound")
		}
		select {
		case <-returned:
		default:
			t.Fatal("admission cancellation did not release the native dial")
		}
		await(t, started, true)
		if controller.Ready() || protocol.calls != 0 || len(target.keys) != 0 {
			t.Fatal("late socket reached protocol processing or key adoption")
		}
		if _, err := wire.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("late successful socket survived cleanup: %v", err)
		}
	})
}

func TestDialAdmissionMonotonicReturnBoundary(t *testing.T) {
	for _, boundary := range []struct {
		name     string
		delay    time.Duration
		admitted bool
	}{
		{"before", 5*time.Second - time.Nanosecond, true},
		{"exact", 5 * time.Second, false},
		{"after", 5*time.Second + time.Nanosecond, false},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, wire := net.Pipe()
				defer wire.Close()
				protocol, target := &admissionProtocol{}, &testTarget{}
				entered := make(chan struct{})
				controller, err := New(context.Background(), protocol, target, func(context.Context) (net.Conn, error) {
					close(entered)
					// A native call may return without observing cancellation. The
					// elapsed admission bound still applies to this successful return.
					time.Sleep(boundary.delay)
					return local, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer controller.Close()
				started := begin(controller)
				<-entered
				time.Sleep(boundary.delay)
				synctest.Wait()
				if boundary.admitted {
					admissionRoundTrip(t, wire, "bounded")
					await(t, started, false)
					return
				}
				select {
				case err := <-started:
					if err == nil {
						t.Fatal("elapsed native dial was admitted")
					}
				default:
					t.Fatal("elapsed native dial entered the protocol loop")
				}
				if controller.Ready() || protocol.calls != 0 || len(target.keys) != 0 {
					t.Fatal("elapsed admission changed protocol or peer state")
				}
				if _, err := wire.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("elapsed native socket survived teardown: %v", err)
				}
			})
		})
	}
}

func TestDialAdmissionCancellationJoinsLateSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, wire := net.Pipe()
		defer wire.Close()
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		captured := make(chan context.Context, 1)
		release := make(chan struct{})
		protocol, target := &testProtocol{}, &testTarget{}
		controller, err := New(parent, protocol, target, func(ctx context.Context) (net.Conn, error) {
			captured <- ctx
			<-release
			return local, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		started := begin(controller)
		owner := <-captured
		cancel()
		synctest.Wait()
		if owner.Err() != context.Canceled {
			t.Fatal("parent cancellation did not retire its pending dial")
		}
		closed := make(chan struct{})
		go func() {
			controller.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("shutdown reported joined while its captured dial was pending")
		default:
		}
		close(release)
		synctest.Wait()
		await(t, started, true)
		select {
		case <-closed:
		default:
			t.Fatal("shutdown did not join the returned cancelled socket")
		}
		if _, err := wire.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("cancelled socket survived cleanup: %v", err)
		}
		if controller.Ready() || protocol.calls != 0 || len(target.keys) != 0 || target.revokes != 1 || protocol.closes != 1 {
			t.Fatal("cancelled admission changed protocol state or cleanup ownership")
		}
	})
}
