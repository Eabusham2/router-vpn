//go:build go1.25

package applexray

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestDialConnectionsReturnedPacketBelongsToNativeOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type key struct{}
		parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "captured DNS policy"), time.Second)
		defer cancel()
		var owner Connections
		defer owner.Close()
		request, err := owner.BeginDial(parent)
		if err != nil || request.Context.Value(key{}) != "captured DNS policy" {
			t.Fatal("native dial lost its captured caller policy", err)
		}
		backend := fakePackets(false)
		packet := NewPacketConn(request.Context, backend)
		if err := request.Publish(packet); err != nil {
			t.Fatal(err)
		}
		// The actual DNS pool cancels its dial context before its first write.
		// Let both cancellation and the old deadline pass deterministically.
		cancel()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if request.Context.Err() != nil {
			t.Fatal("completed native dial retained caller lifetime")
		}
		address := &net.UDPAddr{IP: net.IPv4(192, 168, 50, 133), Port: 53}
		if _, err := packet.WriteTo([]byte("owned query after completed dial"), address); err != nil {
			t.Fatal("completed DNS dial cancelled its returned connection", err)
		}
		<-backend.writes
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		if request.Context.Err() == nil || backend.closes.Load() != 1 {
			t.Fatal("native retirement lost the returned DNS connection")
		}
		if _, err := packet.WriteTo([]byte("stale"), address); !errors.Is(err, net.ErrClosed) {
			t.Fatal("retired DNS connection accepted another query", err)
		}
	})
}

func TestDialConnectionsPendingCallerCancellationAndDeadlineRejectPublication(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			var owner Connections
			defer owner.Close()
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			request, err := owner.BeginDial(parent)
			if err != nil {
				t.Fatal(err)
			}
			if deadline {
				time.Sleep(time.Second)
			} else {
				cancel() // Do not yield to AfterFunc before attempting publication.
			}
			probe := &connectionCloseProbe{onClose: request.Release}
			if err := request.Publish(probe); !errors.Is(err, net.ErrClosed) || probe.calls.Load() != 1 || request.Context.Err() == nil {
				t.Fatal("cancelled pending caller published or leaked its native result", err)
			}
		})
	}
}
