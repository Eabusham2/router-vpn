package applexray

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type connectionCloseProbe struct {
	calls   atomic.Int32
	err     error
	onClose func()
}

func (p *connectionCloseProbe) Close() error {
	p.calls.Add(1)
	if p.onClose != nil {
		p.onClose()
	}
	return p.err
}

func TestConnectionsSynchronousShutdownDoesNotWaitForCallbackScheduling(t *testing.T) {
	var owner Connections
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callbackEntered, releaseCallback := make(chan struct{}), make(chan struct{})
	defer close(releaseCallback)
	// Delay the old AfterFunc cancellation path deliberately. Owner.Close must
	// revoke the production packet wrapper without waiting for this callback.
	request, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop := context.AfterFunc(ctx, func() { close(callbackEntered); <-releaseCallback; request.Cancel() })
	defer stop()
	backend := fakePackets(false)
	packet := NewPacketConn(request.Context, backend)
	if err = request.Publish(packet); err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	if _, err = packet.WriteTo([]byte("current"), addr); err != nil {
		t.Fatal(err)
	}
	<-backend.writes
	cancel()
	wait(t, callbackEntered)
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if request.Context.Err() == nil || backend.closes.Load() != 1 {
		t.Fatal("Close returned before request/transport teardown")
	}
	for n := 0; n < 100; n++ {
		if _, err = packet.WriteTo([]byte("stale"), addr); !errors.Is(err, net.ErrClosed) {
			t.Fatal("post-close packet accepted", err)
		}
	}
	select {
	case <-backend.writes:
		t.Fatal("late bytes reached the old transport")
	default:
	}
}

func TestConnectionsClosePublishedStreamSynchronously(t *testing.T) {
	var owner Connections
	request, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	stream := NewStreamConn(request.Context, a, b.RemoteAddr())
	if err = request.Publish(stream); err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Write([]byte("stale")); err == nil || n != 0 {
		t.Fatal("stream write survived owner close", n, err)
	}
	select {
	case <-stream.done:
	default:
		t.Fatal("Close returned before stream teardown")
	}
}

func TestConnectionsLateDispatchCannotPublishAfterClose(t *testing.T) {
	var owner Connections
	request, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if request.Context.Err() == nil {
		t.Fatal("pending dispatch was not synchronously cancelled")
	}
	probe := &connectionCloseProbe{onClose: request.Release}
	if err = request.Publish(probe); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late dispatch accepted", err)
	}
	if probe.calls.Load() != 1 {
		t.Fatal("late connection leaked")
	}
	if _, err = owner.Begin(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed owner reused")
	}
}

func TestConnectionsPreserveCallerPolicyAndReleaseIsolation(t *testing.T) {
	type key struct{}
	var owner Connections
	deadline := time.Now().Add(time.Minute)
	parent, cancel := context.WithDeadline(context.WithValue(context.Background(), key{}, "captured policy"), deadline)
	defer cancel()
	first, err := owner.Begin(parent)
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := first.Context.Deadline()
	if !ok || !got.Equal(deadline) || first.Context.Value(key{}) != "captured policy" {
		t.Fatal("caller context policy changed")
	}
	first.Release()
	if first.Context.Err() == nil || second.Context.Err() != nil {
		t.Fatal("release crossed request ownership")
	}
	probe := &connectionCloseProbe{onClose: second.Release}
	if err = second.Publish(probe); err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if probe.calls.Load() != 1 {
		t.Fatal("live sibling did not close exactly once")
	}
}

func TestConnectionsCancelBeforeAnyBackendCloseAndKeepErrors(t *testing.T) {
	var owner Connections
	requests := make([]*Request, 20)
	probes := make([]*connectionCloseProbe, 20)
	failure := errors.New("owned close failure")
	for n := range requests {
		var err error
		requests[n], err = owner.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	for n, request := range requests {
		probes[n] = &connectionCloseProbe{err: failure, onClose: func() {
			for _, other := range requests {
				if other.Context.Err() == nil {
					t.Error("backend close observed an uncancelled sibling")
				}
			}
			request.Release()
		}}
		if err := request.Publish(probes[n]); err != nil {
			t.Fatal(err)
		}
	}
	var group sync.WaitGroup
	for n := 0; n < 20; n++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := owner.Close(); !errors.Is(err, failure) {
				t.Error("close error lost", err)
			}
		}()
	}
	group.Wait()
	for _, probe := range probes {
		if probe.calls.Load() != 1 {
			t.Fatal("concurrent Close tore down resource more than once")
		}
	}
}

func TestConnectionsConcurrentPublicationAndClose(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		var owner Connections
		request, err := owner.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		probe := &connectionCloseProbe{onClose: request.Release}
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			err := request.Publish(probe)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}()
		go func() { defer group.Done(); <-start; _ = owner.Close() }()
		close(start)
		group.Wait()
		if probe.calls.Load() != 1 || request.Context.Err() == nil {
			t.Fatal("publication race leaked resource or request")
		}
	}
}

func TestConnectionsRejectInvalidAndDuplicatePublicationWithoutLosingOwner(t *testing.T) {
	var owner Connections
	defer owner.Close()
	if _, err := owner.Begin(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := owner.Begin(ctx); err == nil {
		t.Fatal("cancelled request accepted")
	}
	r, _ := owner.Begin(context.Background())
	if err := r.Publish(nil); err == nil || r.Context.Err() == nil {
		t.Fatal("nil publication retained request")
	}
	r, _ = owner.Begin(context.Background())
	first, second := &connectionCloseProbe{}, &connectionCloseProbe{}
	if err := r.Publish(first); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(second); err == nil {
		t.Fatal("double publication accepted")
	}
	if first.calls.Load() != 0 || second.calls.Load() != 1 {
		t.Fatal("duplicate replaced the existing owner")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if first.calls.Load() != 1 {
		t.Fatal("duplicate publication orphaned first resource")
	}
}

var _ io.Closer = (*Connections)(nil)

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

func TestDialConnectionsCancellationDuringPublicationKeepsExactOwner(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		var owner Connections
		parent, cancel := context.WithCancel(context.Background())
		request, err := owner.BeginDial(parent)
		if err != nil {
			t.Fatal(err)
		}
		probe := &connectionCloseProbe{onClose: request.Release}
		start, joined := make(chan struct{}), make(chan struct{})
		go func() { <-start; cancel(); close(joined) }()
		close(start)
		err = request.Publish(probe)
		<-joined
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if err == nil && (request.Context.Err() != nil || probe.calls.Load() != 0) {
			t.Fatal("caller revoked a successfully handed-over connection")
		}
		if err != nil && (request.Context.Err() == nil || probe.calls.Load() != 1) {
			t.Fatal("rejected handover retained a pending connection")
		}
		if err := owner.Close(); err != nil || request.Context.Err() == nil || probe.calls.Load() != 1 {
			t.Fatal("handover race lost exact native retirement", err)
		}
	}
}

type dialPublicationContext struct {
	context.Context
	intercept       atomic.Bool
	entered, resume chan struct{}
}

func (p *dialPublicationContext) Err() error {
	if p.intercept.CompareAndSwap(true, false) {
		close(p.entered)
		<-p.resume
	}
	return p.Context.Err()
}

func TestDialConnectionsCancellationAfterCallbackStopCannotPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent := &dialPublicationContext{Context: ctx, entered: make(chan struct{}), resume: make(chan struct{})}
	var owner Connections
	defer owner.Close()
	request, err := owner.BeginDial(parent)
	if err != nil {
		t.Fatal(err)
	}
	probe := &connectionCloseProbe{onClose: request.Release}
	parent.intercept.Store(true)
	done := make(chan error, 1)
	go func() { done <- request.Publish(probe) }()
	wait(t, parent.entered)
	// Publish has stopped AfterFunc and still holds the owner lock. This
	// cancellation must be caught by its synchronous caller observation.
	cancel()
	close(parent.resume)
	if err := <-done; !errors.Is(err, net.ErrClosed) || probe.calls.Load() != 1 || request.Context.Err() == nil {
		t.Fatal("caller cancelled during native publication was adopted", err)
	}
}
