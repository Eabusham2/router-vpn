package mobilepq

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type deferredProbe struct {
	calls  atomic.Int32
	closes atomic.Int32
	step   func() (Event, error)
	err    error
}

func (p *deferredProbe) Step(uint32, []byte) (Event, error) {
	p.calls.Add(1)
	if p.step != nil {
		return p.step()
	}
	return Event{Wait: time.Millisecond}, nil
}
func (p *deferredProbe) Close() error { p.closes.Add(1); return p.err }

func TestDeferredChecksNeverAllocateNativeHandles(t *testing.T) {
	var registry FactoryRegistry
	var opens atomic.Int32
	if err := registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { opens.Add(1); return &deferredProbe{}, nil })); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		ctx, cancel := context.WithCancel(context.Background())
		original := nativeConfig()
		p, err := NewDeferredProtocol(ctx, original, &registry)
		if err != nil {
			t.Fatal(err)
		}
		copy := p.config.Secret
		cancel()
		// Explicit Close joins cancellation, including when the core never
		// starts an endpoint after checking its options.
		if err = p.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(copy, make([]byte, len(copy))) || original.Secret[0] != 3 {
			t.Fatal("private copy retained or caller assets erased")
		}
		if _, err = p.Step(0, nil); !errors.Is(err, ErrStopped) {
			t.Fatal("closed syntax-check owner reused", err)
		}
	}
	if opens.Load() != 0 {
		t.Fatal("configuration checks allocated cryptographic handles")
	}
}

func TestDeferredOpensOnceAndErasesCapturedCopies(t *testing.T) {
	var registry FactoryRegistry
	var opens atomic.Int32
	native := &deferredProbe{}
	config := nativeConfig()
	if err := registry.Install(factoryFunc(func(a, b, c []byte, v int) (Protocol, error) {
		opens.Add(1)
		if !bytes.Equal(a, config.Secret) || !bytes.Equal(b, config.Public) || !bytes.Equal(c, config.Peer) || v != config.Version {
			t.Error("captured protocol inputs changed")
		}
		return native, nil
	})); err != nil {
		t.Fatal(err)
	}
	p, err := NewDeferredProtocol(context.Background(), config, &registry)
	if err != nil {
		t.Fatal(err)
	}
	copy := p.config.Secret
	var wg sync.WaitGroup
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Step(0, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if opens.Load() != 1 || native.calls.Load() != 20 || !bytes.Equal(copy, make([]byte, len(copy))) {
		t.Fatal("factory repeated or temporary keys retained")
	}
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if native.closes.Load() != 1 {
		t.Fatal("close did not join one native owner")
	}
}

func TestDeferredCancelDuringFactoryCannotPublish(t *testing.T) {
	var registry FactoryRegistry
	entered, release := make(chan struct{}), make(chan struct{})
	native := &deferredProbe{}
	if err := registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { close(entered); <-release; return native, nil })); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewDeferredProtocol(ctx, nativeConfig(), &registry)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := p.Step(0, nil); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("factory not entered")
	}
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case <-closed:
		t.Fatal("Close escaped in-flight factory")
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrStopped) {
		t.Fatal("cancelled factory returned a usable protocol", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if native.calls.Load() != 0 || native.closes.Load() != 1 {
		t.Fatal("cancelled factory handle leaked or executed")
	}
}

func TestDeferredCancelDuringStepErasesKeyAndJoins(t *testing.T) {
	var registry FactoryRegistry
	entered, release := make(chan struct{}), make(chan struct{})
	key := bytes.Repeat([]byte{9}, 32)
	native := &deferredProbe{step: func() (Event, error) { close(entered); <-release; return Event{Key: key}, nil }}
	if err := registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { return native, nil })); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewDeferredProtocol(ctx, nativeConfig(), &registry)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		event, err := p.Step(0, nil)
		if len(event.Key) != 0 {
			t.Error("cancelled key escaped")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Step not entered")
	}
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case <-closed:
		t.Fatal("Close escaped in-flight native Step")
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, make([]byte, 32)) || native.closes.Load() != 1 {
		t.Fatal("cancelled key or handle retained")
	}
}

func TestDeferredRejectsInvalidInputWithoutFactoryAndDoesNotRetryFailure(t *testing.T) {
	var registry FactoryRegistry
	var opens atomic.Int32
	if err := registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) {
		opens.Add(1)
		return nil, errors.New("private detail")
	})); err != nil {
		t.Fatal(err)
	}
	p, err := NewDeferredProtocol(context.Background(), nativeConfig(), &registry)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, input := range []struct {
		kind   uint32
		packet []byte
	}{{3, nil}, {0, []byte{1}}, {2, []byte{1}}, {1, make([]byte, 65536)}} {
		if _, err = p.Step(input.kind, input.packet); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if opens.Load() != 0 {
		t.Fatal("invalid input initialized native protocol")
	}
	if _, err = p.Step(0, nil); err == nil || err.Error() == "private detail" {
		t.Fatal("failed factory accepted or details leaked", err)
	}
	if _, err = p.Step(0, nil); !errors.Is(err, ErrStopped) || opens.Load() != 1 {
		t.Fatal("failed constructor reused")
	}
	if _, err = NewDeferredProtocol(nil, nativeConfig(), &registry); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err = NewDeferredProtocol(context.Background(), nativeConfig(), nil); err == nil {
		t.Fatal("nil registry accepted")
	}
	bad := nativeConfig()
	bad.Peer = nil
	if _, err = NewDeferredProtocol(context.Background(), bad, &registry); err == nil {
		t.Fatal("invalid captured keys accepted")
	}
}

func TestDeferredPacketRejectionIsRecoverableAndCleanupErrorsAreStable(t *testing.T) {
	var registry FactoryRegistry
	calls := 0
	native := &deferredProbe{err: errors.New("private cleanup detail"), step: func() (Event, error) {
		calls++
		if calls == 1 {
			return Event{}, ErrPacket
		}
		return Event{Wait: time.Millisecond}, nil
	}}
	if err := registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { return native, nil })); err != nil {
		t.Fatal(err)
	}
	p, err := NewDeferredProtocol(context.Background(), nativeConfig(), &registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Step(1, []byte{1}); !errors.Is(err, ErrPacket) {
		t.Fatal(err)
	}
	if _, err = p.Step(0, nil); err != nil {
		t.Fatal("rejected packet terminated owner", err)
	}
	for n := 0; n < 5; n++ {
		if err = p.Close(); !errors.Is(err, ErrCleanup) {
			t.Fatal("cleanup failure lost", err)
		}
	}
	if native.closes.Load() != 1 {
		t.Fatal("native owner repeatedly closed")
	}
}
