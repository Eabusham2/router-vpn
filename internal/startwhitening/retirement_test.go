package startwhitening

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOriginalWhiteningOwnerObservation(t *testing.T) {
	for _, fault := range []string{"none", "reset", "close", "cancel", "copy", "generation", "cancelled-caller"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			o := NewOwner(ctx)
			defer o.Close()
			read, err := o.CaptureOriginalContext()
			if err != nil || read(t.Context()) != nil {
				t.Fatal("original owner observation missing", err)
			}
			if fault == "none" {
				call, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
				o.mu.Lock()
				blocked := read(call)
				o.mu.Unlock()
				stop()
				if !errors.Is(blocked, context.DeadlineExceeded) {
					t.Fatal("busy original owner ignored caller deadline", blocked)
				}
			}
			switch fault {
			case "reset":
				o.Reset()
			case "close":
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "copy":
				copied := new(Owner)
				reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(o).Elem())
				if _, err := copied.CaptureOriginalContext(); err == nil {
					t.Fatal("copied owner borrowed original observation")
				}
				return
			case "generation":
				o.mu.Lock()
				o.generation = context.Background()
				o.mu.Unlock()
			case "cancelled-caller":
				call, stop := context.WithCancel(t.Context())
				stop()
				if read(call) == nil {
					t.Fatal("cancelled caller observed original owner")
				}
				return
			}
			if (read(t.Context()) == nil) != (fault == "none") {
				t.Fatal("owner mutation escaped fresh observation", fault)
			}
		})
	}
}

type retirementCipher struct {
	net.Conn
	started, release chan struct{}
	once             sync.Once
	closes           atomic.Int32
	failure          error
}

func (c *retirementCipher) Close() error {
	c.once.Do(func() { c.closes.Add(1); close(c.started); <-c.release })
	return c.failure
}

// This test exercises the shipping whitening owner and authenticated close
// ledger. Its cipher is explicitly a blocking lifecycle double; native SS/UoT
// traffic is covered separately by the real encrypted provider fixture.
func TestAuthenticatedWhiteningRetirementRequiresJoinedOriginalClose(t *testing.T) {
	owner := NewOwner(t.Context())
	defer owner.Close()
	a, b := net.Pipe()
	defer b.Close()
	raw, err := owner.Open(t.Context(), [32]byte{7}, false, func(context.Context) (net.Conn, error) { return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("original cipher close failed")
	cipher := &retirementCipher{Conn: raw, started: make(chan struct{}), release: make(chan struct{}), failure: failure}
	defer func() {
		select {
		case <-cipher.release:
		default:
			close(cipher.release)
		}
	}()
	stream, err := OwnAuthenticatedStream(raw, cipher)
	if err != nil {
		t.Fatal(err)
	}
	retire := stream.CaptureJoinedRetirement(a)
	if retire == nil || retire(t.Context()) == nil {
		t.Fatal("live stream fabricated joined retirement")
	}
	if stream.CaptureJoinedRetirement(b) != nil {
		t.Fatal("foreign raw connection acquired retirement")
	}
	copied := new(AuthenticatedStream)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(stream).Elem())
	if copied.CaptureJoinedRetirement(a) != nil {
		t.Fatal("copied stream acquired retirement")
	}
	var typedNil *net.TCPConn
	if stream.CaptureJoinedRetirement(typedNil) != nil {
		t.Fatal("typed nil connection acquired retirement")
	}
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	<-cipher.started
	if retire(t.Context()) == nil {
		t.Fatal("unfinished original cipher close acquired retirement")
	}
	close(cipher.release)
	if err := <-closed; !errors.Is(err, failure) {
		t.Fatal("original close error disappeared", err)
	}
	if err := retire(t.Context()); err != nil {
		t.Fatal("joined exact stream not recognized", err)
	}
	if stream.CaptureJoinedRetirement(a) != nil {
		t.Fatal("closed stream minted new retirement")
	}
	for i := 0; i < 3; i++ {
		if !errors.Is(stream.Close(), failure) {
			t.Fatal("close retry erased original error")
		}
	}
	if cipher.closes.Load() != 1 {
		t.Fatal("cipher closed more than once")
	}
	call, cancel := context.WithCancel(t.Context())
	cancel()
	if retire(call) == nil {
		t.Fatal("cancelled caller consumed retirement")
	}
	stream.Conn = b
	if retire(t.Context()) == nil {
		t.Fatal("replacement cipher borrowed retirement")
	}
	stream.Conn = cipher
	raw.Conn = b
	if retire(t.Context()) == nil {
		t.Fatal("replacement raw connection borrowed retirement")
	}
	raw.Conn = a
	owner.mu.Lock()
	owner.conns[raw] = stream
	owner.mu.Unlock()
	if retire(t.Context()) == nil {
		t.Fatal("retained owner entry escaped retirement readback")
	}
	owner.mu.Lock()
	delete(owner.conns, raw)
	owner.mu.Unlock()
	if err := retire(t.Context()); err != nil {
		t.Fatal("restored original identity lost receipt", err)
	}
}
