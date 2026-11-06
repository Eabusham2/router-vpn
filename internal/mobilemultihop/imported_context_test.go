package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type importedBoundedEngine struct {
	*importedProofEngine
	observe func(context.Context) (string, error)
	legacy  atomic.Int32
}

func (e *importedBoundedEngine) Identity() string {
	e.legacy.Add(1)
	return "uncancellable-reader-must-not-be-used"
}
func (e *importedBoundedEngine) IdentityContext(ctx context.Context) (string, error) {
	if e.observe != nil {
		return e.observe(ctx)
	}
	return e.id, ctx.Err()
}

func TestImportedProofContextUsesAdmittedReader(t *testing.T) {
	for _, phase := range []string{"entry-proof", "private-proof", "owner-check", "measurement-proof"} {
		t.Run(phase, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
			if err != nil {
				t.Fatal(err)
			}
			e := &importedBoundedEngine{importedProofEngine: &importedProofEngine{id: "captured-owner", selected: LocalTag}}
			c.engine, c.engineID = e, e.id
			c.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
			entered := make(chan struct{})
			e.observe = func(ctx context.Context) (string, error) { close(entered); <-ctx.Done(); return "", ctx.Err() }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				switch phase {
				case "entry-proof":
					result <- c.verifyImportedEntry(ctx)
				case "private-proof":
					_, err := c.prove(ctx, LocalTag, c.meta.ExitAPI, c.meta.ExitToken, c.meta.ExitNodeID)
					result <- err
				case "owner-check":
					result <- c.requireValidContext(ctx)
				case "measurement-proof":
					m := &importedMeasurementEngine{owner: c, engine: &importedHopInput{e.importedProofEngine}, identity: e.id + ":" + LocalTag}
					result <- m.VerifyMeasurement(ctx)
				}
			}()
			select {
			case <-entered:
			case err := <-result:
				t.Fatal("operation bypassed admitted bounded reader", err)
			case <-time.After(time.Second):
				t.Fatal("operation did not enter bounded read")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("lost caller cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled native observation did not join")
			}
			if e.legacy.Load() != 0 || c.generation.Load() != 1 {
				t.Fatal("observation used legacy reader or retired healthy owner")
			}
		})
	}
}

type importedLateHop struct {
	identity   string
	connection net.Conn
	change     func()
	legacy     atomic.Int32
}

func (e *importedLateHop) Identity() string { e.legacy.Add(1); return "legacy-reader" }
func (e *importedLateHop) IdentityContext(ctx context.Context) (string, error) {
	return e.identity, ctx.Err()
}
func (e *importedLateHop) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	e.change()
	return e.connection, nil
}
func TestImportedMeasurementClosesLateOriginalConnection(t *testing.T) {
	for _, fault := range []string{"cancel", "hop-owner", "controller-owner"} {
		t.Run(fault, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
			if err != nil {
				t.Fatal(err)
			}
			e := &importedBoundedEngine{importedProofEngine: &importedProofEngine{id: "original", selected: LocalTag}}
			c.engine, c.engineID = e, e.id
			c.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
			original, peer := net.Pipe()
			defer original.Close()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := &importedLateHop{identity: "original:" + LocalTag, connection: original}
			input.change = func() {
				switch fault {
				case "cancel":
					cancel()
				case "hop-owner":
					input.identity = "replacement:" + LocalTag
				case "controller-owner":
					e.id = "replacement"
				}
			}
			m := &importedMeasurementEngine{owner: c, engine: input, identity: input.identity}
			connection, err := m.Dial(ctx, externalEntryTag, "1.1.1.1:443")
			if connection != nil || err == nil {
				t.Fatal("retired operation returned original connection", err)
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			_, readErr := peer.Read(make([]byte, 1))
			if !errors.Is(readErr, net.ErrClosed) && readErr == nil {
				t.Fatal("original returned connection was not closed")
			}
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				t.Fatal("original returned connection remained owned")
			}
			if input.legacy.Load() != 0 || e.legacy.Load() != 0 || c.generation.Load() != 1 {
				t.Fatal("observation touched legacy reader or replacement authority")
			}
		})
	}
}

func TestImportedStartupCloseJoinsAdmittedIdentityRead(t *testing.T) {
	config, capture, files, profile := importedEntryFixture(t, "", "")
	c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
	if err != nil {
		t.Fatal(err)
	}
	e := &importedBoundedEngine{importedProofEngine: &importedProofEngine{id: "captured-startup", selected: LocalTag}}
	entered := make(chan struct{})
	e.observe = func(ctx context.Context) (string, error) { close(entered); <-ctx.Done(); return "", ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- c.Run(ctx, e) }()
	select {
	case <-entered:
	case err := <-run:
		t.Fatal("startup used unbounded legacy identity", err)
	case <-time.After(time.Second):
		cancel()
		<-run
		t.Fatal("startup did not admit original observation")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal("startup close lost original drain", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-run
		<-closeDone
		t.Fatal("startup owner mutex prevented cancellation")
	}
	if err := <-run; !errors.Is(err, context.Canceled) {
		t.Fatal("startup lost cancellation", err)
	}
	if e.legacy.Load() != 0 || c.Healthy() {
		t.Fatal("retired startup retained native identity")
	}
}

func TestImportedOwnerContextRetiresHeldControllerRead(t *testing.T) {
	for _, phase := range []string{"identity", "selection"} {
		t.Run(phase, func(t *testing.T) {
			c := &Controller{}
			c.mu.Lock()
			held := true
			release := func() {
				if held {
					held = false
					c.mu.Unlock()
				}
			}
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if phase == "identity" {
					done <- c.requireValidContext(ctx)
				} else {
					_, err := c.selectionContext(ctx)
					done <- err
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("lost original controller read deadline", err)
				}
			case <-time.After(time.Second):
				release()
				<-done
				t.Fatal("controller read waited beyond caller ownership")
			}
		})
	}
}
