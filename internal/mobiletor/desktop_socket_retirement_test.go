package mobiletor

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDesktopSocketRetirementHeldStages(t *testing.T) {
	p := desktopSocketFixturePolicy()
	var refuse atomic.Bool
	refuse.Store(true)
	p.revoke = func(context.Context, DesktopSocketGrant) error {
		if refuse.Load() {
			return syscall.Errno(10022)
		}
		return nil
	}
	b, _ := newDesktopSocketFixture(t, p)
	listener := desktopSocketListener(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := listener.AcceptTCP(); accepted <- c }()
	connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := desktopSocketAwait(t, accepted)
	defer peer.Close()
	request := desktopSocketAwait(t, p.requests)
	raw := connection.(*desktopSocketConn).socket
	held := &desktopSocketHeldIO{Conn: raw.conn, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer func() { refuse.Store(false); release.Do(func() { close(held.release) }) }()
	raw.mu.Lock()
	raw.conn = held
	raw.mu.Unlock()
	read := make(chan error, 1)
	go func() { _, err := connection.Read(make([]byte, 1)); read <- err }()
	desktopSocketAwait(t, held.entered)
	b.Cancel()
	awaitStage := func(phase uint32, failure bool) {
		t.Helper()
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			if raw.retirement.phase.Load() == phase && (!failure || raw.retirement.first.Load() != nil) {
				return
			}
			select {
			case <-deadline.C:
				t.Fatal("original retirement did not reach held stage", phase)
			case <-tick.C:
			}
		}
	}
	failedClose := func() (error, desktopRetirementSnapshot) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		err := b.Close(ctx)
		var snapshot desktopRetirementSnapshot
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &snapshot) {
			t.Fatal("lost original deadline or snapshot", err)
		}
		desktopSocketAssertReserved(t, "tcp", request.Local)
		if p.count() != 1 {
			t.Fatal("diagnostic changed original permit ownership")
		}
		return err, snapshot
	}
	awaitStage(retirementIO, false)
	first, ioSnapshot := failedClose()
	firstText := first.Error()
	if ioSnapshot.stages[retirementIO] != 1 || ioSnapshot.total != 1 {
		t.Fatal("missing entered I/O stage", first)
	}
	release.Do(func() { close(held.release) })
	if err := desktopSocketAwait(t, read); err == nil {
		t.Fatal("cancelled original read succeeded")
	}
	awaitStage(retirementRevoke, true)
	_, revokeSnapshot := failedClose()
	// The ordinary fixture policy uses errors.Join. Unknown wrappers stay
	// opaque; classification must not execute an arbitrary Unwrap method.
	if revokeSnapshot.stages[retirementRevoke] != 1 || revokeSnapshot.failures[5] != 1 || revokeSnapshot.errnoCount != 0 {
		t.Fatal("lost failed original revoke", revokeSnapshot.Error())
	}
	refuse.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if first.Error() != firstText || ioSnapshot.stages[retirementIO] != 1 {
		t.Fatal("later cleanup rewrote original failed wait")
	}
	if b.retirementSnapshot().total != 0 {
		t.Fatal("original socket did not drain")
	}
}

func TestDesktopSocketRetirementSnapshotContendedAndBounded(t *testing.T) {
	b := &DesktopSocketBroker{sockets: make(map[*desktopSocket]struct{})}
	b.mu.Lock()
	result := make(chan desktopRetirementSnapshot, 1)
	go func() { result <- b.retirementSnapshot() }()
	select {
	case snapshot := <-result:
		if !snapshot.busy || snapshot.total != -1 {
			b.mu.Unlock()
			t.Fatal("contended owner was read", snapshot)
		}
	case <-time.After(time.Second):
		b.mu.Unlock()
		t.Fatal("diagnostic waited for owner lock")
	}
	b.mu.Unlock()
	for i := 0; i < DesktopSocketLimit+10; i++ {
		socket := &desktopSocket{network: "tcp"}
		socket.retirement.phase.Store(retirementRelease)
		socket.retirement.failure(syscall.Errno(i + 1))
		b.sockets[socket] = struct{}{}
	}
	snapshot := b.retirementSnapshot()
	if snapshot.total != DesktopSocketLimit+10 || snapshot.truncated != 10 || snapshot.tcp != DesktopSocketLimit || snapshot.errnoCount != 8 || len(snapshot.Error()) > 2048 {
		t.Fatal("snapshot is not bounded", snapshot.Error())
	}
}

type desktopRetirementPoisonError []byte

func (desktopRetirementPoisonError) Error() string {
	panic("diagnostic invoked private error formatter")
}
func (desktopRetirementPoisonError) Unwrap() error { panic("diagnostic invoked arbitrary unwrap") }
func (desktopRetirementPoisonError) Is(error) bool { panic("diagnostic invoked arbitrary classifier") }

func TestDesktopSocketRetirementFailurePrivacy(t *testing.T) {
	var unknown desktopRetirementState
	unknown.failure(desktopRetirementPoisonError("private endpoint and credentials"))
	if unknown.first.Load().class != 5 {
		t.Fatal("unknown error misclassified")
	}
	var known desktopRetirementState
	known.failure(&net.OpError{Op: "private operation", Err: &os.SyscallError{Syscall: "private syscall", Err: syscall.Errno(10022)}})
	known.failure(context.Canceled)
	if *known.first.Load() != (desktopRetirementFailure{class: 4, errno: 10022}) {
		t.Fatal("first original failure changed")
	}
	b := &DesktopSocketBroker{}
	b.retirement.failure(desktopRetirementPoisonError("secret"))
	text := b.retirementSnapshot().Error()
	if strings.Contains(text, "secret") || !strings.Contains(text, "broker_first=other") {
		t.Fatal("unsafe diagnostic", text)
	}
}
