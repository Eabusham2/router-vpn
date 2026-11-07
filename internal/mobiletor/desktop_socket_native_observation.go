package mobiletor

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

type desktopDarwinRequestObservationKey struct{}
type desktopDarwinRequestObservation struct {
	owner     [32]byte
	pid       uint32
	sequence  uint64
	operation string
	command   atomic.Uint32
}

// Diagnostic capture only. No observer can grant a socket, refresh Current or
// change the existing parent/guardian operation deadline.
func desktopDarwinObserveRequest(ctx context.Context, capture DesktopSocketCapture, owner DesktopSocketKernelOwner, sequence uint64, operation string) context.Context {
	return context.WithValue(ctx, desktopDarwinRequestObservationKey{}, &desktopDarwinRequestObservation{
		owner: desktopSocketObservationOwner(capture, owner, ""), pid: owner.ProcessID, sequence: sequence,
		operation: desktopDarwinObservationOperation(operation),
	})
}

func desktopDarwinObservationOperation(operation string) string {
	switch operation {
	case "probe", "create", "bind", "grant", "revoke", "release", "tunnel", "retire-tunnel", "finish", "socks-associate":
		return operation
	default:
		return "other"
	}
}

const (
	desktopNativeObservationQueued uint32 = iota
	desktopNativeObservationPath
	desktopNativeObservationStart
	desktopNativeObservationWait
	desktopNativeObservationLibinfo
	desktopNativeObservationDone
)

type desktopDarwinReadbackObservation struct {
	state atomic.Uint64
}

type desktopDarwinReadbackSnapshot struct {
	owner             [32]byte
	guardian, command uint32
	sequence          uint64
	operation, kind   string
	phase, child      uint32
	elapsed           time.Duration
}

func (s desktopDarwinReadbackSnapshot) String() string {
	names := [...]string{"queued", "protected-path", "start", "wait", "libinfo", "done"}
	phase := "unknown"
	if s.phase < uint32(len(names)) {
		phase = names[s.phase]
	}
	return fmt.Sprintf("Darwin native observation: owner=%x guardian=%d request=%d operation=%s command=%d kind=%s phase=%s child=%d elapsed_us=%d",
		s.owner, s.guardian, s.sequence, s.operation, s.command, s.kind, phase, s.child, s.elapsed.Microseconds())
}

func (o *desktopDarwinReadbackObservation) enter(phase uint32, pid uint32) {
	if o != nil {
		o.state.Store(uint64(pid)<<32 | uint64(phase))
	}
}

// Observe expiration while Start/Wait or a native library call is still in
// progress; a returned error cannot report a call which never returns. The
// callback captures this exact request and joins before normal return. It
// emits only bounded metadata, never command arguments, stderr or credentials.
func desktopDarwinObserveReadback(ctx context.Context, kind string, report func(desktopDarwinReadbackSnapshot)) (*desktopDarwinReadbackObservation, func()) {
	request, _ := ctx.Value(desktopDarwinRequestObservationKey{}).(*desktopDarwinRequestObservation)
	if request == nil || report == nil {
		return nil, func() {}
	}
	switch kind {
	case "pfctl", "dscl", "ifconfig", "libinfo":
	default:
		kind = "other"
	}
	// Copy identity before scheduling. A replacement request context cannot
	// relabel a pending original operation or obtain its command counter.
	snapshot := desktopDarwinReadbackSnapshot{owner: request.owner, guardian: request.pid, sequence: request.sequence,
		operation: request.operation, command: request.command.Add(1), kind: kind}
	observation := &desktopDarwinReadbackObservation{}
	started := time.Now()
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(joined)
		state := observation.state.Load()
		snapshot.phase = uint32(state)
		if snapshot.phase == desktopNativeObservationDone {
			return
		}
		snapshot.child = uint32(state >> 32)
		snapshot.elapsed = time.Since(started)
		report(snapshot)
	})
	return observation, func() {
		observation.state.Store(uint64(desktopNativeObservationDone))
		if !stop() {
			<-joined
		}
	}
}
