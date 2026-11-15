package mobiletor

import (
	"context"
	"fmt"
	"sync"
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
	case "probe", "create", "bind", "grant", "renew", "revoke", "release", "tunnel", "retire-tunnel", "finish", "socks-associate":
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
	desktopNativeObservationSend
	desktopNativeObservationReceive
	desktopNativeObservationAcknowledge
	desktopNativeObservationAdopt
)

type desktopDarwinReadbackObservation struct {
	mu        sync.Mutex
	state     uint64
	started   time.Time
	entered   time.Time
	durations [10]time.Duration
	query     string
}

type desktopDarwinReadbackSnapshot struct {
	owner             [32]byte
	guardian, command uint32
	sequence          uint64
	operation, kind   string
	phase, child      uint32
	elapsed           time.Duration
	phaseElapsed      time.Duration
	queued, path      time.Duration
	start, wait       time.Duration
	query             string
}

func (s desktopDarwinReadbackSnapshot) String() string {
	names := [...]string{"queued", "protected-path", "start", "wait", "libinfo", "done", "send", "receive", "acknowledge", "adopt"}
	phase := "unknown"
	if s.phase < uint32(len(names)) {
		phase = names[s.phase]
	}
	query := s.query
	if query == "" {
		query = "other"
	}
	return fmt.Sprintf("Darwin native observation: owner=%x guardian=%d request=%d operation=%s command=%d kind=%s phase=%s child=%d elapsed_us=%d query=%s phase_us=%d queued_us=%d path_us=%d start_us=%d wait_us=%d",
		s.owner, s.guardian, s.sequence, s.operation, s.command, s.kind, phase, s.child, s.elapsed.Microseconds(), query,
		s.phaseElapsed.Microseconds(), s.queued.Microseconds(), s.path.Microseconds(), s.start.Microseconds(), s.wait.Microseconds())
}

func (o *desktopDarwinReadbackObservation) enter(phase uint32, pid uint32) {
	if o != nil {
		o.mu.Lock()
		defer o.mu.Unlock()
		now := time.Now()
		previous := uint32(o.state)
		if previous < uint32(len(o.durations)) {
			o.durations[previous] += now.Sub(o.entered)
		}
		o.entered = now
		o.state = uint64(pid)<<32 | uint64(phase)
	}
}

// Only fixed query categories leave the guardian. Anchor paths, interfaces,
// account identities, command input and arbitrary arguments are never logged.
func (o *desktopDarwinReadbackObservation) describeCommand(path string, args []string) {
	if o == nil {
		return
	}
	query := "other"
	if path == "/sbin/pfctl" {
		if len(args) >= 2 && args[len(args)-2] == "-s" {
			switch args[len(args)-1] {
			case "info", "rules", "nat", "states":
				query = args[len(args)-1]
			case "Anchors":
				query = "anchors"
			case "Interfaces":
				query = "interfaces"
			}
		} else if len(args) == 6 && args[0] == "-n" && args[1] == "-v" && args[2] == "-a" && args[4] == "-f" && args[5] == "-" {
			query = "canonical"
		}
	}
	o.mu.Lock()
	o.query = query
	o.mu.Unlock()
}

// Phase and timing are captured together. A cancellation between Start and
// Wait must not pair the new child/phase with the previous phase's duration.
// This short metadata lock never encloses native work or the report callback.
func (o *desktopDarwinReadbackObservation) capture(snapshot desktopDarwinReadbackSnapshot) desktopDarwinReadbackSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	snapshot.phase, snapshot.child = uint32(o.state), uint32(o.state>>32)
	snapshot.elapsed, snapshot.phaseElapsed = now.Sub(o.started), now.Sub(o.entered)
	durations := o.durations
	if snapshot.phase < uint32(len(durations)) {
		durations[snapshot.phase] += snapshot.phaseElapsed
	}
	snapshot.queued, snapshot.path = durations[desktopNativeObservationQueued], durations[desktopNativeObservationPath]
	snapshot.start, snapshot.wait = durations[desktopNativeObservationStart], durations[desktopNativeObservationWait]
	snapshot.query = o.query
	return snapshot
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
	case "pfctl", "dscl", "ifconfig", "libinfo", "creator":
	default:
		kind = "other"
	}
	// Copy identity before scheduling. A replacement request context cannot
	// relabel a pending original operation or obtain its command counter.
	snapshot := desktopDarwinReadbackSnapshot{owner: request.owner, guardian: request.pid, sequence: request.sequence,
		operation: request.operation, command: request.command.Add(1), kind: kind}
	started := time.Now()
	observation := &desktopDarwinReadbackObservation{started: started, entered: started}
	joined := make(chan struct{})
	var once sync.Once
	reportCurrent := func() {
		once.Do(func() {
			snapshot = observation.capture(snapshot)
			if snapshot.phase == desktopNativeObservationDone {
				return
			}
			report(snapshot)
		})
	}
	stop := context.AfterFunc(ctx, func() {
		defer close(joined)
		reportCurrent()
	})
	return observation, func() {
		// A command can return its original cancellation before AfterFunc is
		// scheduled. Retain that last stage once instead of marking it done
		// and hiding the very expiration this observation was created for.
		if ctx.Err() != nil {
			reportCurrent()
		}
		observation.enter(desktopNativeObservationDone, 0)
		if !stop() {
			<-joined
		}
	}
}
