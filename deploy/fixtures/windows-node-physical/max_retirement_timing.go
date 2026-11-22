//go:build windows && routervpn_windows_node_composition

package mobiletor

// Installed only by the MAX native test overlay. Timing never changes a caller,
// operation, error or deadline. Successful retirement produces no output.
import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type desktopMAXRetirementEvent struct {
	stage      string
	start, end time.Time
}

type desktopMAXRetirementTiming struct {
	sync.Mutex
	start   time.Time
	events  []desktopMAXRetirementEvent
	dropped int
}

func desktopMAXRetirementTimingStart() *desktopMAXRetirementTiming {
	return &desktopMAXRetirementTiming{start: time.Now()}
}

func (d *desktopMAXRetirementTiming) enter(stage string) func() {
	d.Lock()
	if len(d.events) == 128 {
		d.dropped++
		d.Unlock()
		return func() {}
	}
	index := len(d.events)
	d.events = append(d.events, desktopMAXRetirementEvent{stage: stage, start: time.Now()})
	d.Unlock()
	return func() {
		d.Lock()
		d.events[index].end = time.Now()
		d.Unlock()
	}
}

func (d *desktopMAXRetirementTiming) call(stage string, operation func() error) error {
	defer d.enter(stage)()
	return operation()
}

func (d *desktopMAXRetirementTiming) report(err error) {
	d.reportTo(os.Stderr, err)
}

func (d *desktopMAXRetirementTiming) reportTo(out io.Writer, err error) {
	if err == nil {
		return
	}
	d.Lock()
	now := time.Now()
	events := append([]desktopMAXRetirementEvent(nil), d.events...)
	dropped := d.dropped
	d.Unlock()
	// Do not print errors, handles, captures, account names or configuration.
	fmt.Fprintf(out, "MAX retirement timing elapsed_ns=%d deadline=%t cancelled=%t dropped=%d\n", now.Sub(d.start).Nanoseconds(), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), dropped)
	for index, event := range events {
		end := event.end
		pending := end.IsZero()
		if pending {
			end = now
		}
		fmt.Fprintf(out, "MAX retirement timing step=%d stage=%s start_ns=%d elapsed_ns=%d pending=%t\n", index, event.stage, event.start.Sub(d.start).Nanoseconds(), end.Sub(event.start).Nanoseconds(), pending)
	}
}

type desktopMAXRetirementBinding struct {
	timing         *desktopMAXRetirementTiming
	lock, baseline syscall.GUID
}

var desktopMAXRetirementEngines = struct {
	sync.Mutex
	owners map[*desktopWFPEngine]desktopMAXRetirementBinding
}{owners: make(map[*desktopWFPEngine]desktopMAXRetirementBinding)}

func desktopMAXRetirementRegister(d *desktopMAXRetirementTiming, p *DesktopWindowsSocketPolicy) func() {
	// Called inside the original policy operation gate. Native work retains
	// this binding after caller expiry, until that same worker really returns.
	joined := d.enter("native-close-worker")
	engines := []*desktopWFPEngine{p.leaseEngine, p.baselineEngine}
	desktopMAXRetirementEngines.Lock()
	for _, engine := range engines {
		if engine != nil {
			desktopMAXRetirementEngines.owners[engine] = desktopMAXRetirementBinding{d, p.lockKey, p.sublayer}
		}
	}
	desktopMAXRetirementEngines.Unlock()
	return func() {
		desktopMAXRetirementEngines.Lock()
		for _, engine := range engines {
			if desktopMAXRetirementEngines.owners[engine].timing == d {
				delete(desktopMAXRetirementEngines.owners, engine)
			}
		}
		desktopMAXRetirementEngines.Unlock()
		joined()
	}
}

func desktopMAXRetirementEnumeration(e *desktopWFPEngine, sublayer syscall.GUID) func() {
	desktopMAXRetirementEngines.Lock()
	binding, found := desktopMAXRetirementEngines.owners[e]
	desktopMAXRetirementEngines.Unlock()
	if !found {
		return func() {}
	}
	stage := "other-enumeration"
	if sublayer == binding.lock {
		stage = "lock-enumeration"
	}
	if sublayer == binding.baseline {
		stage = "baseline-enumeration"
	}
	return binding.timing.enter(stage)
}

// The caller and worker can finish independently at the original monitor
// deadline. Sample their state before policy cancellation, then report only
// after the unchanged fail-closed action. A native error can carry addresses
// or account information, so never print its text.
type desktopMAXMonitorObservation struct {
	started time.Time
	state   atomic.Uint32
}

func desktopMAXMonitorStart() *desktopMAXMonitorObservation {
	return &desktopMAXMonitorObservation{started: time.Now()}
}

type desktopMAXMonitorFailure struct {
	stage                       uint32
	returned                    bool
	elapsed                     time.Duration
	deadline, cancelled, closed bool
	errno                       syscall.Errno
	wfpOperation                string
	wfpStatus                   uint64
}

func (o *desktopMAXMonitorObservation) failure(err error) desktopMAXMonitorFailure {
	var errno syscall.Errno
	errors.As(err, &errno)
	state := o.state.Load()
	var operation string
	var status uint64
	if err != nil {
		for line := range strings.SplitSeq(err.Error(), "\n") {
			message, ok := strings.CutPrefix(line, "Windows owned WFP ")
			name, code, separated := strings.Cut(message, " failed (0x")
			if !ok || !separated || len(code) != 9 || code[8] != ')' {
				continue
			}
			switch name {
			case "capture filter enumeration", "read filter enumeration", "close filter enumeration", "read baseline sublayer", "read managed object security", "read exact filter", "confirm filter removal", "delete exact filter":
				value, parseErr := strconv.ParseUint(code[:8], 16, 32)
				if parseErr == nil {
					operation, status = name, value
				}
			}
			if operation != "" {
				break
			}
		}
	}
	return desktopMAXMonitorFailure{
		stage: state & 7, returned: state&8 != 0, elapsed: time.Since(o.started),
		deadline: errors.Is(err, context.DeadlineExceeded), cancelled: errors.Is(err, context.Canceled),
		closed: errors.Is(err, net.ErrClosed), errno: errno, wfpOperation: operation, wfpStatus: status,
	}
}

func (f desktopMAXMonitorFailure) report() { f.writeTo(os.Stderr) }

func (f desktopMAXMonitorFailure) writeTo(out io.Writer) {
	stages := [...]string{"gate", "entered", "revoke-expired", "verify-baseline", "verify-tunnel"}
	fmt.Fprintf(out, "MAX monitor failure stage=%s worker_returned=%t elapsed_ns=%d deadline=%t cancelled=%t closed=%t errno=%d wfp_operation=%q wfp_status=%08x\n", stages[f.stage], f.returned, f.elapsed.Nanoseconds(), f.deadline, f.cancelled, f.closed, f.errno, f.wfpOperation, f.wfpStatus)
}
