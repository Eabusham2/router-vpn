package mobiletor

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
)

// Retirement observations never authorize I/O or cleanup. They describe the
// original owner's failed Close wait; later Box stages may still drain it.
type desktopRetirementState struct {
	phase atomic.Uint32
	first atomic.Pointer[desktopRetirementFailure]
}
type desktopRetirementFailure struct {
	class uint32
	errno uint64
}

const (
	retirementIdle uint32 = iota
	retirementOperation
	retirementChildren
	retirementIO
	retirementPeerOwner
	retirementRevoke
	retirementConnection
	retirementKeeper
	retirementFile
	retirementNative
	retirementRelease
	retirementDone
)

var desktopSocketRetirementNames = [...]string{"idle", "operation", "children", "io", "peer-owner", "revoke", "connection-close", "keeper-close", "file-close", "native-close", "source-release", "done"}
var desktopBrokerRetirementNames = [...]string{"idle", "constructors", "sockets", "source-close", "monitor", "done"}
var desktopRetirementFailureNames = [...]string{"none", "canceled", "deadline", "closed", "syscall", "other"}

func (s *desktopRetirementState) failure(err error) {
	if err == nil || s.first.Load() != nil {
		return
	}
	result := desktopRetirementFailure{class: 5}
	// Inspect only concrete standard-library wrapper fields. Do not call Error,
	// Is, As, Timeout or an arbitrary Unwrap method in this observation path.
	for depth := 0; err != nil && depth < 8; depth++ {
		if reflect.TypeOf(err).Comparable() {
			switch err {
			case context.Canceled:
				result.class = 1
			case context.DeadlineExceeded:
				result.class = 2
			case net.ErrClosed, os.ErrClosed:
				result.class = 3
			}
			if result.class != 5 {
				break
			}
		}
		switch value := err.(type) {
		case syscall.Errno:
			result.class, result.errno = 4, uint64(value)
			err = nil
		case *os.SyscallError:
			if value == nil {
				err = nil
			} else {
				err = value.Err
			}
		case *net.OpError:
			if value == nil {
				err = nil
			} else {
				err = value.Err
			}
		default:
			err = nil
		}
	}
	s.first.CompareAndSwap(nil, &result)
}

type desktopRetirementSnapshot struct {
	broker                            uint32
	brokerFirst                       desktopRetirementFailure
	busy                              bool
	total, tcp, udp, other, truncated int
	stages                            [len(desktopSocketRetirementNames)]int
	failures                          [len(desktopRetirementFailureNames)]int
	errnos                            [8]uint64
	errnoCount, errnoOverflow         int
}

func (b *DesktopSocketBroker) retirementSnapshot() desktopRetirementSnapshot {
	result := desktopRetirementSnapshot{broker: b.retirement.phase.Load()}
	if first := b.retirement.first.Load(); first != nil {
		result.brokerFirst = *first
	}
	if !b.mu.TryLock() {
		result.busy = true
		result.total = -1
		return result
	}
	defer b.mu.Unlock()
	result.total = len(b.sockets)
	visited := 0
	for socket := range b.sockets {
		if visited >= DesktopSocketLimit {
			result.truncated = result.total - visited
			break
		}
		visited++
		switch socket.network {
		case "tcp":
			result.tcp++
		case "udp":
			result.udp++
		default:
			result.other++
		}
		phase := socket.retirement.phase.Load()
		if phase >= uint32(len(result.stages)) {
			phase = retirementIdle
		}
		result.stages[phase]++
		if first := socket.retirement.first.Load(); first != nil {
			class := first.class
			if class >= uint32(len(result.failures)) {
				class = 5
			}
			result.failures[class]++
			if first.errno != 0 {
				seen := false
				for _, value := range result.errnos[:result.errnoCount] {
					if value == first.errno {
						seen = true
						break
					}
				}
				if !seen {
					if result.errnoCount < len(result.errnos) {
						result.errnos[result.errnoCount] = first.errno
						result.errnoCount++
					} else {
						result.errnoOverflow++
					}
				}
			}
		}
	}
	sort.Slice(result.errnos[:result.errnoCount], func(i, j int) bool { return result.errnos[i] < result.errnos[j] })
	return result
}
func (s desktopRetirementSnapshot) Error() string {
	stage := "unknown"
	if s.broker < uint32(len(desktopBrokerRetirementNames)) {
		stage = desktopBrokerRetirementNames[s.broker]
	}
	class := "other"
	if s.brokerFirst.class < uint32(len(desktopRetirementFailureNames)) {
		class = desktopRetirementFailureNames[s.brokerFirst.class]
	}
	var text strings.Builder
	fmt.Fprintf(&text, "desktop retirement close-wait snapshot: broker=%s broker_first=%s errno=%d map_busy=%t sockets=%d tcp=%d udp=%d other=%d truncated=%d", stage, class, s.brokerFirst.errno, s.busy, s.total, s.tcp, s.udp, s.other, s.truncated)
	for index, count := range s.stages {
		if count != 0 {
			fmt.Fprintf(&text, " %s=%d", desktopSocketRetirementNames[index], count)
		}
	}
	for index, count := range s.failures {
		if count != 0 {
			fmt.Fprintf(&text, " first_%s=%d", desktopRetirementFailureNames[index], count)
		}
	}
	fmt.Fprintf(&text, " socket_errno=%v errno_overflow=%d", s.errnos[:s.errnoCount], s.errnoOverflow)
	return text.String()
}
