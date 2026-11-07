//go:build go1.25

package mobilepq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type dialFailureOpaque struct{}

func (*dialFailureOpaque) Error() string { panic("diagnostic called arbitrary Error") }
func (*dialFailureOpaque) Is(error) bool { panic("diagnostic called arbitrary Is") }
func (*dialFailureOpaque) As(any) bool   { panic("diagnostic called arbitrary As") }
func (*dialFailureOpaque) Unwrap() error { panic("diagnostic called arbitrary Unwrap") }
func (*dialFailureOpaque) Timeout() bool { panic("diagnostic called arbitrary Timeout") }

type dialFailureNoncomparable []byte

func (dialFailureNoncomparable) Error() string {
	panic("diagnostic formatted private noncomparable error")
}

type dialFailureConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *dialFailureConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestDialFailureRetainsOriginalAdmissionEvidence(t *testing.T) {
	for _, phase := range []string{"native-syscall", "wrapped-syscall", "joined-syscall", "native-canceled", "native-deadline", "native-closed", "native-eof", "dns-timeout", "opaque", "noncomparable", "deep-wrapper", "socket-error", "missing-socket", "parent-cancel", "budget-cancel", "late-socket", "late-error", "cleanup-error"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				local, wire := net.Pipe()
				defer local.Close()
				defer wire.Close()
				connection := &dialFailureConn{Conn: local}
				protocol, target := &testProtocol{}, &testTarget{}
				var native error
				wantClass, wantCaller, wantOp, wantNetwork := "none", "none", "none", "none"
				var wantErrno uint64
				wantSocket, expired := false, false
				switch phase {
				case "native-syscall", "wrapped-syscall", "joined-syscall", "socket-error", "late-error", "cleanup-error":
					native = &net.OpError{Op: "listen", Net: "udp4", Source: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 1234}, Addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 4321}, Err: &os.SyscallError{Syscall: "private-syscall-secret", Err: syscall.Errno(10022)}}
					wantClass, wantOp, wantNetwork, wantErrno = "syscall", "listen", "udp4", 10022
					if phase == "wrapped-syscall" {
						native = fmt.Errorf("private-path-and-key: %w", native)
					}
					if phase == "joined-syscall" {
						native = errors.Join(fmt.Errorf("private-wrapper: %w", native), context.Canceled)
					}
					wantSocket = phase == "socket-error" || phase == "late-error"
					expired = phase == "late-error"
					if phase == "cleanup-error" {
						target.failRevoke = true
					}
				case "native-canceled":
					native = context.Canceled
					wantClass = "canceled"
				case "native-deadline":
					native = context.DeadlineExceeded
					wantClass = "deadline"
				case "native-closed":
					native = net.ErrClosed
					wantClass = "closed"
				case "native-eof":
					native = io.EOF
					wantClass = "eof"
				case "dns-timeout":
					native = &net.DNSError{Name: "private-host.example", Err: "private-dns-secret", IsTimeout: true}
					wantClass = "timeout"
				case "opaque":
					native = &dialFailureOpaque{}
					wantClass = "other"
				case "noncomparable":
					native = dialFailureNoncomparable("private-key-buffer")
					wantClass = "other"
				case "deep-wrapper":
					native = syscall.Errno(10022)
					for i := 0; i < 32; i++ {
						native = fmt.Errorf("private-wrapper: %w", native)
					}
					wantClass = "other"
				case "parent-cancel":
					wantCaller = "canceled"
				case "budget-cancel":
					wantClass, wantCaller, expired = "canceled", "canceled", true
				case "late-socket":
					wantSocket, expired = true, true
				}
				if expired {
					wantCaller = "canceled"
				}
				original := native
				controller, err := New(parent, protocol, target, func(ctx context.Context) (net.Conn, error) {
					if phase == "parent-cancel" {
						cancel()
					}
					if phase == "budget-cancel" {
						<-ctx.Done()
						native = ctx.Err()
					}
					if phase == "late-socket" || phase == "late-error" {
						time.Sleep(5*time.Second + time.Nanosecond)
					}
					if wantSocket {
						return connection, native
					}
					return nil, native
				})
				if err != nil {
					t.Fatal(err)
				}
				defer controller.Close()
				failure := <-begin(controller)
				var snapshot *dialAdmissionFailure
				if failure == nil || !errors.As(failure, &snapshot) {
					t.Fatal("failed protected dial discarded original admission evidence")
				}
				if snapshot.detail.class != wantClass || snapshot.detail.errno != wantErrno || snapshot.detail.operation != wantOp || snapshot.detail.network != wantNetwork || snapshot.callerClass != wantCaller || snapshot.returnedSocket != wantSocket || snapshot.budgetExpired != expired {
					t.Fatal("dial diagnostic changed its captured failure fields", snapshot.Error())
				}
				if snapshot.elapsedMillis != 0 && !expired || expired && snapshot.elapsedMillis != 5000 {
					t.Fatal("diagnostic changed original admission timing", snapshot.elapsedMillis)
				}
				if original != nil && phase != "noncomparable" && !errors.Is(failure, original) {
					t.Fatal("dial diagnostic discarded original cause identity")
				}
				if wantErrno != 0 {
					var operation *net.OpError
					if !errors.Is(failure, syscall.Errno(wantErrno)) || !errors.As(failure, &operation) || operation.Op != "listen" {
						t.Fatal("dial diagnostic lost inspectable native socket cause")
					}
				}
				if expired && (!errors.Is(failure, context.DeadlineExceeded) || !errors.Is(failure, context.Canceled)) {
					t.Fatal("dial budget lost distinct cancellation and expiry causes")
				}
				if target.failRevoke && !errors.Is(failure, ErrCleanup) {
					t.Fatal("diagnostic hid unconfirmed peer cleanup")
				}
				text := failure.Error()
				if !strings.HasPrefix(text, "protected PQ peer transport could not open (") || len(text) > 350 || strings.Contains(text, "private") || strings.Contains(text, "203.0.113") || strings.Contains(text, "1234") || strings.Contains(text, "4321") {
					t.Fatal("dial observation leaked arbitrary detail or lost its bounded format")
				}
				if wantSocket {
					if connection.closes.Load() != 1 {
						t.Fatal("failed admission changed late-socket close ownership")
					}
					if _, err := wire.Read(make([]byte, 1)); err != io.EOF {
						t.Fatal("failed dial retained its original returned socket", err)
					}
				}
				if controller.Ready() || protocol.calls != 0 || protocol.closes != 1 || len(target.keys) != 0 || target.revokes != 1 {
					t.Fatal("diagnostic admitted a failed native dial or changed cleanup ownership")
				}
			})
		})
	}
}

func TestDialFailureBoundsUnknownOperationAndErrorTree(t *testing.T) {
	unknown := &net.OpError{Op: strings.Repeat("private-op", 4096), Net: "private-network-secret", Err: syscall.Errno(10022)}
	detail := classifyDialFailure(unknown)
	if detail.class != "syscall" || detail.errno != 10022 || detail.operation != "other" || detail.network != "other" {
		t.Fatal("native operation classification lost bounded enum", detail)
	}
	children := make([]error, 1000)
	for i := range children {
		children[i] = &dialFailureOpaque{}
	}
	detail = classifyDialFailure(errors.Join(children...))
	if detail.class != "other" {
		t.Fatal("opaque error tree manufactured a known native cause", detail)
	}
	var absent *net.OpError
	if detail = classifyDialFailure(absent); detail.class != "other" {
		t.Fatal("typed nil error changed observation", detail)
	}
}
