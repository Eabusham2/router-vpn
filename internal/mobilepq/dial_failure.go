package mobilepq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"syscall"
	"time"
)

// A failed admission retains its original error for Is/As without serializing
// addresses, keys, paths, or arbitrary native error text into host startup logs.
// The snapshot never changes admission, retries a dial, or calls an untrusted
// Error/Is/As/Timeout/Unwrap method while the controller owns a failed socket.
type dialAdmissionFailure struct {
	cause          error
	elapsedMillis  int64
	budgetExpired  bool
	callerClass    string
	returnedSocket bool
	detail         dialFailureDetail
}

type dialFailureDetail struct {
	class, operation, network string
	errno                     uint64
}

func newDialAdmissionFailure(cause, caller error, admitted, socket bool, elapsed time.Duration) error {
	owned := errors.Join(cause, caller)
	if !admitted {
		// The admission timer cancels its retained context; preserve that
		// cancellation and the distinct original five-second budget expiry.
		owned = errors.Join(owned, context.DeadlineExceeded)
	}
	return &dialAdmissionFailure{
		cause: owned, elapsedMillis: max(0, elapsed.Milliseconds()),
		budgetExpired: !admitted, callerClass: classifyDialFailure(caller).class,
		returnedSocket: socket, detail: classifyDialFailure(cause),
	}
}

func (f *dialAdmissionFailure) Error() string {
	return fmt.Sprintf("protected PQ peer transport could not open (elapsed_ms=%d budget_expired=%t caller=%s returned_socket=%t cause=%s errno=%d op=%s network=%s)",
		f.elapsedMillis, f.budgetExpired, f.callerClass, f.returnedSocket,
		f.detail.class, f.detail.errno, f.detail.operation, f.detail.network)
}

func (f *dialAdmissionFailure) Unwrap() error { return f.cause }

func classifyDialFailure(cause error) dialFailureDetail {
	result := dialFailureDetail{class: "none", operation: "none", network: "none"}
	if cause == nil {
		return result
	}
	result.class = "other"
	pending := []error{cause}
	// Only inspect concrete standard library fields and exact standard library
	// wrapper types. Joined and cyclic/custom errors cannot make this observer
	// unbounded or execute a callback after the captured dial has returned.
	for visited := 0; len(pending) > 0 && visited < 16; visited++ {
		err := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if err == nil {
			continue
		}
		typeOf := reflect.TypeOf(err)
		if typeOf.Comparable() {
			switch err {
			case context.Canceled:
				result.class = "canceled"
				return result
			case context.DeadlineExceeded:
				result.class = "deadline"
				return result
			case net.ErrClosed, os.ErrClosed, io.ErrClosedPipe:
				result.class = "closed"
				return result
			case io.EOF, io.ErrUnexpectedEOF:
				result.class = "eof"
				return result
			}
		}
		var next error
		switch value := err.(type) {
		case syscall.Errno:
			result.class, result.errno = "syscall", uint64(value)
			return result
		case *net.OpError:
			if value == nil {
				continue
			}
			if result.operation == "none" {
				result.operation = boundedDialOperation(value.Op)
				result.network = boundedDialNetwork(value.Net)
			}
			next = value.Err
		case *os.SyscallError:
			if value != nil {
				next = value.Err
			}
		case *os.PathError:
			if value != nil {
				next = value.Err
			}
		case *os.LinkError:
			if value != nil {
				next = value.Err
			}
		case *net.DNSError:
			if value != nil && value.IsTimeout {
				result.class = "timeout"
				return result
			}
		default:
			if typeOf.Kind() != reflect.Pointer || reflect.ValueOf(err).IsNil() {
				continue
			}
			standard := typeOf.Elem()
			if standard.PkgPath() == "fmt" && standard.Name() == "wrapError" {
				next = err.(interface{ Unwrap() error }).Unwrap()
			} else if standard.PkgPath() == "errors" && standard.Name() == "joinError" || standard.PkgPath() == "fmt" && standard.Name() == "wrapErrors" {
				children := err.(interface{ Unwrap() []error }).Unwrap()
				limit := min(len(children), 16-visited-len(pending))
				for i := limit - 1; i >= 0; i-- {
					pending = append(pending, children[i])
				}
			}
		}
		if next != nil && len(pending) < 16-visited {
			pending = append(pending, next)
		}
	}
	return result
}

func boundedDialOperation(value string) string {
	switch value {
	case "dial", "listen", "read", "write", "close", "set", "control":
		return value
	default:
		return "other"
	}
}

func boundedDialNetwork(value string) string {
	switch value {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "unix", "unixgram":
		return value
	default:
		return "other"
	}
}
