package mobiletor

import (
	"errors"
	"os"
)

// Go's Unix ReadMsg path can retain recvmsg's -1 return value when the
// subsequent poll wait reaches its deadline. A timeout before any frame byte
// or ancillary data is an idle tick; a partially consumed frame never is.
func desktopSocketIdleReceive(n, ancillary, flags int, err error) bool {
	return (n == 0 || n == -1) && ancillary == 0 && flags == 0 && errors.Is(err, os.ErrDeadlineExceeded)
}
