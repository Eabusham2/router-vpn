//go:build !darwin

package mobiletor

import (
	"context"
	"errors"
)

func RunDesktopDarwinPFBaseline(context.Context, []byte, bool) ([]byte, error) {
	return nil, errors.New("the captured Darwin PF baseline utility requires macOS")
}
