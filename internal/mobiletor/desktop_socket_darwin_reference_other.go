//go:build !darwin || !cgo

package mobiletor

import (
	"context"
	"errors"
)

func desktopDarwinPFReferenceExists(context.Context, uint64) (bool, error) {
	return false, errors.New("Darwin PF reference inspection requires the qualified native Apple adapter")
}
