//go:build darwin && !cgo

package mobiletor

import (
	"context"
	"errors"
)

func desktopDarwinPFNativeReplace(context.Context, string, []desktopPFFilterRule) error {
	return errors.New("Darwin owned filter transactions require the actual native Apple SDK adapter")
}
