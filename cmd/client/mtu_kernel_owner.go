package main

import (
	"errors"
	"strings"
)

// The controller keeps this owner for the whole measurement, adoption and
// rollback transaction. Interface names are presentation, never write handles.
type mtuKernelState struct {
	Interface string `json:"interface"`
	Family    int    `json:"family"`
	Index     int    `json:"index"`
	MTU       int    `json:"mtu"`
	Identity  string `json:"identity"`
}

type mtuKernelOwner interface {
	Read() (mtuKernelState, error)
	Change(expected mtuKernelState, mtu int) (mtuKernelState, error)
	Close() error
}

var errMTUKernelOwner = errors.New("captured MTU interface owner is no longer current")

func validMTUKernelCapture(live mtuLiveSnapshot) bool {
	return live.Interface != "" && live.Interface != "." && live.Interface != ".." &&
		!strings.ContainsAny(live.Interface, "/\\\r\n\x00") && len(live.Interface) <= 256 &&
		(live.Family == 4 || live.Family == 6) && live.OriginalMTU >= 576 && live.OriginalMTU <= 9000
}

func validMTUKernelState(state mtuKernelState) bool {
	return validMTUKernelCapture(mtuLiveSnapshot{Interface: state.Interface, Family: state.Family, OriginalMTU: state.MTU}) &&
		state.Index > 0 && state.Identity != "" && len(state.Identity) <= 256 && !strings.ContainsAny(state.Identity, "\x00\r\n")
}
