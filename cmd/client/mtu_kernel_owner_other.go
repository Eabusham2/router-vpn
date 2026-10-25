//go:build !linux && !windows

package main

import "errors"

func openMTUKernelOwner(mtuLiveSnapshot) (mtuKernelOwner, error) {
	return nil, errors.New("this platform requires its retained native TUN MTU owner")
}
