//go:build !linux && !windows && !darwin

package desktopnetwork

import "errors"

func openNativeObserver(func(Event, error)) (nativeObserver, error) {
	return nil, errors.New("this target has no owned desktop network observer")
}
