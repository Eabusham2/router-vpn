//go:build windows

package desktopnetwork

import "sync"

func networkContextNativeObserver() (nativeObserver, *sync.Mutex, bool) {
	native := &windowsObserver{}
	return native, &native.mu, true
}
