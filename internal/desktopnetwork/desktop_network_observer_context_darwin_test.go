//go:build darwin

package desktopnetwork

import "sync"

func networkContextNativeObserver() (nativeObserver, *sync.Mutex, bool) {
	native := &darwinObserver{}
	return native, &native.mu, false
}
