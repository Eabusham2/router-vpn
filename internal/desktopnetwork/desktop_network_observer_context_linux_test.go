//go:build linux

package desktopnetwork

import "sync"

func networkContextNativeObserver() (nativeObserver, *sync.Mutex, bool) {
	native := &linuxObserver{}
	return native, &native.mu, false
}
