//go:build windows && routervpn_windows_candidate_prefix_native

package mobiletor

// Compiled only by the installed prefix acceptance overlay. Both the actual
// controller and actual native child use the same immutable child image path.
// Production exposes no environment, profile, JSON or runtime scope selector.
import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const desktopWindowsPrefixFixtureImage = __CAPTURED_NATIVE_IMAGE__

func desktopWindowsPrefixFixtureScope() []byte {
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		panic(err)
	}
	held, err := os.Open(desktopWindowsPrefixFixtureImage)
	if err != nil {
		panic(err)
	}
	defer held.Close()
	info, err := held.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		panic("installed prefix fixture lost its original native image")
	}
	path, err := syscall.UTF16PtrFromString(desktopWindowsPrefixFixtureImage)
	if err != nil {
		panic(err)
	}
	var blob *desktopWindowsBlob
	status, _, _ := api.appID.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&blob)))
	if blob != nil {
		defer api.freeWFP.Call(uintptr(unsafe.Pointer(&blob)))
	}
	if status != 0 {
		panic(syscall.Errno(status))
	}
	if blob == nil || blob.Data == nil || blob.Size < 2 || blob.Size > 65536 || blob.Size%2 != 0 {
		panic(errors.New("installed prefix fixture has no bounded kernel AppID"))
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
}
