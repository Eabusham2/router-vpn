//go:build windows

package main

import (
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

// The notification stays inside the updater's original-user Job. It never
// resolves an interpreter from PATH or starts an unowned notification child.
// Closing the owning app also retires a notification that the user left open.
func notifyDesktopUpdate(title, message string) {
	if len(title) == 0 || len(title) > 256 || len(message) == 0 || len(message) > 2048 {
		return
	}
	caption, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	text, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return
	}
	system, err := windowscontroller.SystemDirectory()
	if err != nil {
		return
	}
	library, err := syscall.LoadDLL(filepath.Join(system, "user32.dll"))
	if err != nil {
		return
	}
	defer library.Release()
	messageBox, err := library.FindProc("MessageBoxW")
	if err != nil {
		return
	}
	_, _, _ = messageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), 0x40 /* MB_OK | MB_ICONINFORMATION */)
	runtime.KeepAlive(text)
	runtime.KeepAlive(caption)
}
