package main

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

func windowsTorHostCompatibility() (string, error) {
	return windowsTorArchitecture(runtime.GOARCH, func() (bool, error) {
		// Microsoft documents GetMachineTypeAttributes (Windows build 22000+)
		// as the supported query for native OR emulated architecture execution.
		// Only UserEnabled matters: no x64 kernel driver is ever adopted.
		query := syscall.NewLazyDLL("kernel32.dll").NewProc("GetMachineTypeAttributes")
		if err := query.Find(); err != nil {
			return false, errors.New("GetMachineTypeAttributes is unavailable; Windows 11 is required")
		}
		var attributes uint32
		result, _, _ := query.Call(0x8664, uintptr(unsafe.Pointer(&attributes)))
		if result != 0 {
			return false, errors.New("GetMachineTypeAttributes failed")
		}
		return attributes&1 != 0, nil
	})
}
