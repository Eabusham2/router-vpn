//go:build windows

package hopmeasure

import (
	"sync"
	"syscall"
	"unsafe"
)

var nativeMeasurementClock struct {
	sync.Once
	counter   *syscall.LazyProc
	frequency int64
	err       error
}

func readMeasurementClock() (measurementInstant, error) {
	nativeMeasurementClock.Do(func() {
		// kernel32 is a Windows KnownDLL, also on Go's system-DLL allowlist.
		// Do not use PATH, SystemRoot or the portable working directory.
		kernel := syscall.NewLazyDLL("kernel32.dll")
		frequency := kernel.NewProc("QueryPerformanceFrequency")
		counter := kernel.NewProc("QueryPerformanceCounter")
		if frequency.Find() != nil || counter.Find() != nil {
			nativeMeasurementClock.err = errMeasurementClock
			return
		}
		var ticksPerSecond int64
		ok, _, _ := frequency.Call(uintptr(unsafe.Pointer(&ticksPerSecond)))
		if ok == 0 || ticksPerSecond <= 0 {
			nativeMeasurementClock.err = errMeasurementClock
			return
		}
		nativeMeasurementClock.counter, nativeMeasurementClock.frequency = counter, ticksPerSecond
	})
	if nativeMeasurementClock.err != nil || nativeMeasurementClock.counter == nil {
		return measurementInstant{}, errMeasurementClock
	}
	var ticks int64
	ok, _, _ := nativeMeasurementClock.counter.Call(uintptr(unsafe.Pointer(&ticks)))
	if ok == 0 || ticks < 0 {
		return measurementInstant{}, errMeasurementClock
	}
	return measurementInstant{ticks: ticks, frequency: nativeMeasurementClock.frequency}, nil
}
