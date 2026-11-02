package desktopnetwork

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestDarwinIncompleteInterfaceReadbackNeverAdmitsOrReplacesCapture(t *testing.T) {
	original := Link{Index: 5, Name: "private-interface-name", MTU: 0, Flags: 0, Hardware: "private-hardware"}
	for _, row := range []desktopDarwinInterfaceShape{{5, 0, 0, 1, 0, 0}, {5, 1500, 1, 6, 0, 6}, {6, 9000, 1, 6, 0, 6}} {
		calls := 0
		failure := desktopDarwinIncompleteInterface(original, func(index uint32) (desktopDarwinInterfaceReadback, error) {
			calls++
			if index != original.Index {
				t.Fatal("Darwin failure diagnostic replaced its captured index")
			}
			return desktopDarwinInterfaceReadback{Bytes: 112, Records: 1, Shapes: []desktopDarwinInterfaceShape{row}}, nil
		})
		if failure == nil || calls != 1 || !strings.Contains(failure.Error(), "index=5 luid=0 name_present=true mtu=0 flags=0") ||
			!strings.Contains(failure.Error(), "state=observed") || strings.Contains(failure.Error(), "private-") || original.MTU != 0 {
			t.Fatal("Darwin diagnostic admitted or replaced the captured invalid interface", failure)
		}
	}
	for _, nativeError := range []error{syscall.EPERM, errors.New("private-host-data")} {
		failure := desktopDarwinIncompleteInterface(original, func(uint32) (desktopDarwinInterfaceReadback, error) {
			return desktopDarwinInterfaceReadback{}, nativeError
		})
		if failure == nil || !strings.Contains(failure.Error(), "state=read-failed") || strings.Contains(failure.Error(), "private-") {
			t.Fatal("Darwin readback error leaked data or hid the original failure", failure)
		}
	}
	for _, observed := range []desktopDarwinInterfaceReadback{
		{Bytes: -1}, {Bytes: 1<<16 + 1}, {Records: 257}, {Records: -1}, {Records: 1, Addresses: 2},
		{Shapes: make([]desktopDarwinInterfaceShape, 5)},
	} {
		failure := desktopDarwinIncompleteInterface(original, func(uint32) (desktopDarwinInterfaceReadback, error) { return observed, nil })
		if failure == nil || !strings.Contains(failure.Error(), "state=out-of-bounds") || len(failure.Error()) > 600 {
			t.Fatal("Darwin failure diagnostic lost its output bound", failure)
		}
	}
	for _, index := range []uint32{0, 65536} {
		invalid := original
		invalid.Index = index
		failure := desktopDarwinIncompleteInterface(invalid, func(uint32) (desktopDarwinInterfaceReadback, error) {
			t.Fatal("invalid captured index triggered a broader native query")
			return desktopDarwinInterfaceReadback{}, nil
		})
		if failure == nil {
			t.Fatal("invalid captured index became success")
		}
	}
}
