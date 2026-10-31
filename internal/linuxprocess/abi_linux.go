//go:build linux

package linuxprocess

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// The native x64 and ARM64 delivery targets use the documented Linux UAPI.
// syscall.Getsockname discards addrlen and represents an unnamed AF_UNIX pair
// as "@", which cannot distinguish it from an abstract name. Retain the real
// native length instead: an unnamed pair must contain only sa_family_t.
func capturedPairAddress(fd uintptr, peer bool) (bool, error) {
	var call uintptr
	switch runtime.GOARCH {
	case "amd64":
		call = 51 // asm/unistd_64.h: __NR_getsockname
	case "arm64":
		call = 204 // asm-generic/unistd.h: __NR_getsockname
	default:
		return false, errors.New("Linux child native socket ABI has not been proved for this architecture")
	}
	if peer {
		call++ // __NR_getpeername follows getsockname on both targets.
	}
	var address syscall.RawSockaddrUnix
	length := uint32(unsafe.Sizeof(address))
	_, _, errno := syscall.Syscall(call, fd, uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&length)))
	if errno != 0 {
		return false, errno
	}
	minimum := uint32(unsafe.Sizeof(address.Family))
	if length < minimum || length > uint32(unsafe.Sizeof(address)) || address.Family != syscall.AF_UNIX || (length > minimum && address.Path[0] != 0) {
		return false, errors.New("Linux child channel changed its captured native family or uses a pathname")
	}
	// SO_PASSCRED can autobind a socketpair to an abstract address on its
	// first send. That name is never resolved or used as authority. Only the
	// creating parent requires both initial native lengths to be unnamed.
	return length == minimum, nil
}

// Open only the current numeric descriptor beneath the original captured
// parent's fdinfo directory. NO_XDEV forbids a later bind mount over this
// kernel entry; NO_SYMLINKS and BENEATH prohibit redirection. Kernels without
// openat2 cannot supply this native proof and fail without a weaker fallback.
func openRetainedFDInfo(directory *os.File, descriptor uintptr) (*os.File, error) {
	if directory == nil || descriptor > 1<<31-1 || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return nil, errors.New("Linux child lost its original fdinfo directory or proved native ABI")
	}
	name, err := syscall.BytePtrFromString(strconv.FormatUint(uint64(descriptor), 10))
	if err != nil {
		return nil, err
	}
	type openHow struct{ Flags, Mode, Resolve uint64 }
	how := openHow{Flags: syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW, Resolve: 0x01 | 0x04 | 0x08}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd uintptr
	var errno syscall.Errno
	err = raw.Control(func(original uintptr) {
		fd, _, errno = syscall.Syscall6(437, original, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	})
	if err != nil || errno != 0 {
		if errno != 0 {
			return nil, errors.Join(err, errno)
		}
		return nil, err
	}
	return os.NewFile(fd, "original-linux-parent-pidfd-info"), nil
}
