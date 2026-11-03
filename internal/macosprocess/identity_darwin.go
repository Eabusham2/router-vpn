//go:build darwin

package macosprocess

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Public XNU PROC_PIDTBSDINFO/PROC_PIDUNIQIDENTIFIERINFO and csops_audittoken.
// As in the installer, token PID/idversion is a kernel comparison fence;
// caller-filled token fields are not claimed as credential authentication.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master
type nativeBSD struct {
	Flags, Status, XStatus, PID, PPID, UID, GID, RUID, RGID, SVUID, SVGID, Reserved uint32
	Comm                                                                            [16]byte
	Name                                                                            [32]byte
	Files, PGID, Job, Device, TPGID                                                 uint32
	Nice                                                                            int32
	StartSeconds, StartMicroseconds                                                 uint64
}
type nativeUnique struct {
	UUID                   [16]byte
	ID, ParentID           uint64
	Version, ParentVersion int32
	Reserved               [2]uint64
}

func readProcessInfo(pid, flavor int, buffer unsafe.Pointer, size uintptr) error {
	count, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, 2, uintptr(pid), uintptr(flavor), 1, uintptr(buffer), size)
	if errno != 0 {
		return errno
	}
	if count != size {
		return errors.New("native process information has an incomplete ABI result")
	}
	return nil
}

func CaptureIdentity(pid int) (Identity, error) {
	var identity Identity
	if pid <= 1 || pid >= 1<<31 || unsafe.Sizeof(nativeBSD{}) != 136 || unsafe.Offsetof(nativeBSD{}.StartSeconds) != 120 || unsafe.Sizeof(nativeUnique{}) != 56 || unsafe.Offsetof(nativeUnique{}.Version) != 32 {
		return identity, errors.New("native main-image identity has no valid PID or public ABI")
	}
	var before, after nativeBSD
	var generation, last nativeUnique
	if err := readProcessInfo(pid, 3, unsafe.Pointer(&before), unsafe.Sizeof(before)); err != nil {
		return identity, err
	}
	if before.PID != uint32(pid) || before.Status < 1 || before.Status >= 5 || before.StartSeconds == 0 || before.StartMicroseconds >= 1000000 {
		return identity, errors.New("native child is not the same live process")
	}
	if err := readProcessInfo(pid, 17, unsafe.Pointer(&generation), unsafe.Sizeof(generation)); err != nil {
		return identity, err
	}
	if generation.ID == 0 || generation.Version <= 0 {
		return identity, errors.New("native child has no actual exec generation")
	}
	token := [8]uint32{}
	token[5], token[7] = uint32(pid), uint32(generation.Version)
	var digest [20]byte
	_, _, errno := syscall.Syscall6(170 /* csops_audittoken */, uintptr(pid), 5 /* CS_OPS_CDHASH */, uintptr(unsafe.Pointer(&digest)), uintptr(len(digest)), uintptr(unsafe.Pointer(&token)), 0)
	runtime.KeepAlive(token)
	runtime.KeepAlive(digest)
	if err := readProcessInfo(pid, 17, unsafe.Pointer(&last), unsafe.Sizeof(last)); err != nil {
		return identity, err
	}
	if err := readProcessInfo(pid, 3, unsafe.Pointer(&after), unsafe.Sizeof(after)); err != nil {
		return identity, err
	}
	if generation != last || before.PID != after.PID || before.StartSeconds != after.StartSeconds || before.StartMicroseconds != after.StartMicroseconds || after.Status < 1 || after.Status >= 5 {
		return identity, errors.New("native child changed its process or executable during capture")
	}
	// An unavailable CodeDirectory never admits an owned native child. The
	// installer's foreign-UUID exclusion has no role in child authentication.
	if errno != 0 {
		return identity, errno
	}
	identity = Identity{pid, before.StartSeconds, before.StartMicroseconds, generation.ID, generation.Version, generation.UUID, digest}
	if !identity.Valid() {
		return Identity{}, errors.New("native child has an empty main-image signature")
	}
	return identity, nil
}
