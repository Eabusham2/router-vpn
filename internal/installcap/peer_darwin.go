//go:build darwin

package installcap

import (
	"errors"
	"syscall"
	"unsafe"
)

func checkPeer(fd, expected int) error {
	var info syscall.Stat_t
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || kind != syscall.SOCK_STREAM || syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFSOCK || info.Uid != 0 {
		return errors.New("installer channel is not its anonymous root-created stream")
	}
	for _, query := range []func(int) (syscall.Sockaddr, error){syscall.Getsockname, syscall.Getpeername} {
		address, err := query(fd)
		local, ok := address.(*syscall.SockaddrUnix)
		if err != nil || !ok || local.Name != "" {
			return errors.New("installer channel is named or disconnected")
		}
	}
	var credential struct {
		Version uint32
		UID     uint32
		Groups  int16
		Padding uint16
		GIDs    [16]uint32
	}
	size := uint32(unsafe.Sizeof(credential))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), 0, 1,
		uintptr(unsafe.Pointer(&credential)), uintptr(unsafe.Pointer(&size)), 0)
	pid, err := syscall.GetsockoptInt(fd, 0, 2)
	if errno != 0 || size != 76 || credential.Version != 0 || credential.UID != 0 || credential.Groups < 1 || credential.Groups > 16 || err != nil || pid != expected {
		return errors.New("installer channel has another original kernel peer")
	}
	return nil
}
