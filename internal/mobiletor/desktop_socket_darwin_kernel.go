//go:build darwin

package mobiletor

import (
	"errors"
	"os"
	"syscall"
)

// The opaque libproc handles describe the retained socket and PCB, rather
// than a numeric descriptor or a tuple that can be reused. XNU derives them
// from the kernel objects in bsd/kern/socket_info.c. The UID is independently
// read with fstat: XNU's soo_stat obtains it from the original socket so_cred.
type desktopDarwinKernelSocket struct {
	socket, pcb, generation uint64
	uid                     uint32
	family                  int
	network                 string
}

func desktopDarwinSocketIdentity(file *os.File) (desktopDarwinKernelSocket, error) {
	if file == nil {
		return desktopDarwinKernelSocket{}, errors.New("Darwin physical socket descriptor is missing")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return desktopDarwinKernelSocket{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return desktopDarwinKernelSocket{}, errors.New("Darwin physical descriptor is not a kernel socket")
	}
	identity, err := desktopDarwinReadSocket(int(file.Fd()))
	if err != nil {
		return desktopDarwinKernelSocket{}, err
	}
	identity.uid = stat.Uid
	return identity, nil
}

func desktopDarwinBoundInterface(fd int, family int) (uint32, error) {
	level, option := syscall.IPPROTO_IP, 25 // IP_BOUND_IF
	if family == syscall.AF_INET6 {
		level, option = syscall.IPPROTO_IPV6, 125 // IPV6_BOUND_IF
	} else if family != syscall.AF_INET {
		return 0, errors.New("Darwin physical binding has another socket family")
	}
	index, err := syscall.GetsockoptInt(fd, level, option)
	if err != nil || index <= 0 {
		return 0, errors.Join(err, errors.New("Darwin physical socket has no bound interface"))
	}
	return uint32(index), nil
}

func desktopDarwinBindInterface(fd int, family int, index uint32) error {
	if index == 0 || index > 0x7fffffff {
		return errors.New("Darwin physical interface index is invalid")
	}
	level, option := syscall.IPPROTO_IP, 25
	if family == syscall.AF_INET6 {
		level, option = syscall.IPPROTO_IPV6, 125
	} else if family != syscall.AF_INET {
		return errors.New("Darwin physical binding has another socket family")
	}
	if err := syscall.SetsockoptInt(fd, level, option, int(index)); err != nil {
		return err
	}
	actual, err := desktopDarwinBoundInterface(fd, family)
	if err != nil || actual != index {
		return errors.Join(err, errors.New("Darwin physical interface did not read back"))
	}
	return nil
}
