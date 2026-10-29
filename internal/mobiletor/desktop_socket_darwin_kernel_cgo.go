//go:build darwin && cgo

package mobiletor

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <unistd.h>

static int routervpn_darwin_socket(int fd, uint64_t *socket, uint64_t *pcb,
    uint64_t *generation, int *family, int *type) {
    struct socket_fdinfo value;
    memset(&value, 0, sizeof(value));
    int count = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO,
                             &value, sizeof(value));
    if (count != sizeof(value)) return errno ? errno : EIO;
    if ((value.psi.soi_family != AF_INET && value.psi.soi_family != AF_INET6) ||
        (value.psi.soi_kind != SOCKINFO_IN && value.psi.soi_kind != SOCKINFO_TCP) ||
        value.psi.soi_so == 0 || value.psi.soi_pcb == 0) return EINVAL;
    if ((value.psi.soi_type == SOCK_STREAM &&
         (value.psi.soi_kind != SOCKINFO_TCP || value.psi.soi_protocol != IPPROTO_TCP)) ||
        (value.psi.soi_type == SOCK_DGRAM &&
         (value.psi.soi_kind != SOCKINFO_IN || value.psi.soi_protocol != IPPROTO_UDP)) ||
        (value.psi.soi_type != SOCK_STREAM && value.psi.soi_type != SOCK_DGRAM)) return EINVAL;
    *socket = value.psi.soi_so;
    *pcb = value.psi.soi_pcb;
    *generation = value.psi.soi_proto.pri_in.insi_gencnt;
    *family = value.psi.soi_family;
    *type = value.psi.soi_type;
    return 0;
}

static int routervpn_darwin_tunnel(int fd, char *name, uint32_t size) {
    struct socket_fdinfo value;
    memset(&value, 0, sizeof(value));
    int count = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &value, sizeof(value));
    if (count != sizeof(value)) return errno ? errno : EIO;
    if (value.psi.soi_family != AF_SYSTEM || value.psi.soi_type != SOCK_DGRAM ||
        value.psi.soi_kind != SOCKINFO_KERN_CTL || value.psi.soi_so == 0 ||
        strcmp(value.psi.soi_proto.pri_kern_ctl.kcsi_name, "com.apple.net.utun_control") != 0) return EINVAL;
    socklen_t length = size;
    // UTUN_OPT_IFNAME is the documented control option number 2.
    if (getsockopt(fd, SYSPROTO_CONTROL, 2, name, &length) != 0) return errno;
    if (length < 5 || length > size || name[length-1] != '\0') return EINVAL;
    return 0;
}

// Query the actual system user namespace, including configured directory
// services. A local Directory Services search alone cannot exclude a remote
// record with the same UID. Any lookup error is an unknown, occupied identity.
static int routervpn_darwin_uid_exists(uint32_t uid) {
    char buffer[65536];
    struct passwd value, *found = NULL;
    int result = getpwuid_r((uid_t)uid, &value, buffer, sizeof(buffer), &found);
    if (result != 0) return -result;
    return found != NULL;
}

static int routervpn_darwin_uid_account(uint32_t uid, const char *name) {
    char buffer[65536];
    struct passwd value, *found = NULL;
    int result = getpwuid_r((uid_t)uid, &value, buffer, sizeof(buffer), &found);
    return result == 0 && found != NULL && found->pw_name != NULL &&
           strcmp(found->pw_name, name) == 0;
}

static int routervpn_darwin_uid_processes(uint32_t uid) {
    const uint32_t kinds[] = { PROC_UID_ONLY, PROC_RUID_ONLY };
    for (int which = 0; which < 2; which++) {
        int count = proc_listpids(kinds[which], uid, NULL, 0);
        if (count < 0) return -1;
        if (count == 0) continue;
        // The count includes spare capacity on some versions. Inspect actual
        // returned positive PIDs instead of equating buffer size with a match.
        if (count > 1024 * 1024) return -1;
        pid_t *pids = calloc(1, (size_t)count + 1024);
        if (pids == NULL) return -1;
        int size = proc_listpids(kinds[which], uid, pids, count + 1024);
        if (size < 0 || size >= count + 1024 || size % sizeof(pid_t) != 0) {
            free(pids); return -1;
        }
        for (int i = 0; i < size / sizeof(pid_t); i++) {
            if (pids[i] > 0) { free(pids); return 1; }
        }
        free(pids);
    }
    return 0;
}
*/
import "C"

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func desktopDarwinReadSocket(fd int) (desktopDarwinKernelSocket, error) {
	var socket, pcb, generation C.uint64_t
	var family, kind C.int
	code := C.routervpn_darwin_socket(C.int(fd), &socket, &pcb, &generation, &family, &kind)
	if code != 0 {
		return desktopDarwinKernelSocket{}, syscall.Errno(code)
	}
	network := "tcp"
	if int(kind) == syscall.SOCK_DGRAM {
		network = "udp"
	}
	return desktopDarwinKernelSocket{socket: uint64(socket), pcb: uint64(pcb), generation: uint64(generation), family: int(family), network: network}, nil
}

func desktopDarwinUIDAvailable(uid uint32) bool {
	return C.routervpn_darwin_uid_exists(C.uint32_t(uid)) == 0
}

func desktopDarwinUIDAccount(uid uint32, account string) bool {
	name := C.CString(account)
	defer C.free(unsafe.Pointer(name))
	return C.routervpn_darwin_uid_account(C.uint32_t(uid), name) == 1
}

func desktopDarwinNoUIDProcesses(uid uint32) error {
	if C.routervpn_darwin_uid_processes(C.uint32_t(uid)) != 0 {
		return errors.New("Darwin physical creator identity has a live or unobserved process")
	}
	return nil
}

func desktopDarwinKernelAvailable() bool { return true }

func desktopDarwinReadTunnel(file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("Darwin tunnel control descriptor is missing")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return "", err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != 0 {
		return "", errors.New("Darwin tunnel control has another kernel creator")
	}
	var name [64]C.char
	code := C.routervpn_darwin_tunnel(C.int(file.Fd()), &name[0], C.uint32_t(len(name)))
	if code != 0 {
		return "", syscall.Errno(code)
	}
	return C.GoString(&name[0]), nil
}
