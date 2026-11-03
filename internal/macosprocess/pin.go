package macosprocess

import "os"

type pinMetadata struct {
	mode     os.FileMode
	uid, gid uint32
	links    uint64
}

// XNU soo_stat reports socket read/write readiness in the permission bits:
// bsd/kern/sys_socket.c, soo_stat. Those bits are not a pathname access mode.
// Only the fixed inherited GUI descriptor uses this class. Its root socket
// credentials remain stable; capture separately proves LOCAL_PEERCRED/PID,
// stream type, accepted local address and the original retained descriptor.
func samePinMetadata(before, after pinMetadata, guiSocket bool) bool {
	if after.uid != 0 || before.uid != after.uid || before.gid != after.gid || before.links != after.links {
		return false
	}
	if guiSocket {
		return before.mode&^os.FileMode(0666) == os.ModeSocket && after.mode&^os.FileMode(0666) == os.ModeSocket
	}
	return before.mode == after.mode && after.mode.Perm()&0022 == 0
}
