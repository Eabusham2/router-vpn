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
//
// A directory's link count can change when its owned children change (including
// ordinary file entries on APFS). It is not the immutable hard-link count of a
// captured regular file. Directories must remain linked, with the same exact
// type/permissions/owner; checkPin separately revalidates their original inode,
// named path and ACL on every observation.
func samePinMetadata(before, after pinMetadata, guiSocket, directory bool) bool {
	if after.uid != 0 || before.uid != after.uid || before.gid != after.gid {
		return false
	}
	if guiSocket {
		return !directory && before.links == after.links &&
			before.mode&^os.FileMode(0666) == os.ModeSocket && after.mode&^os.FileMode(0666) == os.ModeSocket
	}
	if before.mode != after.mode || after.mode.Perm()&0022 != 0 {
		return false
	}
	if directory {
		return before.mode.Type() == os.ModeDir && before.links > 0 && after.links > 0
	}
	return !before.mode.IsDir() && before.links == after.links
}
