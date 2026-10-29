//go:build linux || darwin

package main

import (
	"encoding/binary"
	"errors"
)

// Darwin ACL grants are independent of Unix mode bits. Decode the bounded
// ATTR_CMN_EXTENDED_SECURITY result, retaining ordinary read and deny-only
// system ACLs while refusing any extra mutation authority, including inherited
// grants. Apple defines this layout in bsd/sys/kauth.h and packs it in
// bsd/vfs/vfs_attrlist.c; both supported Mac architectures are little endian.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h
func validateOwnedDarwinACL(data []byte, private bool) error {
	invalid := errors.New("the privileged path has an invalid native ACL readback")
	if len(data) < 12 {
		return invalid
	}
	total := uint64(binary.LittleEndian.Uint32(data[:4]))
	start := int64(4) + int64(int32(binary.LittleEndian.Uint32(data[4:8])))
	length := uint64(binary.LittleEndian.Uint32(data[8:12]))
	if total < 12 || total > uint64(len(data)) || start < 12 || uint64(start) > total || length > total-uint64(start) {
		return invalid
	}
	if length == 0 {
		return nil
	}
	security := data[start : uint64(start)+length]
	if length < 44 || binary.LittleEndian.Uint32(security[:4]) != 0x012cc16d {
		return invalid
	}
	count := uint64(binary.LittleEndian.Uint32(security[36:40]))
	if count == 0xffffffff {
		if length == 44 {
			return nil
		}
		return invalid
	}
	if count > 128 || length != 44+24*count {
		return invalid
	}
	const readOnlyRights uint32 = 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20 | 1<<22 | 1<<24
	for index := uint64(0); index < count; index++ {
		entry := security[44+index*24 : 44+(index+1)*24]
		kind := binary.LittleEndian.Uint32(entry[16:20]) & 0xf
		rights := binary.LittleEndian.Uint32(entry[20:24])
		switch kind {
		case 1: // KAUTH_ACE_PERMIT
			if rights & ^readOnlyRights != 0 || private && rights != 0 {
				return errors.New("the privileged path ACL grants mutation authority beyond its Unix permissions")
			}
		case 2: // KAUTH_ACE_DENY cannot grant another principal authority.
		default:
			return invalid
		}
	}
	return nil
}
