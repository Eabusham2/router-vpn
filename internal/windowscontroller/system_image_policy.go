package windowscontroller

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Windows self-relative SECURITY_DESCRIPTOR, ACL, ACE and SID layouts have
// fixed-width fields on both supported architectures. This validator accepts
// only explicit effective grants it can prove safe. Denials cannot turn an
// unsafe grant into an accepted policy, and unknown ACE types fail closed.
func validateSystemImageDescriptor(data []byte) error {
	// File read data/EA/attributes, execute/traverse, READ_CONTROL and
	// SYNCHRONIZE, plus GENERIC_READ/EXECUTE, cannot mutate the image.
	return validateSystemObjectDescriptor(data, 0xa01200a9)
}

func validateSystemObjectDescriptor(data []byte, readOnlyRights uint32) error {
	if len(data) < 20 || data[0] != 1 || binary.LittleEndian.Uint16(data[2:4])&0x8004 != 0x8004 {
		return errors.New("Windows system image requires a self-relative descriptor with an explicit DACL")
	}
	owner := binary.LittleEndian.Uint32(data[4:8])
	if owner < 20 || owner%4 != 0 {
		return errors.New("Windows system image has no bounded owner")
	}
	sid, _, err := systemImageSID(data, int(owner))
	if err != nil || !trustedSystemImageSID(sid) {
		return errors.Join(err, errors.New("Windows system image owner is not a trusted OS principal"))
	}
	dacl := int(binary.LittleEndian.Uint32(data[16:20]))
	if dacl < 20 || dacl%4 != 0 || dacl > len(data)-8 {
		return errors.New("Windows system image has no bounded non-null DACL")
	}
	acl := data[dacl:]
	size, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
	if (acl[0] != 2 && acl[0] != 4) || size < 8 || size > len(acl) || size%4 != 0 || count > (size-8)/4 {
		return errors.New("Windows system image DACL is malformed")
	}
	acl = acl[:size]
	offset := 8
	for index := 0; index < count; index++ {
		if offset > len(acl)-8 {
			return errors.New("Windows system image ACE header is truncated")
		}
		ace := acl[offset:]
		length := int(binary.LittleEndian.Uint16(ace[2:4]))
		if length < 16 || length > len(ace) || length%4 != 0 || (ace[0] != 0 && ace[0] != 1) || ace[1]&^byte(0x1f) != 0 {
			return errors.New("Windows system image has an unsupported or malformed DACL entry")
		}
		ace = ace[:length]
		principal, sidLength, err := systemImageSID(ace, 8)
		if err != nil || sidLength != length-8 {
			return errors.Join(err, errors.New("Windows system image DACL entry has an invalid principal"))
		}
		// The caller supplies the exact object-type read rights. Every other
		// bit requires one of the same trusted principals as ownership.
		mask := binary.LittleEndian.Uint32(ace[4:8])
		if ace[0] == 0 && ace[1]&0x08 == 0 && mask & ^readOnlyRights != 0 && !trustedSystemImageSID(principal) {
			return fmt.Errorf("Windows system image permits an untrusted writer (ACE %d, mask 0x%08x)", index, mask)
		}
		offset += length
	}
	return nil
}

type systemImagePrincipal struct {
	authority uint64
	parts     []uint32
}

func systemImageSID(data []byte, offset int) (systemImagePrincipal, int, error) {
	if offset < 0 || offset > len(data)-8 || data[offset] != 1 || data[offset+1] > 15 {
		return systemImagePrincipal{}, 0, errors.New("Windows system image SID is malformed")
	}
	count := int(data[offset+1])
	length := 8 + count*4
	if length > len(data)-offset {
		return systemImagePrincipal{}, 0, errors.New("Windows system image SID is truncated")
	}
	var principal systemImagePrincipal
	for _, value := range data[offset+2 : offset+8] {
		principal.authority = principal.authority<<8 | uint64(value)
	}
	principal.parts = make([]uint32, count)
	for index := range principal.parts {
		principal.parts[index] = binary.LittleEndian.Uint32(data[offset+8+index*4:])
	}
	return principal, length, nil
}

func trustedSystemImageSID(sid systemImagePrincipal) bool {
	if sid.authority != 5 {
		return false
	}
	if len(sid.parts) == 1 && sid.parts[0] == 18 { // LocalSystem.
		return true
	}
	if len(sid.parts) == 2 && sid.parts[0] == 32 && sid.parts[1] == 544 { // Builtin Administrators.
		return true
	}
	// NT SERVICE\TrustedInstaller has a deterministic service SID, independent
	// of the display language, local account database and current logon user.
	trustedInstaller := [...]uint32{80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464}
	if len(sid.parts) != len(trustedInstaller) {
		return false
	}
	for index, value := range trustedInstaller {
		if sid.parts[index] != value {
			return false
		}
	}
	return true
}
