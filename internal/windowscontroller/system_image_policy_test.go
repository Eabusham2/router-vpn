package windowscontroller

import (
	"encoding/binary"
	"testing"
)

func systemImagePolicySID(parts ...uint32) []byte {
	sid := make([]byte, 8+4*len(parts))
	sid[0], sid[1], sid[7] = 1, byte(len(parts)), 5
	for index, value := range parts {
		binary.LittleEndian.PutUint32(sid[8+index*4:], value)
	}
	return sid
}

func systemImagePolicyACE(kind, flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0], ace[1] = kind, flags
	binary.LittleEndian.PutUint16(ace[2:], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:], mask)
	copy(ace[8:], sid)
	return ace
}

func systemImagePolicyDescriptor(owner []byte, entries ...[]byte) []byte {
	acl := make([]byte, 8)
	acl[0] = 2
	for _, entry := range entries {
		acl = append(acl, entry...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(entries)))
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:], 0x8004)
	binary.LittleEndian.PutUint32(descriptor[4:], 20)
	binary.LittleEndian.PutUint32(descriptor[16:], uint32(20+len(owner)))
	return append(append(descriptor, owner...), acl...)
}

// This exact production parser also runs on the local non-Windows test host.
// The native gate separately supplies descriptors read from retained Windows
// objects, plus the actual OS PowerShell image and its suspended child.
func TestWindowsControllerGUISystemImageDescriptorPolicy(t *testing.T) {
	system := systemImagePolicySID(18)
	administrators := systemImagePolicySID(32, 544)
	installer := systemImagePolicySID(80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464)
	user := systemImagePolicySID(21, 1, 2, 3, 1001)
	read := systemImagePolicyACE(0, 0, 0x001200a9, user)
	for _, owner := range [][]byte{system, administrators, installer} {
		for _, entries := range [][][]byte{
			nil,
			{read},
			{read, systemImagePolicyACE(0, 0, 0x10000000, owner)},
			{read, systemImagePolicyACE(0, 0x08, 0x10000000, user)},
			{systemImagePolicyACE(1, 0, 0x10000000, user), read},
			{systemImagePolicyACE(0, 0x10, 0xa0000000, user)},
		} {
			if err := validateSystemImageDescriptor(systemImagePolicyDescriptor(owner, entries...)); err != nil {
				t.Fatal("trusted system owner with read-only ordinary access was rejected:", err)
			}
		}
	}
	if err := validateSystemImageDescriptor(systemImagePolicyDescriptor(user, read)); err == nil {
		t.Fatal("untrusted image owner acquired system policy")
	}
	// Each mutating/unknown right is independently rejected even with a
	// preceding denial. No ACL order or read grant masks a dangerous allow.
	for _, mask := range []uint32{2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x01000000, 0x02000000, 0x400} {
		for _, flags := range []byte{0, 0x10} {
			entries := [][]byte{systemImagePolicyACE(1, 0, 0x10000000, user), read, systemImagePolicyACE(0, flags, mask, user)}
			if err := validateSystemImageDescriptor(systemImagePolicyDescriptor(system, entries...)); err == nil {
				t.Fatalf("untrusted image writer acquired system policy: mask=0x%x flags=0x%x", mask, flags)
			}
		}
	}
	base := systemImagePolicyDescriptor(installer, read)
	dacl := int(binary.LittleEndian.Uint32(base[16:20]))
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated-header":    func(b []byte) []byte { return b[:19] },
		"absolute":            func(b []byte) []byte { b[3] &^= 0x80; return b },
		"absent-dacl":         func(b []byte) []byte { b[2] &^= 4; return b },
		"null-dacl":           func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:], 0); return b },
		"descriptor-revision": func(b []byte) []byte { b[0] = 2; return b },
		"null-owner":          func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 0); return b },
		"unbounded-owner":     func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 0xfffffffc); return b },
		"owner-sid-revision":  func(b []byte) []byte { b[20] = 2; return b },
		"owner-sid-count":     func(b []byte) []byte { b[21] = 16; return b },
		"owner-sid-authority": func(b []byte) []byte { b[27] = 6; return b },
		"similar-service-sid": func(b []byte) []byte { b[28] = 81; return b },
		"truncated-acl":       func(b []byte) []byte { return b[:len(b)-4] },
		"acl-revision":        func(b []byte) []byte { b[dacl] = 1; return b },
		"unbounded-acl-count": func(b []byte) []byte { binary.LittleEndian.PutUint16(b[dacl+4:], 0xffff); return b },
		"null-ace-size":       func(b []byte) []byte { binary.LittleEndian.PutUint16(b[dacl+10:], 0); return b },
		"unbounded-ace-size":  func(b []byte) []byte { binary.LittleEndian.PutUint16(b[dacl+10:], 0xfffc); return b },
		"object-allow":        func(b []byte) []byte { b[dacl+8] = 5; return b },
		"callback-allow":      func(b []byte) []byte { b[dacl+8] = 9; return b },
		"unknown-flags":       func(b []byte) []byte { b[dacl+9] = 0x80; return b },
		"ace-sid-revision":    func(b []byte) []byte { b[dacl+16] = 2; return b },
		"ace-sid-count":       func(b []byte) []byte { b[dacl+17] = 16; return b },
		"trailing-ace-data":   func(b []byte) []byte { b[dacl+17]--; return b },
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSystemImageDescriptor(mutate(append([]byte(nil), base...))); err == nil {
				t.Fatal("malformed system image protection was admitted")
			}
		})
	}
}
