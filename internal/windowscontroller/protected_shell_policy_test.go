package windowscontroller

import "testing"

func TestWindowsControllerFoundationProtectedShellDescriptor(t *testing.T) {
	system, user := systemImagePolicySID(18), systemImagePolicySID(21, 1, 2, 3, 1001)
	for _, directory := range []bool{false, true} {
		read := uint32(0x00120001)
		if directory {
			read |= 2
		}
		for _, owner := range [][]byte{system, systemImagePolicySID(32, 544)} {
			descriptor := systemImagePolicyDescriptor(owner,
				systemImagePolicyACE(0, 0, read, user), systemImagePolicyACE(0, 0, 0x10000000, owner))
			if err := validateProtectedShellDescriptor(descriptor, directory); err != nil {
				t.Fatal("protected namespace rejected its exact read-only object rights", err)
			}
		}
		if err := validateProtectedShellDescriptor(systemImagePolicyDescriptor(user), directory); err == nil {
			t.Fatal("untrusted namespace owner acquired a protected Shell capability")
		}
		// Include file-like rights which have different meanings for kernel
		// directory/link objects, plus every generic and administrative grant.
		for bit := uint32(1); bit != 0; bit <<= 1 {
			if bit&read != 0 {
				continue
			}
			descriptor := systemImagePolicyDescriptor(system,
				systemImagePolicyACE(1, 0, bit, user), systemImagePolicyACE(0, 0, bit, user))
			if err := validateProtectedShellDescriptor(descriptor, directory); err == nil {
				t.Fatalf("untrusted namespace mutation right acquired a protected Shell capability: directory=%t mask=0x%x", directory, bit)
			}
		}
	}
}
