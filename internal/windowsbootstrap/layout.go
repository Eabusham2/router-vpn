package windowsbootstrap

import "strings"

// IsPortableLauncherName accepts the two fixed executables at the root of the
// ordinary Portable ZIP. Callers must separately prove the retained process,
// actual image, root-relative package and original desktop identity. A public
// filename alone never authorizes a controller or chooses private Data.
func IsPortableLauncherName(name string) bool {
	return strings.EqualFold(name, "RouterVPNPortable.exe") ||
		strings.EqualFold(name, "RouterVPNPortableCore.exe")
}
