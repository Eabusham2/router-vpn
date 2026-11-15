//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"github.com/sagernet/sing-box/routervpn/windowscontroller"
	"os"
)

// Explicit Windows fixture boundary; the security checks are shipping bodies.
func windowsCONNECTExecutionWorkerEnvironment() ([]string, error) {
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	return []string{"SystemRoot=" + paths.Windows, "WINDIR=" + paths.Windows, "PATH=" + paths.System, "GORACE=atexit_sleep_ms=0"}, nil
}

func windowsCONNECTExecutionCodePermissions(file *os.File, info os.FileInfo) error {
	if err := windowsRuntimeObjectUnchanged(file, info); err != nil {
		return err
	}
	user, err := windowsRuntimeCurrentUser()
	if err != nil {
		return err
	}
	security, err := windowsRuntimeInspectSecurity(file)
	if err != nil {
		return err
	}
	defer security.close()
	if err := windowsRuntimeValidateCodeSecurity(security, user); err != nil {
		return err
	}
	return windowsRuntimeObjectUnchanged(file, info)
}
