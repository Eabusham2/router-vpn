package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

func nativeDarwinMultihopCommand(a *app, sel multihopSelection) (*exec.Cmd, error) {
	if _, err := verifyBundledNative(desktopAmneziaPackageRoot()); err != nil {
		return nil, err
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	runtimeDir, tunAlias, err := prepareNativeMultihop(root, sel)
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(root, "modes", "native-multihop-darwin.sh")
	if _, err = os.Stat(helper); err != nil {
		helper = filepath.Join(a.cfg.ScriptsDir, "native-multihop-darwin.sh")
	}
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		return nil, errors.New("native macOS multihop helper is missing")
	}
	cmd := exec.Command("bash", helper, "up", runtimeDir, sel.Native.endpoint, tunAlias)
	cmd.Dir = root
	cmd.Env = nativeMultihopEnvironment(root, sel)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
