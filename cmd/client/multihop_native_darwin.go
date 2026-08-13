package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

func nativeDarwinMultihopCommand(a *app, sel multihopSelection) (*exec.Cmd, error) {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	runtimeDir, tunAlias, err := prepareNativeMultihop(root, sel)
	if err != nil {
		return nil, err
	}
	helper := filepath.Join(root, "client", "native-multihop-darwin.sh")
	if _, err = os.Stat(helper); err != nil {
		helper = filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "native-multihop-darwin.sh")
	}
	if st, statErr := os.Stat(helper); statErr != nil || st.IsDir() {
		return nil, errors.New("native macOS multihop helper is missing")
	}
	cmd := exec.Command("bash", helper, "up", runtimeDir, sel.Entry.Endpoint, tunAlias)
	cmd.Dir = root
	cmd.Env = append(
		os.Environ(),
		"HOMEVPN_ROOT="+root,
		"HOMEVPN_PROFILE_ID="+sel.Entry.ID,
		"HOMEVPN_POLICY_PROFILE_ID="+sel.Control.ID,
		"HOMEVPN_ENDPOINT="+sel.Entry.Endpoint,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
