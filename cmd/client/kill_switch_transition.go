package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const killSwitchHoldEnv = "HOMEVPN_KILLSWITCH_HOLD"

func envWithValue(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func (a *app) stopCommandEnv(hold bool) []string {
	value := "0"
	if hold {
		value = "1"
	}
	return envWithValue(os.Environ(), killSwitchHoldEnv, value)
}

func (a *app) releaseTransitionKillSwitch() error {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	if runtime.GOOS == "windows" {
		helper := filepath.Join(root, "client", "windows-kill-switch.ps1")
		if st, err := os.Lstat(helper); err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			fallback := filepath.Join(filepath.Dir(a.cfg.ScriptsDir), "client", "windows-kill-switch.ps1")
			if fallbackState, fallbackErr := os.Lstat(fallback); fallbackErr != nil || fallbackState.Mode()&os.ModeSymlink != 0 || !fallbackState.Mode().IsRegular() {
				return fmt.Errorf("release held Windows kill switch: helper is missing or unsafe")
			}
			helper = fallback
		}
		powershell, err := safeExecutable("powershell.exe")
		if err != nil {
			return fmt.Errorf("release held Windows kill switch: %w", err)
		}
		cmd := exec.Command(powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper, "-Action", "release", "-Root", root)
		cmd.Dir = filepath.Dir(helper)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("release held Windows kill switch: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}
	a.mu.Lock()
	profileID := a.profiles.SelectedID
	a.mu.Unlock()
	helper := filepath.Join(a.cfg.ScriptsDir, "kill-switch-platform.py")
	cmd := exec.Command("python3", helper, "release")
	cmd.Dir = a.cfg.ScriptsDir
	env := envWithValue(os.Environ(), killSwitchHoldEnv, "0")
	env = envWithValue(env, "HOMEVPN_ROOT", root)
	// Release is intentionally independent of a currently selected profile: the
	// persisted kill-switch state is authoritative. This lets a restarted
	// controller clear a stale on-connect firewall even when its in-memory mode
	// is off or the formerly selected profile has since disappeared. When a
	// profile is selected, pass it only as extra context for platform helpers.
	if profileID != "" {
		env = envWithValue(env, "HOMEVPN_PROFILE_ID", profileID)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("release held kill switch: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
