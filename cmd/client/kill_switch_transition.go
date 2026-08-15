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
	env = envWithValue(env, "HOMEVPN_ROOT", filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client")))
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
