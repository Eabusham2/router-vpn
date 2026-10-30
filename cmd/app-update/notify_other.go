//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

func notifyDesktopUpdate(title, message string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		script := "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
		command = exec.Command("/usr/bin/osascript", "-e", script, title, message)
	case "linux":
		if helper, err := exec.LookPath("notify-send"); err == nil {
			command = exec.Command(helper, title, message)
		}
	}
	if command != nil {
		_ = command.Start()
	}
}
