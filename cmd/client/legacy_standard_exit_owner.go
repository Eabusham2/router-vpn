package main

import (
	"context"
	"os/exec"
	"router-vpn/internal/common"
	"strings"
)

// A legacy standard-exit engine may have a retained platform owner without
// pretending to implement the native Router-node or external command protocol.
type legacyStandardExitLaunch interface {
	Command() *exec.Cmd
	Start(context.Context) error
	Current(context.Context) error
	Discard() error
}

func legacyStandardExitOffPolicy(profile common.RouterProfile) bool {
	policy := strings.ToLower(strings.TrimSpace(profile.KillSwitchPolicy))
	return policy == "off" || policy == "" && !profile.KillSwitch
}
