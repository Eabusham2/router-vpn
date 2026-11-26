package main

import (
	"context"
	"os/exec"
)

// A legacy standard-exit engine may have a retained platform owner without
// pretending to implement the native Router-node or external command protocol.
type legacyStandardExitLaunch interface {
	Command() *exec.Cmd
	Start(context.Context) error
	Current(context.Context) error
	Discard() error
}
