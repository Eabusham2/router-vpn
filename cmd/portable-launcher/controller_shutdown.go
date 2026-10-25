package main

import (
	"os/exec"
	"router-vpn/internal/controllerprocess"
)

func portableControllerToken() (string, error) { return controllerprocess.NewToken() }
func portableControllerEnvironment(env []string, token string) []string {
	return controllerprocess.Environment(env, token)
}
func trackPortableController(cmd *exec.Cmd, token string) { controllerprocess.Track(cmd, token) }
func stopPortableController(cmd *exec.Cmd) error          { return controllerprocess.Stop(cmd) }
