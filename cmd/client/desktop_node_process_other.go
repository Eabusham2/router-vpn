//go:build !windows

package main

import (
	"context"
	"errors"
)

func desktopOwnedNodePackageRoot() (string, error) {
	return "", errors.New("the captured Node package requires its Windows controller")
}

func startDesktopOwnedNodeProcess(context.Context, []string, []string, string) (desktopNodeProcess, error) {
	return nil, errors.New("the direct owned Node process requires its Windows controller")
}

func startDesktopOwnedNodeJournalProcess(context.Context, *app, *desktopNodeLaunch, []string, []string, string) (desktopNodeProcess, error) {
	return nil, errors.New("the durable Node engine requires its Windows controller")
}
