//go:build !windows && !linux

package main

func (a *app) initializeDesktopNodeRecovery() error { return nil }
