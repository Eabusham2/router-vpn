//go:build !linux

package main

import (
	"net/http"

	"router-vpn/internal/common"
)

type desktopPlatformProtectionCapture struct{}

func (a *app) capturePlatformProfileProtection() *desktopPlatformProtectionCapture { return nil }
func (c *desktopPlatformProtectionCapture) token(revision string) string           { return revision }
func (c *desktopPlatformProtectionCapture) settings(value profileProtectionSettings) profileProtectionSettings {
	return value
}
func (c *desktopPlatformProtectionCapture) currentAppLocked(a *app) bool { return c == nil }
func (a *app) handlePlatformProfileProtection(http.ResponseWriter, *http.Request, common.RouterProfile, profileProtectionCapture, string) bool {
	return false
}
func (a *app) guardPlatformProtectionOffPending() error       { return nil }
func (a *app) guardPlatformProtectionPreference(string) error { return nil }
