//go:build !linux

package main

import "net/http"

func (a *app) writeDesktopPlatformMTUViewStatus(http.ResponseWriter, *http.Request, string, string) bool {
	return false
}
