//go:build !linux

package main

import "net/http"

func (*app) retestPlatformServiceMTU(http.ResponseWriter, *http.Request, mtuViewRequest) bool {
	return false
}
func (*app) startPlatformServiceAutomaticMTU() bool { return false }
