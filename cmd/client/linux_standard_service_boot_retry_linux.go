//go:build linux

package main

import (
	"context"
	"time"
)

// Caller holds the original service gate. The retained watcher runs this even
// before READY and without a client request: network startup and installation
// may both be waiting for this original owner to finish its acknowledgment.
// repairBoot continues s.boot's real creator; a missing creator still requires
// the ordinary complete native-absence and prior-boot checks in reassert.
func (s *linuxStandardService) retryBoot(lifetime context.Context) {
	if s == nil || lifetime == nil || lifetime.Err() != nil || s.quiescing || s.bootFailure == nil || s.protectionView != nil && s.protectionView.data.Pending || time.Now().Before(s.bootRetryAfter) {
		return
	}
	attempt, cancel := context.WithTimeout(lifetime, 4*time.Second)
	_ = s.repairBoot(attempt) // repairBoot retains and exposes the exact failure.
	cancel()
	s.bootRetryAfter = time.Now().Add(time.Second)
}
