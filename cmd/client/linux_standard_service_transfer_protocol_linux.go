//go:build linux

package main

import (
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

type linuxStandardServiceTransferRequest struct {
	ID              string                                      `json:"id"`
	DeadlineNS      int64                                       `json:"deadline_ns"`
	Destination     linuxprotection.NodeSelection               `json:"destination"`
	ProfileID       string                                      `json:"profile_id"`
	ProfileRevision string                                      `json:"profile_revision"`
	Prepared        *linuxprotection.NodePreparedRecord         `json:"prepared,omitempty"`
	Snapshot        *mobiletor.DesktopLinuxNodeTransferSnapshot `json:"snapshot,omitempty"`
}
type linuxStandardServiceTransferResponse struct {
	Intent            linuxprotection.StandardNodeTransfer `json:"intent"`
	Phase             string                               `json:"phase"`
	DestinationSHA256 string                               `json:"destination_sha256,omitempty"`
	Committed         bool                                 `json:"committed"`
}
