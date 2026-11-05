//go:build linux

package main

import (
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// Reverse scope is accepted only by the fixed reverse-* handshake, never by
// ordinary observation, MTU, protection, or forward-transfer commands.
type linuxStandardServiceReverseRequest struct {
	Intent linuxprotection.NodeStandardTransfer         `json:"intent"`
	Parent linuxprotection.ParentRecord                 `json:"parent"`
	Source mobiletor.DesktopLinuxClosedTransferSnapshot `json:"source"`
}
type linuxStandardServiceReverseResponse struct {
	Intent      linuxprotection.NodeStandardTransfer          `json:"intent"`
	Phase       string                                        `json:"phase"`
	Destination *mobiletor.DesktopLinuxClosedTransferSnapshot `json:"destination,omitempty"`
	Committed   bool                                          `json:"committed"`
}
