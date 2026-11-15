package main

import (
	"errors"
	"net"
)

// The raw owner first authenticates the command nonce, lease, generation and
// bounded reader delta (including one pending mutation followed by rollback).
// This comparison then requires actual kernel retirement before paired reproof.
// The pinned allocator may reuse the retired utun alias. Its new kernel index
// and exact live readback, never name inequality, identify the successor.
func validateDesktopMacOSPairedNodeReaderRetirement(old, next desktopNodeMTURecord, interfaces []net.Interface) error {
	if !desktopNodeChainDarwinInterfaceName(old.Interface) || !desktopNodeChainDarwinInterfaceName(next.Interface) ||
		old.Index <= 0 || old.Index == next.Index || next.Index <= 0 ||
		next.Reader <= old.Reader || old.Session != next.Session || old.Config != next.Config || old.Path != next.Path {
		return errors.New("paired Darwin reader changed its original source or predecessor")
	}
	found := false
	for _, link := range interfaces {
		if link.Index == old.Index {
			return errors.New("paired Darwin original kernel interface is still present")
		}
		if link.Index == next.Index {
			if found || link.Name != next.Interface || link.MTU != next.MTU || link.Flags&net.FlagUp == 0 || next.MTU < 1280 || next.MTU > 9000 {
				return errors.New("paired Darwin successor does not match actual kernel readback")
			}
			found = true
		}
	}
	if !found {
		return errors.New("paired Darwin successor is absent from actual kernel inventory")
	}
	return nil
}
