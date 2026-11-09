package main

import (
	"context"
	"errors"
	"net"
	"strings"
)

func publicTorExit(value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", errors.New("Tor check returned an invalid/non-public exit address")
	}
	return ip.String(), nil
}

// check.torproject.org IsTor and selected DNS are proved by the owned native
// final outbound. An ambient HTTP request cannot certify the active Tor path.
func (a *app) proveTorBridgeExit() (string, error) {
	raw, found := desktopNodeOwners.Load(a)
	launch, ok := raw.(*desktopNodeLaunch)
	if !found || !ok || launch == nil || launch.tor == nil {
		return "", errors.New("Tor exit proof requires its captured native owner")
	}
	ctx := a.connectionOperationContextOrBackground()
	return a.proveTorBridgeExitContext(ctx, launch)
}

func (a *app) proveTorBridgeExitContext(ctx context.Context, launch *desktopNodeLaunch) (string, error) {
	if ctx == nil || launch == nil || launch.tor == nil {
		return "", errors.New("Tor exit proof has no original caller or native owner")
	}
	if current, found := desktopNodeOwners.Load(a); !found || current != launch {
		return "", errors.New("Tor exit proof belongs to a replaced native owner")
	}
	proof, err := a.waitDesktopTorProof(ctx, launch)
	if err != nil && ctx.Err() != nil {
		return "", errConnectionOperationCancelled
	}
	if err != nil {
		return "", err
	}
	return proof.Proof.IP, nil
}
