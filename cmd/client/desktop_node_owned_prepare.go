package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
)

// Preparation captures the same authenticated controller that owns the later
// native process. It does not acquire, adopt, or retire any protection target;
// staging does that only after the preceding runtime has joined.
type desktopOwnedNodePreparation struct {
	packageRoot string
	dataRoot    string
	lifetime    context.Context
	current     func() error
}

func prepareDesktopOwnedNodeLaunch(a *app, profile common.RouterProfile, mode string) (*desktopNodeLaunch, error) {
	if a == nil {
		return nil, errors.New("native Router preparation requires its captured application")
	}
	a.mu.Lock()
	operation := a.connectionContext
	a.mu.Unlock()
	if operation == nil || operation.Err() != nil {
		return nil, errors.New("native Router preparation requires its active connection operation")
	}
	capture, err := captureDesktopOwnedNodePreparation(a)
	if err != nil {
		return nil, err
	}
	return prepareDesktopOwnedNodeLaunchWith(a, profile, mode, operation, capture, verifyBundledNativeContext,
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}, physicalNetworkIdentity)
}

// The private arguments expose only read-only native verification and lookup
// boundaries to executable tests. Shipping callers always use the capture and
// verifier above; there is no public, environment, or profile override.
func prepareDesktopOwnedNodeLaunchWith(a *app, profile common.RouterProfile, mode string, operation context.Context,
	capture desktopOwnedNodePreparation, verify func(context.Context, string) (string, error), lookup applexray.Lookup,
	networkIdentity func() string) (*desktopNodeLaunch, error) {
	if a == nil || operation == nil || operation.Err() != nil || !desktopOwnedNodeModeEligible(profile, mode) ||
		capture.lifetime == nil || capture.lifetime.Err() != nil || capture.current == nil || verify == nil || networkIdentity == nil ||
		!filepath.IsAbs(capture.packageRoot) || !filepath.IsAbs(capture.dataRoot) {
		return nil, errors.New("native Router preparation has no eligible captured source or owner")
	}
	ctx, cancel := context.WithTimeout(operation, 30*time.Second)
	stopOwner := context.AfterFunc(capture.lifetime, cancel)
	defer func() { stopOwner(); cancel() }()
	network := networkIdentity()
	if network == "" {
		return nil, errors.New("native Router preparation cannot capture its physical network")
	}
	token := desktopOwnedNodeProfileToken(profile)
	current := func() error {
		if ctx.Err() != nil || capture.lifetime.Err() != nil {
			return errors.Join(ctx.Err(), capture.lifetime.Err(), errors.New("native Router preparation owner retired"))
		}
		if err := capture.current(); err != nil {
			return err
		}
		a.mu.Lock()
		actual, exists := a.profileByIDLocked(profile.ID)
		owned := !a.closing && a.connectionContext == operation && exists && desktopOwnedNodeProfileToken(actual) == token
		a.mu.Unlock()
		if !owned || networkIdentity() != network {
			return errors.New("native Router preparation changed its captured operation, profile or network")
		}
		return nil
	}
	if err := current(); err != nil {
		return nil, err
	}
	binary, err := verify(ctx, capture.packageRoot)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(binary) != filepath.Join(capture.packageRoot, "runtime", "native", nativeBinaryName()) {
		return nil, errors.New("native Router preparation verified another package executable")
	}
	if err := current(); err != nil {
		return nil, err
	}
	files, err := readDesktopNodeAssets(capture.dataRoot, profile.ID, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	var start map[string][]byte
	if profile.StartLayer != "" && profile.StartLayer != "off" && mode != "shadowsocks" {
		start, err = readDesktopNodeAssets(capture.dataRoot, profile.ID, "shadowsocks")
		if err != nil {
			return nil, err
		}
		defer func() {
			for _, body := range start {
				clear(body)
			}
		}()
	}
	compileContext, cancelCompile := context.WithTimeout(ctx, 10*time.Second)
	defer cancelCompile()
	original, endpoint, err := compileDesktopNode(compileContext, profile, mode, files, start, lookup)
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	launch, err := newDesktopOwnedNodeLaunch(profile, original, mode, capture.dataRoot, endpoint, network, session, 0)
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		clear(launch.config)
		clear(launch.metadata)
		clear(launch.ownedNode.source)
		return nil, err
	}
	return launch, nil
}
