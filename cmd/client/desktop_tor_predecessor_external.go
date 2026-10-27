package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func desktopTorEntryMode(control, entry common.RouterProfile, requested, base string) (string, error) {
	if entry.External == nil && (entry.NodeKind == "" || entry.NodeKind == "router-vpn") {
		return desktopExternalEntryMode(control, entry, requested, base)
	}
	if entry.NodeKind != "external" || entry.External == nil || !desktopExternalNativeProtocol(entry.External.Protocol) {
		return "", errors.New("Tor predecessor requires its exact linked Router or supported ordinary external transport")
	}
	// Idle settings and bridge edits call this selector before native capture.
	// A protocol label alone cannot make an incomplete or mixed private source
	// eligible; use the same imported-transport validator as actual Connect.
	if _, err := standardExitFromExternalProfile(entry); err != nil {
		return "", errors.New("Tor ordinary entry requires its complete imported transport and public identity")
	}
	mode := requested
	if mode == "" && control.MultihopEnabled && control.MultihopEntryID == entry.ID {
		mode = control.MultihopEntryMode
	}
	if mode != "" && mode != entry.External.Protocol {
		return "", errors.New("Tor ordinary entry mode cannot replace the captured imported protocol")
	}
	if base != "" && base != "auto" && (base != "wg" || entry.External.Protocol != "wireguard") && (base != "awg" || entry.External.Protocol != "amneziawg") {
		return "", errors.New("Tor ordinary entry base conflicts with its captured imported protocol")
	}
	return entry.External.Protocol, nil
}

// Endpoint bootstrap is the sole host lookup: the complete graph is validated
// before invoking it, its result is frozen once, and no proof or selected DNS
// query can use this callback. An interrupted network cannot donate its result.
func desktopTorEndpointLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("Tor endpoint bootstrap lost its captured operation")
	}
	network := physicalNetworkIdentity()
	if network == "" {
		return nil, errors.New("Tor endpoint bootstrap has no captured physical network")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(bounded, "ip", host)
	if err != nil {
		return nil, err
	}
	if bounded.Err() != nil || network != physicalNetworkIdentity() {
		return nil, errors.New("Tor endpoint bootstrap belongs to a retired operation or network")
	}
	return addresses, nil
}

func compileDesktopTorExternalPredecessor(ctx context.Context, source, policy common.RouterProfile, mode string, lookup applexray.Lookup) (*desktopTorPredecessorCapture, error) {
	if ctx == nil || ctx.Err() != nil || source.NodeKind != "external" || source.External == nil || mode != source.External.Protocol || !desktopExternalNativeProtocol(mode) {
		return nil, errors.New("Tor ordinary predecessor lost its exact source, protocol or operation")
	}
	source = cloneRouterProfile(source)
	runtimeProfile := cloneRouterProfile(source)
	// The imported node's own saved graph is another daily-use choice. This
	// capture uses precisely its transport as the predecessor of this Tor path.
	runtimeProfile.MultihopEnabled = false
	runtimeProfile.MultihopEntryID, runtimeProfile.MultihopExitID, runtimeProfile.MultihopEntryMode = "", "", ""
	runtimeProfile.MultihopExecution = "local"
	// The active Tor path owns resolver selection, including its PT bootstrap.
	// Preserve the reusable entry's saved DNS and credentials in source/token.
	copyDNSPolicy(&runtimeProfile, policy)
	exit, err := standardExitFromExternalProfile(runtimeProfile)
	if err != nil {
		return nil, err
	}
	launch, err := compileDesktopExternalCaptured(ctx, runtimeProfile, common.RouterProfile{}, exit, true, "", nil, nil, lookup)
	if err != nil {
		return nil, err
	}
	if launch == nil || launch.external == nil || !launch.external.direct || launch.external.predecessor != "" || launch.external.profile.ID != source.ID {
		return nil, errors.New("Tor ordinary predecessor compiler lost its independent direct transport owner")
	}
	defer func() {
		clear(launch.config)
		clear(launch.metadata)
		clear(launch.external.source)
		clear(launch.external.capture)
	}()
	raw, err := desktopTorRuntimePolicyJSON(launch.external.profile)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	assets, err := desktopNodeAssetsIdentity(mode, nil, nil)
	if err != nil {
		return nil, err
	}
	native, err := mobiletor.NewDesktopExternalPredecessor(mode, string(raw), string(launch.external.source), assets)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &desktopTorPredecessorCapture{entry: source, profileToken: desktopTorSourceIdentityToken(source), assetsSHA256: assets,
		mode: mode, endpoint: launch.endpoint, native: native}, nil
}
