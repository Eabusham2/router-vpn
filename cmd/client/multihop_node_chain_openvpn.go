package main

import (
	"context"
	"errors"
	"runtime"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

// OpenVPN is a distinct schema-five imported middle. Its original inline
// credentials and literal transport never acquire a paired identity or physical
// permission; the first paired WG/AWG remains the sole physical ingress.
func desktopNodeChainOpenVPNMiddle(profile common.RouterProfile, mode string) bool {
	if mode != "openvpn" || profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != mode || profile.External.OpenVPN == nil ||
		profile.NodeProofID != "" || profile.RouterAPI != "" || profile.APIToken != "" ||
		profile.StartLayer != "" && profile.StartLayer != "off" || profile.External.StartLayer != nil {
		return false
	}
	endpoint, err := nativeopenvpn.CompileProfile(*profile.External.OpenVPN, "ordered-openvpn", "")
	if err != nil {
		return false
	}
	remotes, err := nativeopenvpn.Remotes(endpoint)
	return err == nil && len(remotes) == 1 && remotes[0].Host == profile.Endpoint && remotes[0].Validate() == nil
}

func desktopNodeChainHasOpenVPN(nodes []common.MultihopNodeSelection) bool {
	for _, node := range nodes {
		if node.Mode == "openvpn" {
			return true
		}
	}
	return false
}

func nativeNodeChainOpenVPNPlatformSupported() bool {
	return nativeNodeChainPlatformSupported() && (runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin") &&
		(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func desktopNodeChainOpenVPNInput(ctx context.Context, profile common.RouterProfile) (string, string, error) {
	if !desktopNodeChainOpenVPNMiddle(profile, "openvpn") {
		return "", "", errors.New("ordered OpenVPN middle lost its original single literal transport")
	}
	config, capture, endpoint, err := desktopImportedEntrySource(ctx, profile, nil)
	if err != nil {
		return "", "", err
	}
	if endpoint != profile.Endpoint {
		return "", "", errors.New("ordered OpenVPN middle changed its original endpoint")
	}
	input, err := mobilemultihop.NodeChainImportedOpenVPNMemberInput(config, capture)
	return input, endpoint, err
}
