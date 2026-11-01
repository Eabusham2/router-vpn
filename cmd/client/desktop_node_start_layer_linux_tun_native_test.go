//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func linuxHostTUNStartLayer(scenario string) string {
	switch scenario {
	case "layer-aes-connect", "layer-aes-restore":
		return common.StartLayerAES256GCM
	case "layer-whitening-connect", "layer-whitening-wrong-key", "layer-whitening-resolver-failure", "layer-whitening-cover-restore":
		return common.StartLayerAES256GCMXOR
	default:
		return ""
	}
}

func linuxHostTUNWrongKeyCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return scenario == "wrong-key" || scenario == "layer-whitening-wrong-key"
}

func linuxHostTUNResolverFailureCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return scenario == "resolver-failure" || scenario == "layer-whitening-resolver-failure"
}

// This is an observation of the real sealed host before teardown. The parent
// compares the returned physical tuples against its independent encrypted peer;
// neither the original AES listener nor private DNS/proof can become an extra
// physical exception when the captured Start Layer uses whitening.
func linuxHostTUNLayerSource(ctx context.Context, host *desktopLinuxNodeHost, scenario string) (string, []mobilemultihop.PhysicalEgress, error) {
	if host == nil {
		return "", nil, errors.New("installed layer has no retained native host")
	}
	if err := host.enter(ctx); err != nil {
		return "", nil, err
	}
	defer func() { host.gate <- struct{}{} }()
	if host.closed || host.policy == nil || host.policy.Validate() != nil {
		return "", nil, errors.New("installed layer lost its original sealed native host")
	}
	meta := host.policy.Metadata()
	capture, err := host.policy.Capture()
	layer := linuxHostTUNStartLayer(scenario)
	mode, kind, roots := linuxHostTUNMode(scenario), "shadowsocks", 2
	if mode == "wg" {
		kind, roots = "wireguard", 1
	}
	if layer == common.StartLayerAES256GCMXOR {
		kind = "routervpn-aes-xor"
	}
	if err != nil || meta.TargetOS != "linux" || meta.Mode != mode || meta.StartLayer != layer ||
		capture.StartLayer != layer || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != kind ||
		len(capture.PhysicalRoots[0].Destinations) != roots || capture.SelectedDNS.Physical || capture.SelectedDNS.Host != "192.168.50.133" ||
		capture.SelectedDNS.Detour != "proxy" || capture.ConfiguredMTU < 1280 || capture.ConfiguredMTU > 9000 {
		return "", nil, errors.Join(err, errors.New("installed layer changed its exact native cipher, DNS, MTU or physical root"))
	}
	return layer, append([]mobilemultihop.PhysicalEgress(nil), capture.PhysicalRoots[0].Destinations...), nil
}
