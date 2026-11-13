package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// A hostname middle is an original transport source, never a standalone
// physical connection. The shared ordered compiler owns its separately saved
// TCP lookup through the preceding packet prefix. This constructor performs
// no lookup and cannot freeze the hostname using the ordinary network.
func desktopNodeChainImportedHostnameInput(profile common.RouterProfile) (string, error) {
	bad := errors.New("ordered hostname middle requires its original SS2022 profile and saved Custom TCP resolver")
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "shadowsocks" ||
		profile.NodeProofID != "" || profile.APIToken != "" || profile.RouterAPI != "" ||
		profile.StartLayer != "" && profile.StartLayer != "off" ||
		profile.DNSMode != "custom" || profile.DNSProtocol != "tcp" || profile.DNSPort < 1 || profile.DNSPort > 65535 {
		return "", bad
	}
	if _, err := netip.ParseAddr(profile.Endpoint); err == nil {
		return "", bad
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil || exit.Protocol != "shadowsocks" || exit.StartLayer != nil || !strings.EqualFold(exit.Server, profile.Endpoint) {
		return "", bad
	}
	endpoint, outbound, err := directStandardExitRuntimeParts(exit)
	if err != nil || endpoint != nil || outbound == nil {
		return "", bad
	}
	// The ordinary descriptor and transport builder both normalize hostname
	// case. Preserve the original name only after both validate the transport;
	// the shared constructor still requires byte-identical profile, external
	// transport and generated outbound endpoints.
	outbound["server"] = profile.Endpoint
	// Reuse the generated transport envelope without creating an application
	// DNS seed. The exact saved profile below supplies the transport resolver;
	// the independently captured final node supplies application DNS.
	config := standardExitConfig(profile, nil, []any{}, []any{outbound})
	delete(config, "dns")
	raw, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	// RouterProfile.MarshalJSON preserves explicit false Home LAN access and
	// the original DNS/protection settings without mutating the saved profile.
	capture, err := json.Marshal(map[string]any{"schema": 1, "exit_id": profile.ID,
		"protocol": profile.External.Protocol, "expected_public_ip": profile.External.ExpectedPublicIP,
		"profile": profile})
	if err != nil {
		return "", err
	}
	defer clear(capture)
	return mobilemultihop.NodeChainImportedMemberInput(string(raw), string(capture))
}
