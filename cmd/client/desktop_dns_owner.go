package main

import (
	"encoding/json"
	"errors"
	"sync"

	"router-vpn/internal/dnsmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Ordinary external and Tor sessions keep distinct proof/runtime owners. Only
// this immutable mailbox identity and the retained DNS operation lock are
// shared; a Tor session never impersonates an ordinary external graph.
type desktopDNSRuntimeIdentity struct {
	session, source, config, node string
	network                       string
	currentNetwork                func() string
	lock                          *sync.Mutex
	generation                    *uint64
	failed                        *bool
}

func capturedDesktopDNSRuntime(launch *desktopNodeLaunch) (desktopDNSRuntimeIdentity, error) {
	var identity desktopDNSRuntimeIdentity
	if launch == nil || launch.external != nil && launch.tor != nil {
		return identity, errors.New("native DNS requires one captured runtime owner")
	}
	if owner := launch.tor; owner != nil {
		metadata := owner.expected
		identity = desktopDNSRuntimeIdentity{session: metadata.SessionID, source: metadata.SourceSHA256, config: metadata.ConfigSHA256, node: metadata.NodeID,
			network: owner.network, currentNetwork: owner.currentNetworkIdentity, lock: &owner.dnsMu, generation: &owner.dnsGeneration, failed: &owner.dnsFailed}
	} else if owner := launch.external; owner != nil {
		identity = desktopDNSRuntimeIdentity{session: owner.session, source: owner.expected.SourceSHA256, config: owner.expected.ConfigSHA256, node: owner.expected.ExitID,
			network: owner.network, currentNetwork: owner.currentNetworkIdentity, lock: &owner.dnsMu, generation: &owner.dnsGeneration, failed: &owner.dnsFailed}
	} else {
		return identity, errors.New("native DNS has no captured external or Tor runtime")
	}
	if !desktopMTURequestPattern.MatchString(identity.session) || !desktopMTUPathPattern.MatchString(identity.source) || !desktopMTUPathPattern.MatchString(identity.config) || identity.node == "" {
		return desktopDNSRuntimeIdentity{}, errors.New("native DNS runtime identity is incomplete")
	}
	return identity, nil
}

func desktopDNSNetworkCurrent(launch *desktopNodeLaunch) bool {
	identity, err := capturedDesktopDNSRuntime(launch)
	return err == nil && identity.network != "" && identity.network == identity.currentNetwork()
}

func (a *app) desktopDNSCurrentProof(launch *desktopNodeLaunch) error {
	if _, err := capturedDesktopDNSRuntime(launch); err != nil {
		return err
	}
	if launch.tor != nil {
		_, err := a.readDesktopTorProof(launch)
		return err
	}
	_, err := a.readDesktopExternalProof(launch)
	return err
}

func desktopDNSNativeClosed(launch *desktopNodeLaunch) bool {
	identity, err := capturedDesktopDNSRuntime(launch)
	if err != nil {
		return false
	}
	if launch.tor == nil {
		return desktopPathNativeClosed(launch)
	}
	launch.tor.mu.Lock()
	acknowledged := launch.tor.stopAcknowledged
	launch.tor.mu.Unlock()
	if !acknowledged {
		// Cleanup may use the retained directory after rename. Result adoption
		// always requires the current pathname and live proof instead.
		raw, err := readDesktopPathDrainFile(launch, "stopped.json")
		var receipt desktopExternalStop
		acknowledged = err == nil && decodeRelayControlJSON(raw, &receipt) == nil && receipt.Schema == 1 && receipt.SessionID == identity.session && receipt.SourceSHA256 == identity.source && receipt.Closed
	}
	return acknowledged && desktopNodeProcessExited(launch)
}

func desktopDNSExpectedEndpoints(launch *desktopNodeLaunch) (dnsmeasure.Endpoint, string, string, error) {
	bad := errors.New("native DNS has no exact captured resolver policy")
	if _, err := capturedDesktopDNSRuntime(launch); err != nil {
		return dnsmeasure.Endpoint{}, "", "", err
	}
	if launch.tor != nil {
		metadata := launch.tor.expected
		if metadata.SourceSHA256 != launch.tor.digests.SourceSHA256 || metadata.ConfigSHA256 != launch.tor.digests.ConfigSHA256 || metadata.NodeID != launch.profileID {
			return dnsmeasure.Endpoint{}, "", "", bad
		}
		route, label := metadata.FinalTag, "Selected DNS via captured Tor exit"
		if metadata.DNSDetour != "" && metadata.DNSDetour != metadata.FinalTag {
			if metadata.EntryID == "" || metadata.EntryTag == "" || metadata.DNSDetour != metadata.EntryTag {
				return dnsmeasure.Endpoint{}, "", "", bad
			}
			route, label = metadata.EntryTag, "Selected DNS via captured Router entry"
		}
		selected := dnsmeasure.Endpoint{ID: "selected", Name: "Selected DNS", Kind: "selected", Address: metadata.DNS.Address, Port: metadata.DNS.Port, Transport: metadata.DNS.Transport,
			ServerName: metadata.DNS.ServerName, Path: metadata.DNS.Path, Route: route, RouteLabel: label}
		return selected, "Current Tor connection", metadata.IPv6Mode, nil
	}
	policy, err := mobilemultihop.NewExternalPolicy(string(launch.external.source), string(launch.external.capture))
	if err != nil || policy.SourceSHA256() != launch.external.expected.SourceSHA256 {
		return dnsmeasure.Endpoint{}, "", "", bad
	}
	var metadata struct {
		DNSProtocol   string `json:"dns_protocol"`
		DNSServer     string `json:"dns_server"`
		DNSPort       int    `json:"dns_port"`
		DNSServerName string `json:"dns_server_name"`
		DNSPath       string `json:"dns_path"`
		DNSDetour     string `json:"dns_detour"`
		IPv6Mode      string `json:"ipv6_mode"`
	}
	if json.Unmarshal([]byte(policy.Metadata()), &metadata) != nil {
		return dnsmeasure.Endpoint{}, "", "", bad
	}
	selected := dnsmeasure.Endpoint{ID: "selected", Name: "Selected DNS", Kind: "selected", Address: metadata.DNSServer, Port: metadata.DNSPort, Transport: metadata.DNSProtocol,
		ServerName: metadata.DNSServerName, Path: metadata.DNSPath, Route: metadata.DNSDetour, RouteLabel: "Selected DNS via " + metadata.DNSDetour}
	return selected, "Current external exit", metadata.IPv6Mode, nil
}
