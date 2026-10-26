package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func torDNSObservation(s observedConnection, runtimeID string) bool {
	return runtimeID == "external-tor-bridge" || s.Profile.External != nil && s.Profile.External.Protocol == "tor-bridge"
}

// Tor's native receipt is issued only after the captured selected resolver and
// Tor exit have both been proved by the same running engine. The controller
// checks that receipt and its exact configuration; an ordinary-network lookup
// cannot establish DNS ownership for this path.
func proveDesktopTorDNS(ctx context.Context, a *app, s observedConnection, runtimeID string) dnsProofState {
	mode := strings.ToLower(strings.TrimSpace(s.Profile.DNSMode))
	if mode == "" {
		mode = "home"
	}
	result := dnsProofState{Mode: mode, Status: "failed"}
	fail := func(err error) dnsProofState { result.Reason = err.Error(); return result }
	if ctx == nil || context.Cause(ctx) != nil || a == nil {
		return fail(errors.New("selected Tor DNS proof has no live owner context"))
	}
	if runtimeID != "external-tor-bridge" || s.Mode != "external-node" || s.RuntimeMode != runtimeID || !s.Connected || s.Phase != "connected" || s.Profile.ID != s.RouterID || s.Profile.NodeKind != "external" || s.Profile.External == nil || s.Profile.External.Protocol != "tor-bridge" {
		return fail(errors.New("selected Tor DNS observation has no matching connected path"))
	}
	launch := desktopExternalMTULaunch(a)
	if launch == nil || launch.tor == nil || launch.external != nil || launch.mode != runtimeID || launch.profileID != s.RouterID {
		return fail(errors.New("selected Tor DNS has no captured native runtime"))
	}
	owner := launch.tor
	if desktopTorSourceIdentityToken(s.Profile) != owner.profileToken {
		return fail(errors.New("selected Tor DNS observation differs from its captured private policy"))
	}
	current := func() error {
		if err := context.Cause(ctx); err != nil {
			return errors.New("selected Tor DNS proof was cancelled")
		}
		if _, err := a.readDesktopTorProof(launch); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.cmd != launch.command || !a.state.Connected || a.state.Phase != "connected" || a.state.Mode != "external-node" || a.state.RouterID != s.RouterID || a.state.RuntimeMode != runtimeID {
			return errors.New("selected Tor DNS connection changed before proof adoption")
		}
		return nil
	}
	if err := current(); err != nil {
		return fail(err)
	}
	metadata := owner.expected
	if metadata.NodeID != s.RouterID || metadata.SourceSHA256 != owner.digests.SourceSHA256 || metadata.ConfigSHA256 != owner.digests.ConfigSHA256 || metadata.DNS.Mode != mode {
		return fail(errors.New("selected Tor DNS metadata differs from its captured policy"))
	}
	detour := metadata.FinalTag
	pathLabel := "captured Tor exit"
	if mode == "home" {
		if metadata.EntryID == "" || metadata.EntryTag == "" || owner.predecessor == nil {
			return fail(errors.New("selected Home DNS has no authenticated captured Router entry"))
		}
		detour, pathLabel = metadata.EntryTag, "authenticated captured Router entry"
	}
	// Schema 1 direct Tor metadata predates DNSDetour. Its configuration still
	// must route selected DNS through FinalTag. Router-entry captures carry the
	// explicit route in both metadata and the exact config.
	if metadata.EntryID != "" && metadata.DNSDetour != detour || metadata.EntryID == "" && metadata.DNSDetour != "" && metadata.DNSDetour != detour {
		return fail(errors.New("selected Tor DNS metadata names another resolver path"))
	}
	selected := dnsSelection{Mode: mode, Protocol: metadata.DNS.Transport, Host: metadata.DNS.Address, Port: metadata.DNS.Port, ServerName: metadata.DNS.ServerName, Path: metadata.DNS.Path}
	if selected.Host == "" || selected.Port < 1 || selected.Port > 65535 {
		return fail(errors.New("selected Tor DNS metadata has no concrete resolver"))
	}
	snapshot, owned, err := activeDNSRuntimeSnapshotFor(a, s.RouterID, runtimeID)
	if err != nil || !owned || snapshot.source.path != filepath.Join(launch.directory, "sing-box.json") {
		return fail(errors.New("selected Tor DNS configuration belongs to a different native owner"))
	}
	if desktopTorDigest(snapshot.body) != metadata.ConfigSHA256 {
		return fail(errors.New("selected Tor DNS configuration changed after native proof"))
	}
	var config struct {
		DNS struct {
			Final   string `json:"final"`
			Servers []struct {
				Tag    string `json:"tag"`
				Detour string `json:"detour"`
			} `json:"servers"`
		} `json:"dns"`
	}
	if json.Unmarshal(snapshot.body, &config) != nil {
		return fail(errors.New("selected Tor DNS configuration is invalid"))
	}
	// The independent Tor compiler owns its own final resolver tag. The exact
	// config digest above prevents borrowing a different graph; the common
	// checker still requires one matching final server and the DNS hijack rule.
	if err := verifySingBoxDNSConfigBytesForTag(snapshot.body, selected, config.DNS.Final); err != nil {
		return fail(err)
	}
	for _, server := range config.DNS.Servers {
		if server.Tag == config.DNS.Final && server.Detour != detour {
			return fail(errors.New("selected Tor DNS configuration bypasses its captured resolver path"))
		}
	}
	if err := current(); err != nil {
		return fail(err)
	}
	if err := snapshot.source.current(); err != nil {
		return fail(err)
	}
	result.Host, result.Status = selected.Host, "passed"
	result.Reason = fmt.Sprintf("captured native Tor runtime proved selected DNS %s://%s:%d through its %s; TLS identity and request path match the owned configuration", selected.Protocol, selected.Host, selected.Port, pathLabel)
	// Receipt validation is not a DNS timing measurement. Speed Lab and DNS
	// Retest perform separately owned, actually timed native queries.
	return result
}
