package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"router-vpn/internal/mobilemultihop"
)

// Home on an ordinary external exit belongs to its separately captured entry.
// Use the native runtime's actual routed DNS proof, rather than looking up a
// resolver on the controller's ambient network or borrowing the current node.
func proveExternalHomeDNS(ctx context.Context, a *app, s observedConnection, runtimeID string) dnsProofState {
	result := dnsProofState{Mode: "home", Status: "failed"}
	fail := func(err error) dnsProofState { result.Reason = err.Error(); return result }
	if ctx == nil || context.Cause(ctx) != nil {
		return fail(errors.New("selected Home DNS proof has no live context"))
	}
	launch := desktopExternalMTULaunch(a)
	if launch == nil || launch.external.direct || launch.mode != runtimeID || !s.Connected || s.Phase != "connected" {
		return fail(errors.New("selected Home DNS has no captured native entry path"))
	}
	owner := launch.external
	owner.mu.Lock()
	baseline := owner.mtu
	owner.mu.Unlock()
	if baseline == nil || baseline.entryID == "" || baseline.profileID != s.RouterID || mtuProfileSnapshotToken(s.Profile) != baseline.profileToken {
		return fail(errors.New("selected Home DNS observation differs from the captured native policy"))
	}
	current := func() error {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if _, err := a.readDesktopExternalProof(launch); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		profile, exists := a.profileByIDLocked(baseline.profileID)
		entry, entryExists := a.profileByIDLocked(baseline.entryID)
		registered, registeredOK := desktopNodeOwners.Load(a)
		if !registeredOK || registered != launch || a.cmd != launch.command || !a.state.Connected || a.state.Phase != "connected" || a.state.Mode != "external-node" || a.state.RouterID != s.RouterID || a.state.RuntimeMode != runtimeID || !exists || !entryExists || mtuProfileSnapshotToken(profile) != baseline.profileToken || mtuProfileSnapshotToken(entry) != baseline.entryToken {
			return errors.New("selected Home DNS entry, credentials, policy or native owner changed")
		}
		return nil
	}
	if err := current(); err != nil {
		return fail(err)
	}
	policy, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil || policy.SourceSHA256() != owner.expected.SourceSHA256 {
		return fail(errors.New("selected Home DNS lost its exact native graph capture"))
	}
	var metadata struct {
		SourceSHA256  string `json:"source_sha256"`
		ConfigSHA256  string `json:"config_sha256"`
		ExitID        string `json:"exit_id"`
		EntryID       string `json:"entry_id"`
		DNSMode       string `json:"dns_mode"`
		DNSProtocol   string `json:"dns_protocol"`
		DNSServer     string `json:"dns_server"`
		DNSPort       int    `json:"dns_port"`
		DNSServerName string `json:"dns_server_name"`
		DNSPath       string `json:"dns_path"`
		DNSDetour     string `json:"dns_detour"`
	}
	if json.Unmarshal([]byte(policy.Metadata()), &metadata) != nil || metadata.SourceSHA256 != owner.expected.SourceSHA256 || metadata.ConfigSHA256 != owner.expected.ConfigSHA256 || metadata.EntryID != baseline.entryID || metadata.ExitID != baseline.profileID || metadata.DNSMode != "home" || metadata.DNSDetour == "" || metadata.DNSDetour == mobilemultihop.ExternalFinalTag || metadata.DNSDetour == "direct" {
		return fail(errors.New("selected Home DNS metadata differs from the proved entry path"))
	}
	selected := dnsSelection{Mode: metadata.DNSMode, Protocol: metadata.DNSProtocol, Host: metadata.DNSServer, Port: metadata.DNSPort, ServerName: metadata.DNSServerName, Path: metadata.DNSPath}
	snapshot, owned, err := activeDNSRuntimeSnapshotFor(a, s.RouterID, runtimeID)
	if err != nil || !owned || snapshot.source.path != filepath.Join(launch.directory, "sing-box.json") {
		return fail(errors.New("selected Home DNS configuration belongs to a different native owner"))
	}
	raw := snapshot.body
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != metadata.ConfigSHA256 {
		return fail(errors.New("selected Home DNS configuration changed after native proof"))
	}
	if err := verifySingBoxDNSConfigBytes(raw, selected); err != nil {
		return fail(err)
	}
	if err := current(); err != nil {
		return fail(err)
	}
	if err := snapshot.source.current(); err != nil {
		return fail(err)
	}
	result.Host, result.Status = selected.Host, "passed"
	result.Reason = fmt.Sprintf("captured native external runtime proved Home DNS %s://%s:%d through its authenticated entry; TLS identity and request path match the owned configuration", selected.Protocol, selected.Host, selected.Port)
	// Native DNSProven is reachability evidence, not an independently timed OS
	// lookup. Do not fabricate a DNS latency from controller receipt parsing.
	return result
}

func externalHomeDNSObservation(s observedConnection) bool {
	return externalDNSProfile(s.Profile) && (strings.TrimSpace(s.Profile.DNSMode) == "" || strings.EqualFold(strings.TrimSpace(s.Profile.DNSMode), "home"))
}
