//go:build linux

package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func linuxHostProofFixture(t *testing.T) (*desktopLinuxNodeHost, common.RouterProfile) {
	t.Helper()
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	profile.KillSwitch, profile.KillSwitchPolicy = true, "always"
	original, endpoint, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, strings.Repeat("b", 32), "linux", 0)
	if err != nil {
		t.Fatal(err)
	}
	source, err := original.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	return &desktopLinuxNodeHost{policy: policy, source: []byte(source), launch: &desktopNodeLaunch{profileID: profile.ID, endpoint: endpoint}}, profile
}

func TestDesktopLinuxNodeProofCapturedProfile(t *testing.T) {
	host, original := linuxHostProofFixture(t)
	profile, err := host.capturedProofProfile()
	if err != nil || profile.RouterAPI != original.RouterAPI || profile.NodeProofID != original.NodeProofID {
		t.Fatal("Linux proof did not recover its complete sealed original profile", err)
	}
	for _, scenario := range []string{"source-url", "source-secret", "launch-node", "launch-endpoint", "missing-policy"} {
		t.Run(scenario, func(t *testing.T) {
			copy := *host
			copy.launch = &desktopNodeLaunch{profileID: host.launch.profileID, endpoint: host.launch.endpoint}
			copy.source = append([]byte(nil), host.source...)
			switch scenario {
			case "source-url":
				copy.source = bytes.ReplaceAll(copy.source, []byte("10.77.0.1"), []byte("10.88.0.1"))
			case "source-secret":
				copy.source = bytes.ReplaceAll(copy.source, []byte("private-token"), []byte("changed-token"))
			case "launch-node":
				copy.launch.profileID = "another-node"
			case "launch-endpoint":
				copy.launch.endpoint = "198.51.100.9"
			case "missing-policy":
				copy.policy = nil
			}
			if _, err := copy.capturedProofProfile(); err == nil {
				t.Fatal("Linux Router proof accepted a substituted original private capture")
			}
		})
	}
}

func TestDesktopLinuxNodeProofTarget(t *testing.T) {
	profile := common.RouterProfile{RouterAPI: "http://10.77.0.1:8787", IPv6Mode: "on"}
	target, remote, err := desktopLinuxNodeProofTarget(profile)
	if err != nil || target.String() != "http://10.77.0.1:8787/health" || remote != netip.MustParseAddrPort("10.77.0.1:8787") {
		t.Fatal("Linux Router proof changed its captured default target", err)
	}
	profile.PathProbeURL = "https://[fd77::1]:8787/custom-health?trial=1"
	target, remote, err = desktopLinuxNodeProofTarget(profile)
	if err != nil || target.String() != profile.PathProbeURL || remote != netip.MustParseAddrPort("[fd77::1]:8787") {
		t.Fatal("Linux Router proof replaced its explicit private target", err)
	}
	for _, target := range []string{"https://node.example.test:8787/health", "http://1.1.1.1:8787/health", "http://127.0.0.1:8787/health",
		"http://10.77.0.1/health", "http://10.77.0.1:0/health", "http://10.77.0.1:65536/health", "http://10.77.0.1:8787/health#fragment",
		"http://token@10.77.0.1:8787/health", "file:///health", "http://[::ffff:10.77.0.1]:8787/health"} {
		t.Run(target, func(t *testing.T) {
			profile.PathProbeURL = target
			if _, _, err := desktopLinuxNodeProofTarget(profile); err == nil {
				t.Fatal("Linux Router proof admitted ambient resolution or an uncaptured endpoint")
			}
		})
	}
	profile.PathProbeURL, profile.IPv6Mode = "http://[fd77::1]:8787/health", "off"
	if _, _, err := desktopLinuxNodeProofTarget(profile); err == nil {
		t.Fatal("Linux Router proof bypassed selected IPv6 Off")
	}
}

func TestDesktopLinuxNodeReadyInitialAndRetainedReader(t *testing.T) {
	now := time.UnixMilli(1800000000000)
	started := now.Add(-2 * time.Second)
	record := mobilemultihop.DesktopNodeReadyRecord{InterfaceName: "router-vpn", InterfaceIndex: 12, MTU: 1400, ProvedAt: now.Add(-time.Second).UnixMilli()}
	live := desktopNodeMTURecord{Interface: record.InterfaceName, Index: 12, MTU: 1400, Reader: 1}
	if err := validateDesktopLinuxNodeReady(record, live, started, now, nil, true); err != nil {
		t.Fatal("fresh original Linux readiness was refused", err)
	}
	for _, scenario := range []string{"before-start", "future", "historical", "other-ready", "missing-ready", "other-name", "other-index",
		"other-mtu", "new-reader", "active-mtu", "restored", "expired", "failure", "generation", "request", "lease"} {
		t.Run(scenario, func(t *testing.T) {
			r, m, start, fresh, captured := record, live, started, true, &record
			switch scenario {
			case "before-start":
				r.ProvedAt = started.Add(-time.Millisecond).UnixMilli()
			case "future":
				r.ProvedAt = now.Add(time.Millisecond).UnixMilli()
			case "historical":
				start = now.Add(-60 * time.Second)
				r.ProvedAt = now.Add(-31 * time.Second).UnixMilli()
			case "other-ready":
				fresh = false
				r.DNSMilliseconds++
			case "missing-ready":
				fresh, captured = false, nil
			case "other-name":
				m.Interface = "replacement"
			case "other-index":
				m.Index++
			case "other-mtu":
				m.MTU++
			case "new-reader":
				m.Reader++
			case "active-mtu":
				m.Active = true
			case "restored":
				m.Restored = true
			case "expired":
				m.Expired = true
			case "failure":
				m.Failure = "native read failed"
			case "generation":
				m.Generation++
			case "request":
				m.Request = strings.Repeat("c", 32)
			case "lease":
				m.Lease = strings.Repeat("d", 32)
			}
			if err := validateDesktopLinuxNodeReady(r, m, start, now, captured, fresh); err == nil {
				t.Fatal("Linux readiness adopted another or stale initial reader")
			}
		})
	}
	live.Reader, live.Index, live.MTU = 2, 13, 1392
	if err := validateDesktopLinuxNodeReady(record, live, started, now, &record, false); err != nil {
		t.Fatal("retained original readiness rejected the child's later owned MTU reader", err)
	}
	next := live
	next.Heartbeat++
	if !sameDesktopLinuxNodeProofTUN(live, next) {
		t.Fatal("fresh heartbeat changed otherwise identical proof ownership")
	}
	for _, change := range []func(*desktopNodeMTURecord){func(v *desktopNodeMTURecord) { v.Path += "x" },
		func(v *desktopNodeMTURecord) { v.Index++ }, func(v *desktopNodeMTURecord) { v.Reader++ }, func(v *desktopNodeMTURecord) { v.MTU++ },
		func(v *desktopNodeMTURecord) { v.Generation++ }, func(v *desktopNodeMTURecord) { v.Active = true }} {
		next = live
		change(&next)
		if sameDesktopLinuxNodeProofTUN(live, next) {
			t.Fatal("HTTP proof borrowed a changed captured TUN or MTU operation")
		}
	}
}

func TestDesktopLinuxNodeRunningCaptureExcludesInnerTargets(t *testing.T) {
	host, profile := linuxHostProofFixture(t)
	selected, err := captureDesktopLinuxNodeRunningPath(host.policy)
	if err != nil || len(selected.Interfaces) == 0 || len(selected.Destinations) != 1 ||
		selected.Destinations[0].Network != "udp" || selected.Destinations[0].Address != netip.MustParseAddrPort("198.51.100.8:51820") {
		t.Fatal("Linux running inventory did not retain the actual compiled outer path", err)
	}
	for _, destination := range selected.Destinations {
		if destination.Address.Addr().String() == profile.AdGuardIPv4 || destination.Address.Addr() == netip.MustParseAddr("10.77.0.1") {
			t.Fatal("selected DNS or private Router proof became a physical exception")
		}
	}
	selected.Destinations[0].Address = netip.MustParseAddrPort("10.77.0.1:8787")
	other, err := captureDesktopLinuxNodeRunningPath(host.policy)
	if err != nil || other.Destinations[0].Address != netip.MustParseAddrPort("198.51.100.8:51820") {
		t.Fatal("returned comparison mutated the sealed original graph", err)
	}
}
