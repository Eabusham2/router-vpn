package main

import (
	"context"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestAsyncMeasurementTokenCoversCredentialsAndDataplane(t *testing.T) {
	changes := map[string]func(*common.RouterProfile){
		"api-token": func(p *common.RouterProfile) { p.APIToken = "rotated-secret" },
		"probe-url": func(p *common.RouterProfile) { p.PathProbeURL = "http://10.78.0.1:8787/health" },
		"ipv6": func(p *common.RouterProfile) { p.IPv6Mode = "off" },
		"home-dns": func(p *common.RouterProfile) { p.AdGuardIPv4 = "10.78.0.1" },
		"home-dns-v6": func(p *common.RouterProfile) { p.AdGuardIPv6 = "fd00::2" },
		"socks-credential": func(p *common.RouterProfile) { p.SocksPassword = "rotated-socks" },
		"socks-port": func(p *common.RouterProfile) { p.SocksPort = 1081 },
		"home-lan": func(p *common.RouterProfile) { p.HomeLANAccess = true },
		"home-lan-cidrs": func(p *common.RouterProfile) { p.HomeLANCIDRs = []string{"192.168.60.0/24"} },
		"kill-switch": func(p *common.RouterProfile) { p.KillSwitch = true },
		"fallback": func(p *common.RouterProfile) { p.BaseFallback = true },
		"layers": func(p *common.RouterProfile) { p.CustomLayers = []string{"shadowsocks"} },
		"start-layer": func(p *common.RouterProfile) { p.StartLayer = "aes-256-gcm" },
		"mtu-policy": func(p *common.RouterProfile) { p.MTUPolicy = "fixed" },
		"fixed-mtu": func(p *common.RouterProfile) { p.ManualMTU = 1280 },
		"effective-mtu": func(p *common.RouterProfile) { p.EffectiveMTU = 1380 },
		"jumbo": func(p *common.RouterProfile) { p.JumboTUN = true },
		"padding": func(p *common.RouterProfile) { p.DAITAEnabled = true },
		"padding-rate": func(p *common.RouterProfile) { p.DAITARateKbps = 100 },
		"entry": func(p *common.RouterProfile) { p.MultihopEntryID = "other-entry" },
		"exit": func(p *common.RouterProfile) { p.MultihopExitID = "other-exit" },
		"external": func(p *common.RouterProfile) { p.External = &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.9"} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := common.RouterProfile{ID: "exit", APIToken: "original-secret", IPv6Mode: "on"}
			before := asyncMeasurementProfileToken(p)
			change(&p)
			if after := asyncMeasurementProfileToken(p); before == after { t.Fatal("live measurement identity ignored " + name) }
		})
	}
}

func TestAsyncMeasurementTokenIgnoresMeasurementsAndDisplayMetadata(t *testing.T) {
	p := common.RouterProfile{ID: "exit", APIToken: "private-api-token", DNSMode: "custom", DNSHost: "9.9.9.9"}
	before := asyncMeasurementProfileToken(p)
	p.Name, p.Location, p.Latitude, p.Longitude = "renamed", "Austin", 30.1, -97.7
	p.PublicIP, p.UseCount, p.LastUsedAt = "203.0.113.9", 10, "2026-09-07"
	p.LatencySamples, p.LatencyMedianMs, p.LatencyLastTest = 50, 2.5, "2026-09-07"
	p.FastestDNSHost, p.FastestDNSName, p.FastestDNSLatencyMs = "1.1.1.1", "measured", 1.5
	p.DNSResults = []common.DNSBenchmarkResult{{Address: "1.1.1.1", LatencyMs: 1.5}}
	if asyncMeasurementProfileToken(p) != before { t.Fatal("measurement persistence invalidated an unrelated in-flight proof") }
	if strings.Contains(before, "private-api-token") { t.Fatal("identity token exposes credentials") }
}

func TestAsyncMeasurementObserverRejectsCredentialRotationSynchronously(t *testing.T) {
	a, p, session := asyncPathFixture(t, "http://10.77.0.1:8787")
	_, stop, validate, err := asyncMeasurementPathContext(context.Background(), a, p, a.state, session, asyncMeasurementProfileToken(p))
	if err != nil { t.Fatal(err) }
	defer stop()
	a.mu.Lock()
	a.profiles.Profiles[1].APIToken = "rotated-token"
	a.mu.Unlock()
	if err := validate(); err == nil { t.Fatal("credential rotation survived path validation") }
}
