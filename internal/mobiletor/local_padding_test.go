package mobiletor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func localPaddingSourceFixture(t *testing.T, family string) *LocalPaddingSource {
	t.Helper()
	exit := torHostProfile()
	exit["daita_enabled"], exit["daita_rate_kbps"] = true, 64
	source := &LocalPaddingSource{}
	if family == "router" {
		entry := torHomeEntry()
		exit = torHomeProfile()
		exit["daita_enabled"], exit["daita_rate_kbps"] = true, 64
		torHomePair(exit, entry)
		source.PredecessorProfile, source.PredecessorConfig = torHostEncode(t, entry), torHostBase(t)
	} else if family != "direct" {
		entry, graph := externalTorPredecessorFixture(t, family)
		torHomePair(exit, entry)
		exit["multihop_entry_mode"] = family
		source.PredecessorProfile, source.PredecessorConfig = torHostEncode(t, entry), torHostEncode(t, graph)
	}
	source.Profile = torHostEncode(t, exit)
	return source
}

func TestLocalPaddingSourceBindsCompleteCompiledPathWithoutOpeningAdmission(t *testing.T) {
	for _, family := range []string{"direct", "router", "wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(family, func(t *testing.T) {
			source := localPaddingSourceFixture(t, family)
			original := *source
			capture, err := NewLocalPaddingCapture(source, "padding-source-session")
			if err != nil {
				t.Fatal(err)
			}
			if capture.Policy() != (TorPaddingPolicy{Enabled: true, RateKbps: 64}) || capture.SessionSHA256() != localPaddingDigest("padding-source-session") || capture.SourceSHA256() != localPaddingDigest(capture.Config()) || *source != original {
				t.Fatal("source capture changed policy, identity or caller-owned values")
			}
			sha, err := LocalPaddingSourceSHA256(capture.Config(), source.Profile, "padding-source-session")
			if err != nil || sha != capture.SourceSHA256() {
				t.Fatal("independent native source validation did not reproduce its exact receipt identity", err)
			}
			graph, _ := profileObject(capture.Config(), 4<<20)
			outbound := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
			retained := outbound["padding_source"].(map[string]any)
			if retained["profile"] != source.Profile || source.PredecessorConfig != "" && retained["predecessor_config"] != source.PredecessorConfig {
				t.Fatal("native source replaced original predecessor or exit")
			}
			formatted, _ := json.MarshalIndent(graph, "", "  ")
			if sha, err := LocalPaddingSourceSHA256(string(formatted), source.Profile, "padding-source-session"); err != nil || sha != capture.SourceSHA256() {
				t.Fatal("formatting changed canonical native source authority", err)
			}
			// This source foundation cannot enable an incomplete shipping host.
			if config, err := CompileProfileWithPredecessor(source.Profile, "padding-source-session", source.PredecessorConfig, source.PredecessorProfile); err == nil || config != "" {
				t.Fatal("source reconstruction prematurely opened Local padding admission")
			}
		})
	}
}

func TestLocalPaddingSourceRejectsHiddenReplacedAndUnownedGraphs(t *testing.T) {
	for _, fault := range []string{"missing", "source-extra", "profile", "dns", "route", "session", "rate", "ordinary-key", "missing-entry", "server", "compare", "missing-tun", "duplicate-owner", "off"} {
		t.Run(fault, func(t *testing.T) {
			source := localPaddingSourceFixture(t, "socks5")
			capture, err := NewLocalPaddingCapture(source, "padding-source-session")
			if err != nil {
				t.Fatal(err)
			}
			graph, _ := profileObject(capture.Config(), 4<<20)
			exit, _ := profileObject(source.Profile, 256<<10)
			out := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
			retained := out["padding_source"].(map[string]any)
			session := "padding-source-session"
			switch fault {
			case "missing":
				delete(out, "padding_source")
			case "source-extra":
				retained["caller_authorized"] = true
			case "profile":
				exit["id"] = "replacement-tor"
			case "dns":
				graph["dns"].(map[string]any)["final"] = bootstrapDNS
			case "route":
				graph["route"].(map[string]any)["final"] = "custom-exit"
			case "session":
				session = "replacement-session"
			case "rate":
				exit["daita_rate_kbps"] = 192
			case "ordinary-key":
				for _, raw := range graph["outbounds"].([]any) {
					if row := raw.(map[string]any); row["tag"] == "custom-exit" {
						row["password"] = "replacement-secret"
					}
				}
			case "missing-entry":
				delete(retained, "predecessor_profile")
			case "server", "compare":
				exit["multihop_execution"] = map[string]string{"server": "server", "compare": "auto"}[fault]
				retained["profile"] = torHostEncode(t, exit)
			case "missing-tun":
				delete(graph, "inbounds")
			case "duplicate-owner":
				graph["outbounds"] = append(graph["outbounds"].([]any), out)
			case "off":
				exit["daita_enabled"] = false
			}
			if sha, err := LocalPaddingSourceSHA256(torHostEncode(t, graph), torHostEncode(t, exit), session); err == nil || sha != "" || strings.Contains(err.Error(), "replacement-secret") {
				t.Fatal("changed native source acquired a receipt authority or exposed credentials", err)
			}
		})
	}
	profile := torHostProfile()
	profile["daita_enabled"], profile["daita_rate_kbps"] = false, 192
	raw := torHostEncode(t, profile)
	config, err := CompileProfileWithPredecessor(raw, "off-session", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sha, err := LocalPaddingSourceSHA256(config, raw, "off-session"); err != nil || sha != "" {
		t.Fatal("Off unexpectedly required an active padding owner", err)
	}
	profile["daita_enabled"], profile["daita_rate_kbps"] = true, 0
	capture, err := NewLocalPaddingCapture(&LocalPaddingSource{Profile: torHostEncode(t, profile)}, "default-session")
	if err != nil || capture.Policy().RateKbps != 192 {
		t.Fatal("enabled unset padding rate lost its exact default", err)
	}
}

func TestNativePaddingStatusUsesActualCompletedProofAndStableLeaseProgress(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	policy := TorPaddingPolicy{Enabled: true, RateKbps: 64}
	session, source := strings.Repeat("a", 64), strings.Repeat("b", 64)
	base := NativePaddingProofStatus{PathCheckedAt: now.Add(-time.Second).UnixMilli(), DNSCheckedAt: now.Add(-2 * time.Second).UnixMilli(),
		Receipt: &PaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell", SessionSHA256: session, SourceSHA256: source, Generation: 3, RateKbps: 64,
			ChannelCells: 10, ChannelBytes: 5140, ObservedAt: now.Add(-time.Second).UnixMilli(), ExpiresAt: now.Add(8 * time.Second).UnixMilli()}}
	if err := ValidateNativePaddingStatus(&base, policy, session, source, now); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"future-path", "future-dns", "missing-dns", "stale-dns", "after-path", "past-proof", "generation", "counter", "observation", "path-regress", "dns-regress", "missing"} {
		t.Run(fault, func(t *testing.T) {
			candidate, receipt := base, *base.Receipt
			candidate.Receipt = &receipt
			switch fault {
			case "future-path":
				candidate.PathCheckedAt = now.Add(time.Millisecond).UnixMilli()
			case "future-dns":
				candidate.DNSCheckedAt = now.Add(time.Millisecond).UnixMilli()
			case "missing-dns":
				candidate.DNSCheckedAt = 0
			case "stale-dns":
				candidate.DNSCheckedAt = now.Add(-PaddingProofMaxAge).UnixMilli()
			case "after-path":
				candidate.DNSCheckedAt = candidate.PathCheckedAt + 1
			case "past-proof":
				candidate.DNSCheckedAt = now.Add(-29 * time.Second).UnixMilli()
			case "generation":
				receipt.Generation++
			case "counter":
				receipt.ChannelCells--
				receipt.ChannelBytes -= 514
			case "observation":
				receipt.ObservedAt--
			case "path-regress":
				candidate.PathCheckedAt--
			case "dns-regress":
				candidate.DNSCheckedAt--
			case "missing":
				candidate.Receipt = nil
			}
			if ValidateNativePaddingStatus(&candidate, policy, session, source, now) == nil && ValidateNativePaddingProgress(&base, &candidate) == nil {
				t.Fatal("unproved, expired or replaced padding snapshot was accepted")
			}
		})
	}
	if ValidateNativePaddingStatus(&base, TorPaddingPolicy{}, session, source, now) == nil || ValidateNativePaddingStatus(nil, policy, session, source, now) == nil {
		t.Fatal("Off or missing status acquired a cover proof")
	}
	if err := ValidateNativePaddingProgress(&base, &base); err != nil {
		t.Fatal("same cached receipt cannot be read without extending its deadline", err)
	}
	if err := ValidateNativePaddingStatus(&base, policy, session, source, now.Add(9*time.Second)); err == nil {
		t.Fatal("re-reading a cached native status extended its expiry")
	}
}
