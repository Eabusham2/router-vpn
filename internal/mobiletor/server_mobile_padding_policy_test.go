package mobiletor

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestMobileServerTorPaddingBindsSavedSourceNativeOwnerAndMTU(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge", "snowflake"} {
		for _, home := range []bool{false, true} {
			for _, rate := range []int{-1, 0, 32, 64, 192} {
				t.Run(fmt.Sprintf("%s/home=%t/rate=%d", mode, home, rate), func(t *testing.T) {
					options := mobileServerFixture(t, mode, home)
					profile, _ := profileObject(options.Profile, 256<<10)
					profile["daita_enabled"] = true
					if rate >= 0 {
						profile["daita_rate_kbps"] = rate
					}
					options.Profile = torHostEncode(t, profile)
					if err := ValidateProfile(options.Profile); err != nil {
						t.Fatal("bounded Server cover cannot survive idle validation", err)
					}
					policy, err := NewMobileServerTorPolicy(options)
					want := rate
					if want <= 0 {
						want = PaddingDefaultRateKbps
					}
					if err != nil || policy.Options() != options || policy.ServerPolicy().Padding() != (TorPaddingPolicy{Enabled: true, RateKbps: want}) {
						t.Fatal("Server source silently changed the requested cover", err)
					}
					graph, _ := profileObject(policy.Config(), 4<<20)
					outbound := torHostTagged(t, graph["outbounds"], ProfileOutboundTag)
					if outbound["type"] != ServerTorClientType || outbound["profile"] != options.Profile || len(outbound) != 6 {
						t.Fatal("native Server owner did not retain the complete enabled source")
					}
					for _, raw := range graph["outbounds"].([]any) {
						if raw.(map[string]any)["type"] == "routervpn-tor" {
							t.Fatal("data-only Local template escaped into the enabled Server graph")
						}
					}
					replayed, err := NewMobileServerTorPolicy(policy.Options())
					if err != nil || replayed.Config() != policy.Config() || replayed.ServerPolicy().SourceSHA256() != policy.ServerPolicy().SourceSHA256() {
						t.Fatal("actual native constructor cannot reconstruct the enabled policy", err)
					}
					if _, err := ServerMTUAuthority(policy.Config(), options.Profile, options.SessionID, policy.EntryProof()); err != nil {
						t.Fatal("enabled cover lost its actual Server MTU owner", err)
					}
					changed := make(map[string]any, len(profile))
					for key, value := range profile {
						changed[key] = value
					}
					changed["daita_rate_kbps"] = 96
					if _, err := ServerMTUAuthority(policy.Config(), torHostEncode(t, changed), options.SessionID, policy.EntryProof()); err == nil {
						t.Fatal("different saved rate acquired the proved Server MTU authority")
					}
					for _, predecessor := range []string{"", options.EntryConfig} {
						if config, err := CompileProfile(options.Profile, options.SessionID, predecessor); err == nil || config != "" {
							t.Fatal("enabled Server source acquired a Local runtime", err)
						}
					}
					if _, err := CompileProfileWithPredecessor(options.Profile, options.SessionID, options.EntryConfig, options.EntryProfile); err == nil {
						t.Fatal("enabled Server source bypassed the actual Server compiler")
					}
					if local, err := NewLocalPaddingCapture(&LocalPaddingSource{Profile: options.Profile, PredecessorProfile: options.EntryProfile, PredecessorConfig: options.EntryConfig}, options.SessionID); err == nil || local != nil {
						t.Fatal("enabled Server cover borrowed a Local native lease source")
					}
					if options.Profile != torHostEncode(t, profile) {
						t.Fatal("Server compilation changed the immutable saved cover source")
					}
				})
			}
		}
	}
}

func TestMobileServerTorPaddingStillRequiresExactPrivateServerPath(t *testing.T) {
	for _, fault := range []string{"direct", "local", "compare", "missing-entry", "missing-proof", "ordinary-entry", "entry-id", "exit-id", "enabled-type", "rate-type", "rate-min", "rate-max"} {
		t.Run(fault, func(t *testing.T) {
			options := mobileServerFixture(t, "tor-bridge", true)
			profile, _ := profileObject(options.Profile, 256<<10)
			profile["daita_enabled"], profile["daita_rate_kbps"] = true, 64
			switch fault {
			case "direct":
				profile["multihop_enabled"] = false
			case "local":
				profile["multihop_execution"] = "local"
			case "compare":
				profile["multihop_execution"] = "auto"
			case "missing-entry":
				options.EntryConfig = ""
			case "missing-proof":
				options.EntryProfile = ""
			case "ordinary-entry":
				options.EntryProfile = strings.Replace(options.EntryProfile, "router-vpn", "external", 1)
			case "entry-id":
				profile["multihop_entry_id"] = "different-entry"
			case "exit-id":
				profile["multihop_exit_id"] = "different-exit"
			case "enabled-type":
				profile["daita_enabled"] = "true"
			case "rate-type":
				profile["daita_rate_kbps"] = "64"
			case "rate-min":
				profile["daita_rate_kbps"] = 31
			case "rate-max":
				profile["daita_rate_kbps"] = 193
			}
			options.Profile = torHostEncode(t, profile)
			if policy, err := NewMobileServerTorPolicy(options); err == nil || policy != nil {
				t.Fatal("enabled cover invented private Server authority")
			}
		})
	}
}

func TestMobileServerTorPreservesDormantCoverInExactRegistrySource(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge", "snowflake"} {
		for _, home := range []bool{false, true} {
			base := mobileServerFixture(t, mode, home)
			original, err := NewMobileServerTorPolicy(base)
			if err != nil {
				t.Fatal(err)
			}
			for _, rate := range []int{0, 32, 192} {
				profile, err := profileObject(base.Profile, 256<<10)
				if err != nil {
					t.Fatal(err)
				}
				profile["daita_enabled"], profile["daita_rate_kbps"] = false, rate
				options := base
				options.Profile = torHostEncode(t, profile)
				policy, err := NewMobileServerTorPolicy(options)
				if err != nil || policy.Options() != options || policy.ServerPolicy().Padding() != (TorPaddingPolicy{Enabled: false, RateKbps: rate}) {
					t.Fatal("Server compiler dropped or enabled a saved dormant choice", mode, home, rate, err)
				}
				if policy.ServerPolicy().SourceSHA256() == original.ServerPolicy().SourceSHA256() || policy.ServerPolicy().DNSPolicySHA256() != original.ServerPolicy().DNSPolicySHA256() {
					t.Fatal("registry source ignored selected cover or changed DNS")
				}
				var source map[string]any
				if json.Unmarshal([]byte(policy.ServerPolicy().Source()), &source) != nil || source["padding"] == nil {
					t.Fatal("operator source cannot reproduce the client's captured choice")
				}
				replayed, err := NewServerTorPolicy(policy.ServerPolicy().Source(), policy.EntryProof().NodeID())
				if err != nil || replayed.SourceSHA256() != policy.ServerPolicy().SourceSHA256() || replayed.Padding() != policy.ServerPolicy().Padding() {
					t.Fatal("canonical operator source disagrees with native client compiler", err)
				}
			}
		}
	}
}
