package mobiletor

import (
	"encoding/json"
	"testing"
)

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
