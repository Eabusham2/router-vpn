package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestDesktopSingleNodeOffKeepsOriginalSourceAndPlatform(t *testing.T) {
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, layer)
				profile["kill_switch_policy"], profile["kill_switch"] = "off", false
				profile["ipv6_mode"], profile["home_lan_access"] = "on", false
				original, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
				if err != nil {
					t.Fatal(err)
				}
				source, err := original.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				for _, target := range []string{"windows", "linux", "darwin"} {
					policy, err := NewDesktopNodePolicy(original, desktopNodeTestSession, target)
					if target == "darwin" && !DesktopLinuxNodePhysicalGraphSupported(mode, layer) {
						if policy != nil || err == nil {
							t.Fatal("Darwin Off admitted a graph without retained native composition", mode, layer)
						}
						continue
					}
					if err != nil {
						t.Fatal(target, err)
					}
					assertDesktopNodeExactDerivation(t, policy)
					if policy.Metadata().KillSwitchPolicy != "off" || policy.OriginalProfile() != original {
						t.Fatal("Off changed original policy authority")
					}
					replay, err := ParseNodeLaunchInput(source)
					if err != nil {
						t.Fatal(err)
					}
					restored, err := NewDesktopNodePolicyWithMTU(replay, desktopNodeTestSession, target, 0)
					if err != nil || restored.Config() != policy.Config() || !reflect.DeepEqual(restored.Metadata(), policy.Metadata()) {
						t.Fatal("Off source restoration changed original compiled graph", err)
					}
					changed := *policy
					changed.metadata.KillSwitchPolicy = "on-connect"
					if changed.Validate() == nil {
						t.Fatal("Off accepted metadata-only protected substitution")
					}
				}
				if p, err := NewDesktopNodePolicy(original, desktopNodeTestSession, "freebsd"); p != nil || err == nil {
					t.Fatal("Off opened an unsupported native host")
				}
			})
		}
	}
}
