package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopExternalDeviceFixedOriginalAndWorkerReadback(t *testing.T) {
	const session = desktopExternalTestSession
	revision := strings.Repeat("b", 32)
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, protocol := range []string{"shadowsocks", "wireguard"} {
			t.Run(target+"/"+protocol, func(t *testing.T) {
				original := desktopExternalPolicyFixture(t, protocol, "off", "on", false)
				before := original.Config()
				const mtu = 1300
				p, err := NewDesktopExternalPolicyWithDevicePreference(original, session, target, revision, mtu)
				if err != nil {
					t.Fatal(err)
				}
				m := p.Metadata()
				if m.DeviceFixedMTU != mtu || m.DeviceRevision != revision || original.Config() != before || desktopExternalCapturedTestMTU(t, p.Config()) != float64(mtu) {
					t.Fatal("separate device TUN projection lost its source")
				}
				if _, err := RebuildDesktopExternalPolicy(original, session, target, m.SourceSHA256, []byte(p.Config())); err != nil {
					t.Fatal(err)
				}
				if _, err := RebuildDesktopExternalPolicy(original, session, target, m.SourceSHA256, []byte(strings.ReplaceAll(p.Config(), revision, strings.Repeat("c", 32)))); err == nil {
					t.Fatal("different device revision accepted")
				}
				proposal, err := NewDesktopExternalDevicePreference(original, session, revision, mtu)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(proposal)
				if _, err := ParseDesktopExternalDevicePreference(string(b), original, session); err != nil {
					t.Fatal(err)
				}
				proposal.Config = strings.Repeat("f", 64)
				b, _ = json.Marshal(proposal)
				if _, err := ParseDesktopExternalDevicePreference(string(b), original, session); err == nil {
					t.Fatal("preference applied to wrong source")
				}
				if protocol == "wireguard" {
					if _, err := NewDesktopExternalPolicyWithDevicePreference(original, session, target, revision, 9000); err == nil {
						t.Fatal("overrode packet endpoint ceiling")
					}
				}
			})
		}
	}
	server := desktopExternalRouterServerFixture(t, "server")
	p, err := NewDesktopExternalPolicyWithDevicePreference(server, session, "windows", revision, 1280)
	if err != nil {
		t.Fatal("server", err)
	}
	if _, err := RebuildDesktopExternalPolicy(server, session, "windows", p.Metadata().SourceSHA256, []byte(p.Config())); err != nil {
		t.Fatal(err)
	}
}

func desktopExternalCapturedTestMTU(t *testing.T, config string) any {
	t.Helper()
	for _, r := range startObject(t, config)["inbounds"].([]any) {
		if v := r.(map[string]any); v["type"] == "tun" {
			return v["mtu"]
		}
	}
	t.Fatal("no captured tun")
	return nil
}
