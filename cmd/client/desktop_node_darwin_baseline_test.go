package main

import (
	"encoding/json"
	"router-vpn/internal/macosprocess"
	"strings"
	"testing"
)

func TestDesktopDarwinPairedBaselineBindsOriginalCapture(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "ss-v2ray", "naive-h2"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, policy := range []string{"off", "on-connect", "always"} {
				t.Run(mode+"/"+layer+"/"+policy, func(t *testing.T) {
					capture := desktopMacOSNodeSelection{Schema: 1, Family: macosprocess.NodeFamily, ProfileID: "original", NodeID: strings.Repeat("a", 64), Mode: mode, StartLayer: layer, Session: strings.Repeat("b", 32), Source: strings.Repeat("c", 64), Config: strings.Repeat("d", 64), Policy: policy}
					value := desktopMacOSNodeReceipt{Schema: 1, Capture: capture, Phase: "active", Token: "1", Baseline: desktopMacOSBaselineProof{Present: true, Rules: strings.Repeat("e", 64)}}
					raw, _ := json.Marshal(value)
					if _, err := decodeDesktopMacOSNodeReceipt(raw, capture, "active"); err != nil {
						t.Fatal(err)
					}
					for name, change := range map[string]func(*desktopMacOSNodeReceipt){
						"source":              func(v *desktopMacOSNodeReceipt) { v.Capture.Source = strings.Repeat("f", 64) },
						"family":              func(v *desktopMacOSNodeReceipt) { v.Capture.Family = macosprocess.NodeChainFamily },
						"policy":              func(v *desktopMacOSNodeReceipt) { v.Capture.Policy = "unknown" },
						"layer":               func(v *desktopMacOSNodeReceipt) { v.Capture.StartLayer = "unknown" },
						"node":                func(v *desktopMacOSNodeReceipt) { v.Capture.NodeID = strings.Repeat("f", 64) },
						"token":               func(v *desktopMacOSNodeReceipt) { v.Token = "0" },
						"phase":               func(v *desktopMacOSNodeReceipt) { v.Phase = "retired" },
						"absent-active-guard": func(v *desktopMacOSNodeReceipt) { v.Baseline = desktopMacOSBaselineProof{} },
					} {
						changed := value
						change(&changed)
						body, _ := json.Marshal(changed)
						if _, err := decodeDesktopMacOSNodeReceipt(body, capture, "active"); err == nil {
							t.Fatal("accepted changed original native receipt", name)
						}
					}
					for _, broken := range [][]byte{append(append([]byte(nil), raw...), []byte("{}")...), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1)), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"foreign":true`, 1))} {
						if _, err := decodeDesktopMacOSNodeReceipt(broken, capture, "active"); err == nil {
							t.Fatal("accepted noncanonical receipt fields")
						}
					}
				})
			}
		}
	}
}
