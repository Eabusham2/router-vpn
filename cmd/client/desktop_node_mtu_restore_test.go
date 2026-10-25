package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const nativeMTURestoreGraph = `{"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":19100},{"type":"tun","tag":"system","mtu":1420,"auto_route":true}],"endpoints":[{"type":"wireguard","tag":"entry","mtu":1300,"private_key":"fixture-key"}],"dns":{"servers":[{"type":"udp","server":"10.77.0.1"}]},"route":{"final":"captured-exit"}}`

func nodeRestoreFixture(t *testing.T) (*desktopNodeMTUFixture, []byte, []byte) {
	t.Helper()
	fixture := newDesktopNodeMTUFixture(t)
	config := []byte(nativeMTURestoreGraph)
	digest := sha256.Sum256(config)
	fixture.launch.configSHA256 = hex.EncodeToString(digest[:])
	fixture.base.Config, fixture.base.MTU = fixture.launch.configSHA256, 1380
	if err := fixture.publish(fixture.base, false); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]any{"schema": 1, "profile_id": "captured-node", "mode": "shadowsocks", "config_sha256": fixture.launch.configSHA256, "source_sha256": strings.Repeat("c", 64)})
	return fixture, config, metadata
}

func TestNativeRestoreKeepsActualTUNMTUWithoutChangingEntryDNSOrCredentials(t *testing.T) {
	fixture, config, metadata := nodeRestoreFixture(t)
	original := append([]byte(nil), config...)
	restored, receipt, err := capturedDesktopNodeRestoreGraph(fixture.launch, config, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(config, original) {
		t.Fatal("restore mutated its original captured graph")
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(config, &before)
	_ = json.Unmarshal(restored, &after)
	for _, key := range []string{"endpoints", "dns", "route"} {
		if !bytes.Equal(before[key], after[key]) {
			t.Fatal("restore changed a non-system-TUN field", key)
		}
	}
	var inbounds []map[string]any
	_ = json.Unmarshal(after["inbounds"], &inbounds)
	if inbounds[1]["mtu"] != float64(1380) || inbounds[0]["listen_port"] != float64(19100) {
		t.Fatal("restore lost measured TUN state or changed its proof proxy", inbounds)
	}
	var capture map[string]any
	_ = json.Unmarshal(receipt, &capture)
	digest := sha256.Sum256(restored)
	if capture["config_sha256"] != hex.EncodeToString(digest[:]) || capture["source_sha256"] != strings.Repeat("c", 64) || capture["profile_id"] != "captured-node" {
		t.Fatal("restore did not rebind only the new graph digest", capture)
	}
}

func TestNativeRestoreRefusesProvisionalForeignOrStaleMTU(t *testing.T) {
	for _, change := range []string{"active", "failed", "wrong-session", "wrong-config", "stale", "wrong-metadata", "rewritten-config"} {
		t.Run(change, func(t *testing.T) {
			fixture, config, metadata := nodeRestoreFixture(t)
			record := fixture.base
			switch change {
			case "active":
				record.Active = true
			case "failed":
				record.Failure = "rollback unconfirmed"
			case "wrong-session":
				record.Session = strings.Repeat("f", 32)
			case "wrong-config":
				record.Config = strings.Repeat("f", 64)
			case "wrong-metadata":
				metadata = []byte(`{"config_sha256":"` + strings.Repeat("f", 64) + `"}`)
			case "rewritten-config":
				config = bytes.Replace(config, []byte("fixture-key"), []byte("different-key"), 1)
			}
			if err := fixture.publish(record, false); err != nil {
				t.Fatal(err)
			}
			if change == "stale" {
				record.Heartbeat = 1
				raw, _ := json.Marshal(record)
				if err := fixture.launch.directoryRoot.Remove("node-mtu-status.json"); err != nil {
					t.Fatal(err)
				}
				if err := writeDesktopRuntimeFile(fixture.launch, "node-mtu-status.json", raw, false); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := capturedDesktopNodeRestoreGraph(fixture.launch, config, metadata); err == nil {
				t.Fatal("restore accepted unproved live MTU", change)
			}
		})
	}
}

func TestNativeMTURestoreRequiresOneValidSystemTUN(t *testing.T) {
	for _, config := range []string{`null`, `{}`, `{"inbounds":[]}`, `{"inbounds":[{"type":"mixed"}]}`, `{"inbounds":[{"type":"tun","mtu":1420},{"type":"tun","mtu":1420}]}`, `{"inbounds":[{"type":"tun","mtu":1200}]}`, `{"inbounds":[{"type":"tun","mtu":1420.5}]}`} {
		if _, err := restoreDesktopNodeTUNMTU([]byte(config), 1380); err == nil {
			t.Fatal("malformed restore graph was accepted", config)
		}
	}
	for _, mtu := range []int{0, 1200, 1279, 9001} {
		if _, err := restoreDesktopNodeTUNMTU([]byte(nativeMTURestoreGraph), mtu); err == nil {
			t.Fatal("invalid restored MTU was accepted", mtu)
		}
	}
}
