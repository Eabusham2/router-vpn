package mobiletor

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Build the same immutable Local/Server inputs that the child independently
// reopens, preserving the exact private profile and any predecessor assets.
func desktopDeviceMTUInputs(t *testing.T, execution string, entry *DesktopPredecessor, edit func(map[string]any)) *DesktopBridgeInputs {
	t.Helper()
	exit := desktopProfile()
	if entry != nil {
		exit = desktopEntryExit(entry)
		exit["multihop_execution"] = execution
	}
	if edit != nil {
		edit(exit)
	}
	source := torHostEncode(t, exit)
	dir := t.TempDir()
	binary := filepath.Join(dir, "tor")
	var inputs *DesktopBridgeInputs
	var err error
	switch {
	case execution == "server":
		inputs, err = NewDesktopServerTorCapture(source, desktopSession, desktopIsolation, "linux", dir, entry)
	case entry != nil:
		inputs, err = NewDesktopBridgeCaptureWithPredecessor(source, desktopSession, desktopIsolation, "linux", binary, dir, entry)
	default:
		inputs, err = NewDesktopBridgeCapture(source, desktopSession, desktopIsolation, "linux", binary, dir)
	}
	if err != nil {
		t.Fatal(err)
	}
	return inputs
}

func TestDesktopTorDeviceFixedReconstructsOnlyOriginalClientInterface(t *testing.T) {
	for _, execution := range []string{"direct", "local", "server"} {
		t.Run(execution, func(t *testing.T) {
			var entry *DesktopPredecessor
			if execution != "direct" {
				entry, _ = desktopEntryFixture(t, "shadowsocks", "", nil)
			}
			original := desktopDeviceMTUInputs(t, execution, entry, nil)
			revision := strings.Repeat("a", 32)
			fixed, err := original.WithDeviceFixedMTU(revision, 8192)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := DecodeDesktopBridgeCapture(original.Policy().Profile(), fixed.JSON(), original.RuntimeDir())
			if err != nil || !reflect.DeepEqual(rebuilt, fixed) {
				t.Fatal("independent worker differed", err)
			}
			before, after := original.Policy().Metadata(), fixed.Policy().Metadata()
			tag, actual, err := MTUInterface(fixed.Policy().Config())
			if err != nil || tag != before.TUNTag || actual != 8192 || after.ConfiguredMTU != actual ||
				after.DeviceMTURevision != revision || after.DeviceFixedMTU != actual ||
				!before.AllowMTUOptimization() || after.AllowMTUOptimization() || after.NativeMTUPolicy() != "fixed" {
				t.Fatal("device authority or configured capacity changed", err, after)
			}
			if original.Policy().Profile() != fixed.Policy().Profile() || original.Digests().ProfileSHA256 != fixed.Digests().ProfileSHA256 ||
				!reflect.DeepEqual(original.Capture().Predecessor, fixed.Capture().Predecessor) || original.Capture().DeviceFixedMTU != nil ||
				original.Torrc() != fixed.Torrc() || before.SourceSHA256 == after.SourceSHA256 || before.ConfigSHA256 == after.ConfigSHA256 {
				t.Fatal("changed original source, Tor configuration or predecessor, or failed to seal client preference")
			}
			if execution == "server" && original.Policy().ServerPolicy().Source() != fixed.Policy().ServerPolicy().Source() {
				t.Fatal("client size changed remote Tor/DNS source")
			}
			before.SourceSHA256, before.ConfigSHA256 = after.SourceSHA256, after.ConfigSHA256
			before.ConfiguredMTU, before.DeviceFixedMTU, before.DeviceMTURevision = actual, actual, revision
			if before != after {
				t.Fatal("unrelated Tor policy changed", before, after)
			}
			other, err := original.WithDeviceFixedMTU(strings.Repeat("b", 32), 8192)
			if err != nil || other.Policy().SourceSHA256() == after.SourceSHA256 || other.Digests().ConfigSHA256 == after.ConfigSHA256 {
				t.Fatal("same-value revision reused a proof", err)
			}
			fixed.Capture().DeviceFixedMTU.MTU = 7777
			if fixed.Capture().DeviceFixedMTU.MTU != actual {
				t.Fatal("mutable capture escaped")
			}
			if _, err = fixed.WithDeviceFixedMTU(strings.Repeat("b", 32), actual); err == nil {
				t.Fatal("existing capture was rebound")
			}
		})
	}
}

func TestDesktopTorDeviceFixedValidatesTypedSourceAndEntry(t *testing.T) {
	revision := strings.Repeat("c", 32)
	original := desktopDeviceMTUInputs(t, "direct", nil, func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "manual", 1380 })
	valid, err := original.WithDeviceFixedMTU(revision, 1420)
	if err != nil || valid.Policy().Metadata().MTUPolicy != "manual" || original.Policy().Metadata().ConfiguredMTU != 1380 {
		t.Fatal("saved Fixed preference changed", err)
	}
	for _, bad := range []any{nil, map[string]any{}, map[string]any{"revision": strings.ToUpper(revision), "mtu": 1420}, map[string]any{"revision": revision, "mtu": "1420"}, map[string]any{"revision": revision, "mtu": 1279}, map[string]any{"revision": revision, "mtu": 9001}, map[string]any{"revision": revision, "mtu": 1400, "peer_mtu": 1400}} {
		var doc map[string]any
		if err := json.Unmarshal([]byte(original.JSON()), &doc); err != nil {
			t.Fatal(err)
		}
		doc["device_fixed_mtu"] = bad
		if _, err := DecodeDesktopBridgeCapture(original.Policy().Profile(), torHostEncode(t, doc), original.RuntimeDir()); err == nil {
			t.Fatal("worker accepted", bad)
		}
	}
	entry, _ := desktopEntryFixture(t, "wg", "", nil)
	packet := desktopDeviceMTUInputs(t, "server", entry, nil)
	if _, err := packet.WithDeviceFixedMTU(revision, 1400); err != nil {
		t.Fatal("valid packet capacity rejected", err)
	}
	if _, err := packet.WithDeviceFixedMTU(revision, 1500); err == nil {
		t.Fatal("independent 1420-byte WG packet envelope widened")
	}
	entry, _ = desktopEntryFixture(t, "shadowsocks", "", func(p map[string]any) { p["mtu_policy"], p["manual_mtu"] = "fixed", 1420 })
	preserved := desktopDeviceMTUInputs(t, "local", entry, nil)
	if _, err := preserved.WithDeviceFixedMTU(revision, 1380); err == nil {
		t.Fatal("replaced fixed predecessor")
	}
	if _, err := preserved.WithDeviceFixedMTU(revision, 1420); err != nil {
		t.Fatal("matching predecessor rejected", err)
	}
	jumbo := desktopDeviceMTUInputs(t, "direct", nil, func(p map[string]any) { p["jumbo_tun"] = true })
	if _, err := jumbo.WithDeviceFixedMTU(revision, 1420); err == nil {
		t.Fatal("narrowed saved Jumbo interface")
	}
	if _, err := jumbo.WithDeviceFixedMTU(revision, 9000); err != nil {
		t.Fatal("matching Jumbo rejected", err)
	}
}
