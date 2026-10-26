package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"router-vpn/internal/common"
)

func registeredDNSRuntimeSnapshotFixture(t *testing.T) (*app, string, observedConnection) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	path := filepath.Join(root, "run", "owned", "sing-box.json")
	writeDNSRuntimeTestConfig(t, path, "custom", "9.9.9.9", 53)
	profile := common.RouterProfile{ID: "node", DNSMode: "custom", DNSProtocol: "udp", DNSHost: "9.9.9.9", DNSPort: 53}
	a := &app{profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		state: state{Connected: true, Phase: "connected", RouterID: profile.ID, Mode: "external-node", RuntimeMode: "external-socks5"}}
	if err := registerActiveDNSRuntimeConfig(a, profile.ID, "external-socks5", path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearActiveDNSRuntimeConfig(a); desktopNodeOwners.Delete(a) })
	return a, path, observedConnection{Connected: true, Phase: "connected", RouterID: profile.ID, Profile: profile}
}

func replaceDNSRuntimeWithSamePolicy(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".retired"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNativeMultihopDNSRuntimeSnapshotRejectsReplacementBetweenCaptureAndRead(t *testing.T) {
	for _, change := range []string{"same-policy-file", "command", "native-owner", "registration", "node-policy", "public"} {
		t.Run(change, func(t *testing.T) {
			a, path, _ := registeredDNSRuntimeSnapshotFixture(t)
			source, owned, err := captureActiveDNSRuntimeSource(a, "node", "external-socks5")
			if err != nil || !owned {
				t.Fatal("private source capture failed", owned, err)
			}
			switch change {
			case "same-policy-file":
				replaceDNSRuntimeWithSamePolicy(t, path)
			case "command":
				a.cmd = &exec.Cmd{}
			case "native-owner":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{})
			case "registration":
				clearActiveDNSRuntimeConfig(a)
			case "node-policy":
				a.profiles.Profiles[0].DNSHost = "1.1.1.1"
			case "public":
				makeDNSRuntimeTestPublic(t, path)
			}
			if _, err := source.read(); err == nil {
				t.Fatal("changed captured DNS source reached policy validation", change)
			}
		})
	}
}

func TestNativeMultihopDNSRuntimeSnapshotRejectsChangesDuringLookup(t *testing.T) {
	for _, change := range []string{"none", "same-policy-file", "command", "native-owner", "registration", "node-policy", "public"} {
		t.Run(change, func(t *testing.T) {
			a, path, observation := registeredDNSRuntimeSnapshotFixture(t)
			calls := 0
			proof := proveSelectedDNSWithLookup(context.Background(), a, observation, "external-socks5", func(context.Context, string) ([]string, error) {
				calls++
				switch change {
				case "same-policy-file":
					replaceDNSRuntimeWithSamePolicy(t, path)
				case "command":
					a.cmd = &exec.Cmd{}
				case "native-owner":
					desktopNodeOwners.Store(a, &desktopNodeLaunch{})
				case "registration":
					clearActiveDNSRuntimeConfig(a)
				case "node-policy":
					a.profiles.Profiles[0].DNSHost = "1.1.1.1"
				case "public":
					makeDNSRuntimeTestPublic(t, path)
				}
				return []string{"192.0.2.1"}, nil
			})
			if calls != 1 || (proof.Status == "passed") != (change == "none") {
				t.Fatalf("lookup adopted a changed captured DNS owner: %s calls=%d proof=%+v", change, calls, proof)
			}
		})
	}
}

func TestNativeMultihopDNSRuntimeSnapshotNeverRepairsPublicInput(t *testing.T) {
	_, path, _ := registeredDNSRuntimeSnapshotFixture(t)
	makeDNSRuntimeTestPublic(t, path)
	if _, err := readPrivateRuntimeSnapshot(path, maxPrivateStoreBytes); err == nil {
		t.Fatal("public runtime snapshot was accepted")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateRuntimePathPermissions(path, info); err == nil {
		t.Fatal("active snapshot silently repaired private permissions")
	}
}
