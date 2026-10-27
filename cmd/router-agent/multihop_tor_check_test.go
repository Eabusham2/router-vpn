package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/multihoprelay"
)

func torRegistryCheckFixture(t *testing.T, root string) (string, string, string, multihoprelay.Config) {
	t.Helper()
	sources := filepath.Join(root, "tor-sources")
	if err := os.MkdirAll(sources, 0700); err != nil {
		t.Fatal(err)
	}
	config := multihoprelay.Config{ListenIP: "10.77.0.1", FirstPort: 26240, LastPort: 26271, TTLSeconds: 90}
	for _, mode := range []string{"tor", "tor-bridge"} {
		source := pairingTorSource(mode)
		source["id"] = mode + "-operator"
		raw, _ := json.Marshal(source)
		policy, err := mobiletor.NewServerTorPolicy(string(raw), pairingTorNode)
		if err != nil {
			t.Fatal(err)
		}
		config.TorExits = append(config.TorExits, multihoprelay.TorExitSource{ID: policy.ID(), Mode: policy.Mode(), SourceSHA256: policy.SourceSHA256(), DNSPolicySHA256: policy.DNSPolicySHA256()})
		if err := os.WriteFile(filepath.Join(sources, policy.SourceSHA256()+".json"), []byte(policy.Source()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config.Exits = []multihoprelay.Exit{{ID: "preserved-proxy", Mode: "shadowsocks", NodeID: strings.Repeat("b", 64), DNS: "10.88.0.1",
		Transport: map[string]any{"type": "shadowsocks", "tag": "exit", "server": "198.51.100.2", "server_port": 8388, "method": "aes-256-gcm", "password": "offline-validation-only"}}}
	registry, agent := filepath.Join(root, "registry.json"), filepath.Join(root, "agent.json")
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(registry, raw, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(cfg{NodeID: pairingTorNode, TunnelCIDRs: []string{"10.77.0.0/24"}})
	if err := os.WriteFile(agent, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return registry, agent, sources, config
}

func TestCheckRelayTorRegistryRequiresActualInstalledPackage(t *testing.T) {
	root := t.TempDir()
	registry, agent, sources, _ := torRegistryCheckFixture(t, root)
	_, err := checkRelayRegistryWithPaths(registry, agent, relayRegistryCheckPaths{
		torSources: sources, packagePrefix: root, core: filepath.Join(root, "unavailable-core"), temporary: filepath.Join(root, "checks"),
	})
	if err == nil || !strings.Contains(err.Error(), "Tor relay package is unavailable") {
		t.Fatal("Tor references passed without the installed native executable", err)
	}
	if _, err := os.Stat(filepath.Join(root, "checks")); !os.IsNotExist(err) {
		t.Fatal("failed package admission reached configuration execution")
	}
}

func TestCheckRelayTorRegistryWithRealPackageAndCore(t *testing.T) {
	packagePrefix, core := os.Getenv("ROUTERVPN_SERVER_TOR_PACKAGE"), os.Getenv("ROUTERVPN_SERVER_TOR_NATIVE_CLI")
	if packagePrefix == "" || core == "" {
		t.Skip("set actual compiled server Tor package/core paths for native image acceptance")
	}
	for _, fault := range []string{"valid", "source-missing", "source-public", "source-linked", "source-parent-linked", "source-directory-public", "wrong-entry", "wrong-dns", "wrong-mode", "changed-source", "invalid-core", "changed-package"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			registry, agent, sources, config := torRegistryCheckFixture(t, root)
			paths := relayRegistryCheckPaths{torSources: sources, packagePrefix: packagePrefix, core: core, temporary: filepath.Join(root, "checks")}
			path := filepath.Join(sources, config.TorExits[0].SourceSHA256+".json")
			switch fault {
			case "source-missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "source-public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "source-linked":
				if err := os.Rename(path, path+".owned"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".owned", path); err != nil {
					t.Fatal(err)
				}
			case "source-parent-linked":
				if err := os.Rename(sources, sources+".owned"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(sources+".owned", sources); err != nil {
					t.Fatal(err)
				}
			case "source-directory-public":
				if err := os.Chmod(sources, 0755); err != nil {
					t.Fatal(err)
				}
			case "wrong-entry":
				raw, _ := json.Marshal(cfg{NodeID: strings.Repeat("c", 64), TunnelCIDRs: []string{"10.77.0.0/24"}})
				if err := os.WriteFile(agent, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-dns":
				config.TorExits[0].DNSPolicySHA256 = strings.Repeat("c", 64)
			case "wrong-mode":
				config.TorExits[0].Mode = "tor-bridge"
			case "changed-source":
				raw, _ := os.ReadFile(path)
				raw = []byte(strings.Replace(string(raw), "192.168.50.133", "192.168.50.134", 1))
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-core":
				paths.core = filepath.Join(root, "missing-core")
			case "changed-package":
				paths.packagePrefix = root
			}
			raw, _ := json.Marshal(config)
			if err := os.WriteFile(registry, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(registry)
			count, err := checkRelayRegistryWithPaths(registry, agent, paths)
			if fault == "valid" {
				if err != nil || count != 3 {
					t.Fatal("actual native checker did not validate both Tor sources and the preserved proxy", count, err)
				}
			} else if err == nil || count != 0 {
				t.Fatal("invalid Tor registry was counted as accepted", fault, count)
			}
			after, _ := os.ReadFile(registry)
			if string(before) != string(after) {
				t.Fatal("offline checker modified the registry")
			}
			if entries, err := os.ReadDir(paths.temporary); err == nil && len(entries) != 0 {
				t.Fatal("offline checker left private native configuration files")
			}
		})
	}
}

// The operator integration suite uses this test-only entry point to execute
// the shipping checker against an isolated real package/core. Production CLI
// paths are fixed and deliberately have no environment override.
func TestRunOperatorStagedTorRegistryCheck(t *testing.T) {
	registry := os.Getenv("ROUTERVPN_TEST_TOR_REGISTRY")
	if registry == "" {
		t.Skip("operator integration supplies private staged paths")
	}
	packagePrefix, core := os.Getenv("ROUTERVPN_SERVER_TOR_PACKAGE"), os.Getenv("ROUTERVPN_SERVER_TOR_NATIVE_CLI")
	if packagePrefix == "" || core == "" {
		t.Fatal("operator native gate requires actual package and core")
	}
	_, err := checkRelayRegistryWithPaths(registry, os.Getenv("ROUTERVPN_TEST_TOR_AGENT"), relayRegistryCheckPaths{
		torSources: os.Getenv("ROUTERVPN_TEST_TOR_SOURCES"), packagePrefix: packagePrefix, core: core, temporary: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
}
