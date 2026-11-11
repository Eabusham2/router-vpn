package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func changeOrderedIdentityFiles(t *testing.T, a *app, index int, change func(string) string) {
	t.Helper()
	for _, name := range []string{"wg.conf", "wg-socks.conf"} {
		path := filepath.Join(clientRoot(a), "generated", a.profiles.Profiles[index].ID, "wg", name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(change(string(raw))), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopNodeChainIdentityInventoryReachesEveryNativeProjection(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 4)
	installOrderedAWGAssets(t, a, nodes, []string{"awg2-fast", "awg2-strong", "wg", "shadowsocks"}, "off")
	capture := captureNodeChainTest(t, a, nodes)
	for _, target := range []string{"windows", "linux", "darwin"} {
		t.Run(target, func(t *testing.T) {
			projected, err := capture.project(context.Background(), target, 0)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := projected.LaunchInput()
			var source mobilemultihop.NodeChainSource
			if err != nil || json.Unmarshal([]byte(launch), &source) != nil || len(source.IdentitySources) != len(nodes) {
				t.Fatal("desktop native source omitted complete original WG identity inventory", err)
			}
			for i, identity := range source.IdentitySources {
				var files map[string][]byte
				original, err := readDesktopNodeAssets(clientRoot(a), nodes[i].ID, "wg")
				if err != nil || json.Unmarshal([]byte(identity), &files) != nil || !reflect.DeepEqual(files, original) {
					t.Fatal("native projection substituted an original identity source", i, err)
				}
				clearViaEntryAssets(original)
				clearViaEntryAssets(files)
			}
			opened, err := mobilemultihop.ParseNodeChainLaunchInput(launch)
			if err != nil || opened.Config() != projected.Config() || opened.SourceSHA256() != projected.SourceSHA256() {
				t.Fatal("native reader could not reproduce complete identity capture", err)
			}
		})
	}
	previousConfig, previousSource := capture.chain.Config(), capture.chain.SourceSHA256()
	changeOrderedIdentityFiles(t, a, 0, func(raw string) string { return "# captured original identity revision\n" + raw })
	if capture.currentContext(context.Background(), a) == nil {
		t.Fatal("old identity capture accepted changed original bytes")
	}
	replacement := captureNodeChainTest(t, a, nodes)
	if replacement.chain.Config() != previousConfig || replacement.chain.SourceSHA256() == previousSource {
		t.Fatal("identity-only revision changed the requested transport or failed to change native source identity")
	}
}

func TestDesktopNodeChainIdentityParserRejectsMalformedUnusedWGCompanion(t *testing.T) {
	for _, index := range []int{0, 1, 3} {
		for _, fault := range []string{"private-key", "public-key", "unsupported-field"} {
			t.Run([]string{"first-awg", "middle-awg", "unused", "final-ss"}[index]+"/"+fault, func(t *testing.T) {
				a, nodes := desktopNodeChainCaptureFixture(t, 4)
				installOrderedAWGAssets(t, a, nodes, []string{"awg2-fast", "awg2-strong", "wg", "shadowsocks"}, "off")
				changeOrderedIdentityFiles(t, a, index, func(raw string) string {
					switch fault {
					case "private-key":
						return regexp.MustCompile(`(?m)^PrivateKey\s*=.*$`).ReplaceAllString(raw, "PrivateKey = AQ==")
					case "public-key":
						return regexp.MustCompile(`(?m)^PublicKey\s*=.*$`).ReplaceAllString(raw, "PublicKey = AQ==")
					default:
						return strings.Replace(raw, "[Interface]\n", "[Interface]\nPostUp = invalid-native-hook\n", 1)
					}
				})
				if fault == "public-key" {
					raw, err := os.ReadFile(filepath.Join(clientRoot(a), "generated", nodes[index].ID, "wg", "wg.conf"))
					if err != nil {
						t.Fatal(err)
					}
					a.profiles.Profiles[index].NodeProofID, err = nodeProofIDFromWGConfig(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
				control := common.CloneRouterProfile(a.profiles.Profiles[3])
				if capture, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, "local", nil); err == nil || capture != nil {
					t.Fatal("desktop native identity parser accepted malformed original WG companion")
				}
			})
		}
	}
}

func TestDesktopNodeChainIdentityUsesOnlyOriginalFirstHostBootstrap(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
			profile := &a.profiles.Profiles[0]
			original, hostname := profile.Endpoint, "ordered-first.example.test"
			for _, family := range []string{"wg", "awg2-fast", "awg2-strong"} {
				directory := filepath.Join(clientRoot(a), "generated", profile.ID, family)
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					path := filepath.Join(directory, entry.Name())
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), original, hostname)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			profile.Endpoint = hostname
			control := common.CloneRouterProfile(a.profiles.Profiles[2])
			lookups := 0
			capture, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, "local", func(_ context.Context, host string) ([]netip.Addr, error) {
				lookups++
				if host != hostname {
					t.Fatal("identity validation looked up another node")
				}
				return []netip.Addr{netip.MustParseAddr(original)}, nil
			})
			if err != nil || lookups != 1 || capture.endpoint != original || capture.members[0].Profile.Endpoint != hostname || a.profiles.Profiles[0].Endpoint != hostname {
				t.Fatal("identity validation changed original host ownership or repeated bootstrap", err, lookups)
			}
			launch, err := capture.chain.LaunchInput()
			var source mobilemultihop.NodeChainSource
			if err != nil || json.Unmarshal([]byte(launch), &source) != nil || len(source.IdentitySources) != 3 {
				t.Fatal("hostname identity inventory missing", err)
			}
			if _, err := mobilemultihop.ParseNodeChainLaunchInput(launch); err != nil {
				t.Fatal("native reader rejected same captured bootstrap", err)
			}
			if capture.currentContext(context.Background(), a) != nil {
				t.Fatal("original hostname source was not retained")
			}
		})
	}
}
