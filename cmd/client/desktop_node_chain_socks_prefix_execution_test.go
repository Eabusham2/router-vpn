package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestDesktopSOCKSPrefixExecutionSelectionBounds(t *testing.T) {
	for prefixes := 1; prefixes <= 6; prefixes++ {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, protocol := range []string{"socks5"} {
				t.Run(fmt.Sprintf("%d-%s-%s", prefixes, mode, protocol), func(t *testing.T) {
					a, nodes := desktopSOCKSPrefixProductApp(t, prefixes, mode, protocol)
					for _, choice := range []string{"server", "auto"} {
						selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[prefixes+1], a.profiles.Profiles, nodes, choice)
						if err != nil || !desktopSOCKSTrioExecutionMembers(selection.Nodes, choice) ||
							!reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodes) {
							t.Fatal("complete original SOCKS path refused or reordered", choice, err)
						}
						if _, err := resolveDesktopNodeChainSOCKSMembers(selection.Control, a.profiles.Profiles, nodes, choice); err == nil {
							t.Fatal("execution choice entered Local-only constructor")
						}
					}
				})
			}
		}
	}
}

func TestDesktopSOCKSPrefixExecutionOriginalPreparation(t *testing.T) {
	for _, prefixes := range []int{2, 6} {
		for _, target := range []string{"windows", "linux", "darwin"} {
			for _, protocol := range []string{"socks5"} {
				for _, choice := range []string{"server", "auto"} {
					t.Run(fmt.Sprintf("%d-%s-%s-%s", prefixes, target, protocol, choice), func(t *testing.T) {
						a, nodes := desktopSOCKSPrefixProductApp(t, prefixes, "awg2-strong", protocol)
						selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[prefixes+1], a.profiles.Profiles, nodes, choice)
						if err != nil {
							t.Fatal(err)
						}
						selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
						if err != nil {
							t.Fatal("complete original SOCKS source capture", err)
						}
						launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
						if err != nil {
							t.Fatal(err)
						}
						owner, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
						if err != nil {
							t.Fatal("complete typed execution preparation", err)
						}
						original, err := owner.socksPhysical.OriginalDesktopSOCKSPolicy()
						if err != nil || original != launch.chain.socksPolicy || owner.physical != nil || owner.connectPhysical != nil {
							t.Fatal("SOCKS execution replaced original physical authority", err)
						}
						native, err := original.NativeSource()
						captured, sourceErr := owner.preparation.OriginalSOCKSSource()
						if err != nil || sourceErr != nil || native != captured {
							t.Fatal("SOCKS execution borrowed a different captured source")
						}
						var source mobilemultihop.NodeChainSource
						if json.Unmarshal([]byte(owner.preparation.LocalSource()), &source) != nil || source.Schema != 3 || len(source.Nodes) != prefixes+2 || len(source.IdentitySources) != prefixes+2 {
							t.Fatal("complete SOCKS execution source inventory changed")
						}
						for position, identity := range source.IdentitySources {
							if (identity == "") != (position == prefixes) {
								t.Fatal("complete SOCKS execution substituted private identity", position)
							}
						}
						_, meta, policy, err := owner.readPolicy()
						if err != nil || meta.TargetOS != target || len(meta.Prefixes) != prefixes+2 || meta.Prefixes[prefixes].NodeKind != "external" || meta.Prefixes[prefixes].NodeID != "" ||
							policy.SelectedDNS.Physical || policy.SelectedDNS.Detour != mobilemultihop.SelectorTag || len(policy.PhysicalRoots) != 1 {
							t.Fatal("complete SOCKS source lost global proof, selected DNS or first physical root", err)
						}
						for position, prefix := range meta.Prefixes {
							if prefix.Position != position || prefix.ProfileID != nodes[position].ID || prefix.Mode != nodes[position].Mode {
								t.Fatal("SOCKS execution reordered captured proof positions", position)
							}
						}
						if _, err := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(owner.preparation.Source()); err == nil {
							t.Fatal("complete SOCKS execution entered generic paired parser")
						}
						if err := owner.attach(launch); err != nil {
							t.Fatal(err)
						}
						replacement, err := mobilemultihop.ParseDesktopNodeChainSOCKSExecutionPreparation(owner.preparation.Source())
						if err != nil {
							t.Fatal("replacement control failed before ownership boundary", err)
						}
						owner.preparation = replacement
						if owner.validateSource() == nil {
							t.Fatal("equal serialized SOCKS preparation replaced its original owner")
						}
					})
				}
			}
		}
	}
}

func TestDesktopSOCKSPrefixExecutionSourceRefusals(t *testing.T) {
	a, launch := desktopSOCKSPrefixProductLaunchFixture(t, 6, "wg", "socks5")
	_ = a
	for _, fault := range []string{"old-middle", "two-imports", "prefix-mode", "prefix-layer", "duplicate-id", "duplicate-proof", "missing-proof", "hostname", "credentials", "paired-import", "wrong-final", "final-layer", "too-many", "connect-family"} {
		t.Run(fault, func(t *testing.T) {
			members := cloneDesktopNodeChainMembers(launch.chain.selection.Nodes)
			switch fault {
			case "old-middle":
				members[1], members[6] = members[6], members[1]
			case "two-imports":
				members[1] = members[6]
				members[1].Profile.ID = "other-import"
			case "prefix-mode":
				members[3].Mode = "hysteria2"
			case "prefix-layer":
				members[3].Profile.StartLayer = "unsupported"
			case "duplicate-id":
				members[3].Profile.ID = members[0].Profile.ID
			case "duplicate-proof":
				members[3].Profile.NodeProofID = members[0].Profile.NodeProofID
			case "missing-proof":
				members[3].Profile.NodeProofID = ""
			case "hostname":
				members[6].Profile.Endpoint = "proxy.example.test"
				members[6].Profile.External.SOCKS5.Host = members[6].Profile.Endpoint
			case "credentials":
				members[6].Profile.External.SOCKS5.Password = ""
			case "paired-import":
				members[6].Profile.NodeKind = "router-vpn"
			case "wrong-final":
				members[7].Mode = "hysteria2"
			case "final-layer":
				members[7].Profile.StartLayer = "aes-256-gcm"
			case "too-many":
				members = append([]desktopNodeChainMember{members[0]}, members...)
			case "connect-family":
				members[6].Mode = "http-connect"
			}
			for _, choice := range []string{"server", "auto"} {
				if desktopSOCKSTrioExecutionMembers(members, choice) || desktopOrderedExecutionMembers(members, choice) == nil {
					t.Fatal("SOCKS execution admitted changed source", choice, fault)
				}
			}
		})
	}
}

func TestDesktopSOCKSPrefixExecutionPublic4Server(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 4, "server", "server")
}
func TestDesktopSOCKSPrefixExecutionPublic4CompareLocal(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 4, "auto", "local")
}
func TestDesktopSOCKSPrefixExecutionPublic4CompareServer(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 4, "auto", "server")
}
func TestDesktopSOCKSPrefixExecutionPublic8Server(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 8, "server", "server")
}
func TestDesktopSOCKSPrefixExecutionPublic8CompareLocal(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 8, "auto", "local")
}
func TestDesktopSOCKSPrefixExecutionPublic8CompareServer(t *testing.T) {
	testDesktopSOCKSPrefixExecutionPublic(t, 8, "auto", "server")
}

func TestDesktopSOCKSPrefixExecutionSavedProfileRetainsSource(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testDesktopSOCKSExecutionSavedProfile(t, count) })
	}
}

func desktopSOCKSPrefixProductApp(t *testing.T, prefixes int, mode, protocol string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	if protocol != "socks5" {
		t.Fatal("SOCKS fixture changed protocol")
	}
	return desktopSOCKSPrefixCaptureFixture(t, prefixes, mode, "password", "off")
}
func desktopSOCKSPrefixProductLaunchFixture(t *testing.T, prefixes int, mode, protocol string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopSOCKSPrefixProductApp(t, prefixes, mode, protocol)
	selected, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[prefixes+1], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selected, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("a", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}
