//go:build linux || windows || (darwin && (amd64 || arm64))

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

func orderedImportedPrefixCatalogFixture(t *testing.T, count int, hostname bool) (*app, orderedCandidatePreparationRequest) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	if hostname {
		installDesktopOrderedHostname(t, a, nodes)
	} else {
		installDesktopOrderedImported(t, a, nodes)
	}
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	// The absent imported suffix still owns these saved protection restrictions.
	middle := &a.profiles.Profiles[count-2]
	middle.KillSwitchPolicy, middle.IPv6Mode, middle.HomeLANAccess = "always", "off", false
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	return a, orderedCandidatePreparationRequest{RequestID: strings.Repeat("a", 32), Position: count - 3, CandidateIDs: []string{id}, Samples: 50, Scope: orderedCandidateSavedPrefixScope}
}

func TestOrderedCandidatePrefixImportedSavedCatalog(t *testing.T) {
	for _, count := range []int{4, 8} {
		for _, hostname := range []bool{false, true} {
			kind := "literal"
			if hostname {
				kind = "hostname"
			}
			t.Run(fmt.Sprintf("%d-%s", count, kind), func(t *testing.T) {
				a, q := orderedImportedPrefixCatalogFixture(t, count, hostname)
				before, state := cloneRouterProfileStore(a.profiles), a.state
				observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
				view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, q.Position, q.Scope, observe)
				if err != nil {
					t.Fatal("saved imported prefix chooser borrowed the connected-path gate", err)
				}
				p := beginOrderedPreparationFixture(t, a, q)
				if !view.matchesPreparation(p, time.Now()) || p.prefixPreparation == nil || p.inventory.prefixPreparation != p.prefixPreparation || p.inventory.plan != nil || view.catalog.plan != nil ||
					len(p.selection.Nodes) != count || p.selection.Nodes[count-2].Profile.External == nil ||
					p.prefixPreparation.OriginalSourceSHA256() != p.selection.Native.source {
					t.Fatal("saved prefix lost its complete original source or borrowed full-path authority")
				}
				if len(view.prefixes) != count-2 || view.prefixes[len(view.prefixes)-1].Position != q.Position {
					t.Fatal("chooser exposed the imported suffix or lost a paired prefix", view.prefixes)
				}
				if _, err := captureDesktopNodeChainCandidateSources(context.Background(), a, p.inventory.launch, q.Position, q.CandidateIDs); err == nil {
					t.Fatal("saved prefix widened the independent connected-path candidate gate")
				}
				if p.inventory.current(context.Background()) == nil || p.inventory.pulseCurrent(context.Background()) == nil {
					t.Fatal("closed prefix catalog acquired connected measurement authority")
				}
				current, err := captureDesktopNodeChainCandidateSourcesForScope(context.Background(), a, p.inventory.launch, q.Position, q.CandidateIDs, q.Scope)
				if err != nil || !orderedCandidateSameInventory(p.inventory, current) {
					t.Fatal("fresh saved-prefix recapture lost its original source", err)
				}
				if err := p.sourceCurrent(context.Background()); err != nil {
					t.Fatal(err)
				}
				launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "windows", p)
				if err != nil {
					t.Fatal("closed saved prefix could not reach its distinct native preparation", err)
				}
				meta := launch.candidatePrefix.policy.Metadata()
				if meta.ApplicationOpen || meta.DNSOpen || meta.PrefixPosition != q.Position || len(meta.Prefixes) != count-2 || meta.PolicyProfileID != before.SelectedID ||
					meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess || launch.chain != nil || launch.command != nil {
					t.Fatal("prefix projection lost the absent suffix policy or opened ordinary traffic", meta)
				}
				if err := p.finish(); err != nil {
					t.Fatal(err)
				}
				if !p.down || !p.owner.drained || a.candidatePreparation != nil || a.connectionContext != nil || a.cmd != nil || a.state != state || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("unused saved-prefix purpose changed Home or complete saved preferences")
				}
			})
		}
	}
}

func TestOrderedCandidatePrefixImportedSavedRefusals(t *testing.T) {
	for _, fault := range []string{"complete-scope", "imported-position", "final-position", "foreign-prefix-owner", "changed-scope", "candidate-secret", "final-asset", "physical-network"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedImportedPrefixCatalogFixture(t, 4, false)
			switch fault {
			case "complete-scope":
				q.Scope = orderedCandidateSavedCompleteScope
			case "imported-position":
				q.Position = 2
			case "final-position":
				q.Position = 3
			}
			observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
			if fault == "complete-scope" || fault == "imported-position" || fault == "final-position" {
				if err == nil {
					_ = p.finish()
					t.Fatal("saved prefix admitted a full-path purpose or non-packet suffix")
				}
				if a.state.Connected || a.candidatePreparation != nil || a.connectionContext != nil {
					t.Fatal("rejected prefix left an admitted connection owner")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.finish() })
			switch fault {
			case "foreign-prefix-owner":
				other, err := mobilemultihop.ParseNodeChainCandidatePreparation(p.prefixPreparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				p.prefixPreparation = other
			case "changed-scope":
				p.request.Scope = orderedCandidateSavedCompleteScope
			case "candidate-secret":
				a.profiles.Profiles[len(a.profiles.Profiles)-1].External.Shadowsocks.Password = strings.Repeat("A", 43) + "="
			case "final-asset":
				path := filepath.Join(clientRoot(a), "generated", a.profiles.SelectedID, "shadowsocks", "sing-box.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "physical-network":
				p.observeNetwork = func(ctx context.Context) (string, error) { return "replacement-physical-network", ctx.Err() }
			}
			if p.sourceCurrent(context.Background()) == nil || !p.invalidated.Load() || a.state.Connected {
				t.Fatal("saved prefix revived a changed source, purpose or physical owner")
			}
		})
	}
}
