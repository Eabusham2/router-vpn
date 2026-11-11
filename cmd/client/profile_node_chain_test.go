package main

import (
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func catalogNodeChainProfile() common.RouterProfile {
	p := catalogTokenProfile()
	p.MultihopEnabled, p.MultihopExecution = true, "local"
	p.MultihopNodes = []common.MultihopNodeSelection{{ID: "first", Mode: "wg"}, {ID: "middle", Mode: "wg"}, {ID: p.ID, Mode: "shadowsocks"}}
	return p
}

func TestOrderedNodeCatalogTokenBindsEveryMemberAndOrder(t *testing.T) {
	for name, mutate := range map[string]func(*common.RouterProfile){
		"middle-relink":  func(p *common.RouterProfile) { p.MultihopNodes[1].ID = "replacement" },
		"middle-mode":    func(p *common.RouterProfile) { p.MultihopNodes[1].Mode = "awg2-fast" },
		"middle-removed": func(p *common.RouterProfile) { p.MultihopNodes = append(p.MultihopNodes[:1], p.MultihopNodes[2:]...) },
		"reorder": func(p *common.RouterProfile) {
			p.MultihopNodes[0], p.MultihopNodes[1] = p.MultihopNodes[1], p.MultihopNodes[0]
		},
		"fourth": func(p *common.RouterProfile) {
			p.MultihopNodes = append(p.MultihopNodes[:2], common.MultihopNodeSelection{ID: "fourth", Mode: "wg"}, p.MultihopNodes[2])
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := catalogNodeChainProfile()
			before := publicProfileToken(original)
			changed := cloneRouterProfile(original)
			mutate(&changed)
			if publicProfileToken(changed) == before || publicProfileToken(original) != before {
				t.Fatal("ordered selection mutation retained its revision or changed the original capture")
			}
		})
	}
}

func TestOrderedNodeCatalogViewOwnsCompleteNonsecretSelection(t *testing.T) {
	profile := catalogNodeChainProfile()
	view := publicProfileForCapabilities(profile, nil)
	if !reflect.DeepEqual(view.MultihopNodes, profile.MultihopNodes) {
		t.Fatal("public saved selection lost an ordered member")
	}
	view.MultihopNodes[1].ID = "replacement"
	if profile.MultihopNodes[1].ID != "middle" {
		t.Fatal("public view shared mutable private selection storage")
	}
}

func TestOrderedNodeCatalogRevisionsRequireEveryCurrentMember(t *testing.T) {
	p := catalogNodeChainProfile()
	a := &app{profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p, {ID: "first"}, {ID: "middle", APIToken: "original-middle"}}}}
	before, err := a.connectionProfileTokensLocked(p)
	if err != nil || len(before) != 3 || before["middle"] == "" {
		t.Fatalf("incomplete ordered catalog receipt: %v", err)
	}
	a.profiles.Profiles[2].APIToken = "relinked-middle"
	after, err := a.connectionProfileTokensLocked(p)
	if err != nil || before["middle"] == after["middle"] || before["first"] != after["first"] || before[p.ID] != after[p.ID] {
		t.Fatal("middle credential replacement was not independently visible")
	}
	a.profiles.Profiles = a.profiles.Profiles[:2]
	if _, err := a.connectionProfileTokensLocked(p); err == nil {
		t.Fatal("ordered catalog silently omitted an unlinked middle node")
	}
}
