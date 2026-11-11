package common

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nodeChainProfile(count int) RouterProfile {
	p := RouterProfile{ID: "control", MultihopEnabled: true, MultihopExecution: "local"}
	for i := 0; i < count; i++ {
		mode := "wg"
		if i == count-1 {
			mode = "shadowsocks"
		}
		p.MultihopNodes = append(p.MultihopNodes, MultihopNodeSelection{ID: fmt.Sprintf("node-%d", i), Mode: mode})
	}
	return p
}

func TestOrderedNodeProfileRoundTripPreservesEveryPosition(t *testing.T) {
	for _, count := range []int{2, 3, 4, MultihopMaximumNodes} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			original := nodeChainProfile(count)
			frozen := CloneRouterProfile(original)
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var decoded RouterProfile
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.MultihopNodes, original.MultihopNodes) || decoded.MultihopExecution != "local" || !decoded.MultihopEnabled {
				t.Fatal("selected path order, member mode, or explicit execution was lost")
			}
			if !reflect.DeepEqual(original, frozen) {
				t.Fatal("encoding normalized the live selected-node source")
			}
			if decoded.MultihopEntryID != "" || decoded.MultihopExitID != "" || decoded.MultihopEntryMode != "" {
				t.Fatal("ordered selection became a pair projection")
			}
		})
	}
}

func TestOrderedNodeProfileRejectsIncompleteOrAmbiguousSelection(t *testing.T) {
	cases := map[string]func(*RouterProfile){
		"one":                func(p *RouterProfile) { p.MultihopNodes = p.MultihopNodes[:1] },
		"nine":               func(p *RouterProfile) { *p = nodeChainProfile(MultihopMaximumNodes + 1) },
		"duplicate-middle":   func(p *RouterProfile) { p.MultihopNodes[1].ID = p.MultihopNodes[0].ID },
		"missing-middle":     func(p *RouterProfile) { p.MultihopNodes[1].ID = "" },
		"noncanonical-id":    func(p *RouterProfile) { p.MultihopNodes[1].ID = " middle " },
		"path-id":            func(p *RouterProfile) { p.MultihopNodes[1].ID = "../middle" },
		"oversized-id":       func(p *RouterProfile) { p.MultihopNodes[1].ID = strings.Repeat("a", 65) },
		"missing-mode":       func(p *RouterProfile) { p.MultihopNodes[1].Mode = "" },
		"noncanonical-mode":  func(p *RouterProfile) { p.MultihopNodes[1].Mode = "WG" },
		"oversized-mode":     func(p *RouterProfile) { p.MultihopNodes[1].Mode = strings.Repeat("a", 65) },
		"implicit-execution": func(p *RouterProfile) { p.MultihopExecution = "" },
		"server":             func(p *RouterProfile) { p.MultihopExecution = "server" },
		"auto":               func(p *RouterProfile) { p.MultihopExecution = "auto" },
		"legacy-entry":       func(p *RouterProfile) { p.MultihopEntryID = p.MultihopNodes[0].ID },
		"legacy-exit":        func(p *RouterProfile) { p.MultihopExitID = p.MultihopNodes[2].ID },
		"legacy-mode":        func(p *RouterProfile) { p.MultihopEntryMode = "wg" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := nodeChainProfile(3)
			mutate(&p)
			frozen := CloneRouterProfile(p)
			if _, err := json.Marshal(p); err == nil {
				t.Fatal("invalid ordered selection was saved")
			}
			if !reflect.DeepEqual(p, frozen) {
				t.Fatal("failed save changed the live ordered source")
			}
			type wire RouterProfile
			raw, _ := json.Marshal(wire(p))
			var decoded RouterProfile
			if err := json.Unmarshal(raw, &decoded); err == nil {
				t.Fatal("invalid ordered selection was loaded")
			}
		})
	}
}

func TestOrderedNodeProfileCloneHasNoMutableSelectionAlias(t *testing.T) {
	original := nodeChainProfile(4)
	clone := CloneRouterProfile(original)
	clone.MultihopNodes[1].ID, clone.MultihopNodes[2].Mode = "replacement", "awg2-fast"
	if original.MultihopNodes[1].ID != "node-1" || original.MultihopNodes[2].Mode != "wg" {
		t.Fatal("captured ordered selection shares mutable catalog storage")
	}
	store := RouterProfileStore{SelectedID: original.ID, Profiles: []RouterProfile{original}}
	copy := copyProfileStoreForJSON(store)
	copy.Profiles[0].MultihopNodes[1], copy.Profiles[0].MultihopNodes[2] = copy.Profiles[0].MultihopNodes[2], copy.Profiles[0].MultihopNodes[1]
	if store.Profiles[0].MultihopNodes[1].ID != "node-1" {
		t.Fatal("store clone reordered the live path")
	}
}

func TestOrderedNodeSchemaLeavesLegacyPairRepresentation(t *testing.T) {
	p := RouterProfile{MultihopEnabled: true, MultihopEntryID: " entry ", MultihopExitID: " exit ", MultihopExecution: "auto", MultihopEntryMode: "awg2-fast"}
	if err := NormalizeRouterProfile(&p); err != nil {
		t.Fatal(err)
	}
	if p.MultihopEntryID != "entry" || p.MultihopExitID != "exit" || p.MultihopExecution != "auto" || p.MultihopEntryMode != "awg2-fast" || p.MultihopNodes != nil {
		t.Fatal("legacy pair was rewritten into another execution or selection")
	}
}
