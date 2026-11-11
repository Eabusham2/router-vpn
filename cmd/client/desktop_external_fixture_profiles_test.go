//go:build routervpn_controller_privileged

package main

import (
	"testing"

	"router-vpn/internal/common"
)

// This pure source guard is shared with the actual Darwin native controller.
// A paired fixture owns its original entry as well as the selected final node;
// an unrelated second profile must never satisfy that requirement.
func macOSExternalNativeFixtureProfiles(store common.RouterProfileStore) bool {
	if len(store.Profiles) < 1 || len(store.Profiles) > 2 || store.SelectedID != "installed-macos-external" {
		return false
	}
	exit := store.Profiles[0]
	if exit.ID != store.SelectedID || exit.NodeKind != "external" || exit.External == nil {
		return false
	}
	if !exit.MultihopEnabled {
		return len(store.Profiles) == 1 && exit.MultihopEntryID == "" && exit.MultihopExitID == ""
	}
	if len(store.Profiles) != 2 || exit.MultihopExecution != "local" || exit.MultihopExitID != exit.ID {
		return false
	}
	entry := store.Profiles[1]
	if entry.ID != exit.MultihopEntryID || entry.NodeKind != "external" || entry.External == nil || entry.MultihopEnabled {
		return false
	}
	switch entry.ID {
	case "installed-macos-wg-entry":
		return entry.External.Protocol == "wireguard"
	case "installed-macos-awg-entry":
		return entry.External.Protocol == "amneziawg"
	case "installed-macos-ss-entry":
		return entry.External.Protocol == "shadowsocks"
	}
	return false
}

func TestMacOSExternalNativeFixtureKeepsOriginalDirectAndPairedSources(t *testing.T) {
	direct := func() common.RouterProfileStore {
		return common.RouterProfileStore{SelectedID: "installed-macos-external", Profiles: []common.RouterProfile{{
			ID: "installed-macos-external", NodeKind: "external", External: &common.ExternalNodeConfig{Protocol: "https-connect"},
		}}}
	}
	paired := func(id, protocol string) common.RouterProfileStore {
		store := direct()
		exit := &store.Profiles[0]
		exit.MultihopEnabled, exit.MultihopExecution = true, "local"
		exit.MultihopEntryID, exit.MultihopExitID = id, exit.ID
		store.Profiles = append(store.Profiles, common.RouterProfile{ID: id, NodeKind: "external", External: &common.ExternalNodeConfig{Protocol: protocol}})
		return store
	}
	if !macOSExternalNativeFixtureProfiles(direct()) {
		t.Fatal("the original single external node was rejected")
	}
	for id, protocol := range map[string]string{"installed-macos-wg-entry": "wireguard", "installed-macos-awg-entry": "amneziawg", "installed-macos-ss-entry": "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			if !macOSExternalNativeFixtureProfiles(paired(id, protocol)) {
				t.Fatal("the exact original entry and final pair was rejected")
			}
		})
	}
	for name, change := range map[string]func(*common.RouterProfileStore){
		"missing-entry":     func(s *common.RouterProfileStore) { s.Profiles = s.Profiles[:1] },
		"extra-entry":       func(s *common.RouterProfileStore) { s.Profiles = append(s.Profiles, s.Profiles[1]) },
		"changed-selection": func(s *common.RouterProfileStore) { s.SelectedID = s.Profiles[1].ID },
		"reordered":         func(s *common.RouterProfileStore) { s.Profiles[0], s.Profiles[1] = s.Profiles[1], s.Profiles[0] },
		"unrelated-entry":   func(s *common.RouterProfileStore) { s.Profiles[1].ID = "another-saved-node" },
		"replaced-final":    func(s *common.RouterProfileStore) { s.Profiles[0].MultihopExitID = s.Profiles[1].ID },
		"server-selection":  func(s *common.RouterProfileStore) { s.Profiles[0].MultihopExecution = "server" },
		"unbound-entry":     func(s *common.RouterProfileStore) { s.Profiles[0].MultihopEntryID = "" },
		"duplicate-identity": func(s *common.RouterProfileStore) {
			s.Profiles[1].ID = s.Profiles[0].ID
			s.Profiles[0].MultihopEntryID = s.Profiles[0].ID
		},
		"wrong-entry-protocol":            func(s *common.RouterProfileStore) { s.Profiles[1].External.Protocol = "shadowsocks" },
		"entry-is-router":                 func(s *common.RouterProfileStore) { s.Profiles[1].NodeKind = "router-vpn" },
		"no-entry-source":                 func(s *common.RouterProfileStore) { s.Profiles[1].External = nil },
		"nested-entry":                    func(s *common.RouterProfileStore) { s.Profiles[1].MultihopEnabled = true },
		"disabled-pair-with-extra-source": func(s *common.RouterProfileStore) { s.Profiles[0].MultihopEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			store := paired("installed-macos-wg-entry", "wireguard")
			change(&store)
			if macOSExternalNativeFixtureProfiles(store) {
				t.Fatal("fixture accepted a changed or incomplete original source set")
			}
		})
	}
	if macOSExternalNativeFixtureProfiles(common.RouterProfileStore{}) {
		t.Fatal("fixture accepted no original source")
	}
}
