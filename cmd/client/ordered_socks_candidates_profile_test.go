package main

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func orderedImportedCandidateAdd(t *testing.T, a *app, protocol string) common.RouterProfile {
	t.Helper()
	candidate, err := externalProfileFromCreateRequest(createRequestFor(protocol))
	if err != nil {
		t.Fatal(err)
	}
	candidate.ID, candidate.Name, candidate.StartLayer = "original-imported-candidate", "Original imported candidate", "off"
	candidate.MultihopExecution = "local"
	candidate.MTUPolicy, candidate.ManualMTU = "manual", 1380
	candidate.DNSMode, candidate.DNSProtocol, candidate.DNSHost, candidate.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	candidate.KillSwitchPolicy, candidate.IPv6Mode, candidate.HomeLANAccess = "always", "off", false
	if err := common.NormalizeRouterProfile(&candidate); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles = append(a.profiles.Profiles, candidate)
	return candidate
}

func orderedImportedCandidateProposalFixture(t *testing.T, prefix, protocol, layer string) (*app, []desktopNodeChainMember, common.RouterProfile) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installOrderedAWGAssets(t, a, nodes, []string{prefix, "wg", "shadowsocks"}, layer)
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	return a, selection.Nodes, orderedImportedCandidateAdd(t, a, protocol)
}

func TestOrderedSOCKSCandidateProposalKeepsTypedFuturePath(t *testing.T) {
	for _, prefix := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"off", "aes-256-gcm+xor-whitening"} {
			t.Run(prefix+"/"+layer, func(t *testing.T) {
				a, members, candidate := orderedImportedCandidateProposalFixture(t, prefix, "socks5", layer)
				before, state, command := cloneRouterProfileStore(a.profiles), a.state, a.cmd
				control, nodes, err := orderedCandidateProposal(members, 0, candidate, a.profiles.Profiles)
				wanted := []common.MultihopNodeSelection{{ID: members[0].Profile.ID, Mode: prefix}, {ID: candidate.ID, Mode: "socks5"}, {ID: members[2].Profile.ID, Mode: "shadowsocks"}}
				if err != nil || !reflect.DeepEqual(nodes, wanted) || control.ID != members[2].Profile.ID {
					t.Fatal("SOCKS proposal lost original prefix, typed middle or paired final", err)
				}
				profiles := cloneRouterProfileStore(a.profiles).Profiles
				profiles[2] = common.CloneRouterProfile(control)
				compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
				if err != nil {
					t.Fatal("complete typed SOCKS proposal compilation", err)
				}
				typed, ok := compiled.(*desktopNodeChainSOCKSCapture)
				if !ok || typed == nil || typed.original == nil || typed.original.chain != nil {
					t.Fatal("SOCKS proposal borrowed generic or CONNECT runtime authority")
				}
				var source mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(typed.original.input), &source) != nil || source.Schema != 3 || source.Execution != "local" || len(source.Nodes) != 3 || len(source.IdentitySources) != 3 || source.IdentitySources[1] != "" {
					t.Fatal("SOCKS proposal lost distinct schema3 or borrowed paired identity")
				}
				config, capture, endpoint, err := desktopImportedEntrySource(context.Background(), candidate, nil)
				if err != nil || endpoint != candidate.Endpoint {
					t.Fatal("original SOCKS candidate capture", err)
				}
				input, err := mobilemultihop.NodeChainImportedSOCKSMemberInput(config, capture)
				if err != nil || input != source.Nodes[1] {
					t.Fatal("SOCKS proposal changed original imported source bytes", err)
				}
				_, meta, err := typed.source.ReadValidated()
				if err != nil || meta.NativeAdmission != "closed" || len(meta.Proofs) != 3 || meta.Proofs[0].Mode != prefix || meta.Proofs[1].Mode != "socks5" || meta.Proofs[1].StartLayer != "off" || meta.Proofs[2].Mode != "shadowsocks" || meta.Proofs[0].StartLayer != layer || meta.Proofs[2].StartLayer != layer {
					t.Fatal("SOCKS proposal changed original independent policy", err)
				}
				if _, err := mobilemultihop.NewNodeChain(typed.original.input); err == nil {
					t.Fatal("SOCKS proposal passed generic admission")
				}
				if _, err := mobilemultihop.NewNodeChainCONNECTSource(typed.original.input); err == nil {
					t.Fatal("SOCKS proposal passed CONNECT admission")
				}
				record, err := a.orderedCandidateProfileRecordLocked(control, "Next original SOCKS path")
				if err != nil || record.Mode != "shadowsocks" || len(record.NodeChain) != 3 || record.NodeChain[1].Mode != "socks5" || !reflect.DeepEqual(record.Prefs.MultihopNodes, wanted) {
					t.Fatal("complete SOCKS future profile capture failed", err)
				}
				if !reflect.DeepEqual(before, a.profiles) || a.state != state || a.cmd != command {
					t.Fatal("SOCKS future profile changed active owner or catalog")
				}
				publication, err := appendOrderedCandidateProfile(a, record, func() error { return compiled.validate(context.Background(), control, profiles) })
				if err != nil || publication == nil {
					t.Fatal("SOCKS future profile append failed", err)
				}
				// Use the shipping Load route, which applies saved preferences before
				// validating the exact ordered member references. No native launch is requested.
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": record.ID})
				if loaded.Code != http.StatusOK {
					t.Fatal("SOCKS future profile Load failed", loaded.Code, loaded.Body.String())
				}
				middle, found := a.profileByIDLocked(candidate.ID)
				final, finalFound := a.profileByIDLocked(control.ID)
				if !found || !finalFound || !reflect.DeepEqual(middle, candidate) || !reflect.DeepEqual(final.MultihopNodes, wanted) || a.cmd != nil || a.state.Connected {
					t.Fatal("SOCKS future Load changed captured middle policy/credentials or connected")
				}
				profiles[3].External.SOCKS5.Password += "-changed"
				if compiled.validate(context.Background(), control, profiles) == nil {
					t.Fatal("SOCKS future Save adopted replacement credentials")
				}
				if _, _, err := orderedCandidateProposal(members, 1, candidate, a.profiles.Profiles); err == nil {
					t.Fatal("SOCKS future proposal admitted unsupported later placement")
				}
			})
		}
	}
}

func TestOrderedCandidateProposalCompilerRetainsGenericSS(t *testing.T) {
	for _, cipher := range []string{"", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		name := cipher
		if name == "" {
			name = "paired"
		}
		t.Run(name, func(t *testing.T) {
			a, catalog, id := desktopCandidateSourceTestCatalog(t, cipher)
			before := cloneRouterProfileStore(a.profiles)
			candidate, _ := a.profileByIDLocked(id)
			control, nodes, err := orderedCandidateProposal(catalog.launch.chain.selection.Nodes, 0, candidate, a.profiles.Profiles)
			if err != nil {
				t.Fatal(err)
			}
			profiles := cloneRouterProfileStore(a.profiles).Profiles
			for i := range profiles {
				if profiles[i].ID == control.ID {
					profiles[i] = common.CloneRouterProfile(control)
				}
			}
			compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
			if err != nil {
				t.Fatal("retained SS source compiler", err)
			}
			generic, ok := compiled.(*desktopNodeChainCapture)
			if !ok || generic == nil || generic.chain == nil || generic.socks != nil {
				t.Fatal("SS proposal changed its original compiler family")
			}
			if err := compiled.validate(context.Background(), control, profiles); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("generic source compiler changed the active catalog")
			}
		})
	}
}

func TestOrderedSOCKSCandidateProposalRejectsUnsupportedPlacement(t *testing.T) {
	for _, protocol := range []string{"socks5"} {
		for _, fault := range []string{"later-prefix", "candidate-is-prefix", "candidate-is-final", "hostname", "start-layer", "wrong-protocol", "unpaired-final", "wrong-final-mode", "missing-candidate", "duplicate-source"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				a, members, candidate := orderedImportedCandidateProposalFixture(t, "wg", protocol, "off")
				position := 0
				switch fault {
				case "later-prefix":
					position = 1
				case "candidate-is-prefix":
					candidate.ID = members[0].Profile.ID
				case "candidate-is-final":
					candidate.ID = members[2].Profile.ID
				case "hostname":
					candidate.Endpoint = "proxy.example.test"
					candidate.External.SOCKS5.Host = candidate.Endpoint
				case "start-layer":
					candidate.StartLayer = "aes-256-gcm"
				case "wrong-protocol":
					candidate.External.Protocol = "http-connect"
				case "unpaired-final":
					members[2].Profile = candidate
				case "wrong-final-mode":
					members[2].Mode = "http-connect"
				case "missing-candidate":
					a.profiles.Profiles = a.profiles.Profiles[:3]
				case "duplicate-source":
					a.profiles.Profiles = append(a.profiles.Profiles, candidate)
				}
				if fault != "missing-candidate" && fault != "duplicate-source" {
					a.profiles.Profiles[3] = candidate
				}
				if _, _, err := orderedCandidateProposal(members, position, candidate, a.profiles.Profiles); err == nil {
					t.Fatal("unsupported SOCKS future path admitted", fault)
				}
			})
		}
	}
}

func TestOrderedSOCKSCandidateSaveHTTPRequiresFreshOriginalOwner(t *testing.T) {
	f := startupProvedNodeChainOwner(t, 3)
	candidate := orderedImportedCandidateAdd(t, f.a, "socks5")
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "original-socks-candidate", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, 0, []string{candidate.ID})
	if err != nil {
		t.Fatal("original SOCKS candidate catalog", err)
	}
	testOrderedCandidateSaveHTTPRequiresFreshOriginalOwner(t, f, catalog, candidate.ID)
}

func TestOrderedSOCKSCandidateProfilePublicationUsesOriginalSource(t *testing.T) {
	a, members, candidate := orderedImportedCandidateProposalFixture(t, "awg2-fast", "socks5", "off")
	before := cloneRouterProfileStore(a.profiles)
	control, nodes, err := orderedCandidateProposal(members, 0, candidate, a.profiles.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	profiles := cloneRouterProfileStore(a.profiles).Profiles
	profiles[2] = common.CloneRouterProfile(control)
	compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := a.orderedCandidateProfileRecordLocked(control, "Original SOCKS next connection")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(record)
	if err != nil || strings.Contains(string(raw), candidate.External.SOCKS5.Password) || strings.Contains(string(raw), candidate.External.SOCKS5.Username) {
		t.Fatal("saved candidate profile copied original transport credentials")
	}
	// This is the real source-checked store transaction. It supplies no native
	// DOWN or physical observer evidence to the prepared Save admission guard.
	current := func() error { return compiled.validate(context.Background(), control, profiles) }
	publication, err := appendOrderedCandidateProfile(a, record, current)
	if err != nil || publication == nil {
		t.Fatal("typed future profile append failed", err)
	}
	orderedCandidateStoredRecordMatches(t, a, record)
	profiles[3].External.SOCKS5.Password += "-replacement"
	if later, err := appendOrderedCandidateProfile(a, record, current); err == nil || later != nil {
		t.Fatal("profile append adopted replacement original credentials")
	}
	orderedCandidateStoredRecordMatches(t, a, record)
	if err := publication.rollback(); err != nil {
		t.Fatal("original publication rollback failed", err)
	}
	if store, err := loadConnectionProfileStore(a); err != nil || len(store.Profiles) != 0 {
		t.Fatal("rollback failed to restore original store", err)
	}
	if !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("future source transaction changed active saved catalog")
	}
}

func orderedCandidateStoredRecordMatches(t *testing.T, a *app, want connectionProfileRecord) {
	t.Helper()
	raw, err := readPrivateRegular(connectionProfileStorePath(a), connectionProfileStoreMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Profiles []json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || len(stored.Profiles) != 1 {
		t.Fatal("original candidate record missing", err)
	}
	wire, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if json.Unmarshal(stored.Profiles[0], &actual) != nil || json.Unmarshal(wire, &expected) != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("candidate store changed original policy, private-source references or record identity")
	}
}
