package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func orderedCompleteProposalFixture(t *testing.T, count int, protocol, execution string) (*app, []desktopNodeChainMember, common.RouterProfile) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	modes := make([]string, count)
	for i := range modes {
		modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
	}
	modes[count-1] = "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, "off")
	// Start from explicit saved preferences. Legacy empty Base/DNS fields are
	// normalized when loaded; that migration is separate from route retention.
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].BaseTunnel = "auto"
		a.profiles.Profiles[i].DNSHost = a.profiles.Profiles[i].AdGuardIPv4
	}
	a.profiles.Profiles[count-1].MultihopExecution = execution
	if protocol == "http-connect" || protocol == "https-connect" {
		orderedCandidateSSServiceFixture(t, a, a.profiles.Profiles[count-1])
	}
	var candidate common.RouterProfile
	if protocol == "shadowsocks" {
		id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
		a.profiles.Profiles[len(a.profiles.Profiles)-1].MultihopExecution = "local"
		candidate, _ = a.profileByIDLocked(id)
	} else {
		candidate = orderedImportedCandidateAdd(t, a, protocol)
	}
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, execution)
	if err != nil {
		t.Fatal(err)
	}
	return a, selection.Nodes, candidate
}

func orderedCompleteProposalSource(t *testing.T, compiled orderedCandidateProposalCapture) mobilemultihop.NodeChainSource {
	t.Helper()
	var input string
	switch capture := compiled.(type) {
	case *desktopNodeChainCapture:
		input = capture.input
	case *desktopNodeChainSOCKSCapture:
		input = capture.original.input
	case *desktopNodeChainCONNECTCapture:
		input = capture.original.input
	default:
		t.Fatal("proposal used an unknown source family")
	}
	var source mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(input), &source) != nil {
		t.Fatal("complete original proposal source is unreadable")
	}
	return source
}

func testOrderedCandidateCompleteProposal(t *testing.T, execution string) {
	for _, count := range []int{3, 4, 8} {
		for _, protocol := range []string{"shadowsocks", "socks5", "http-connect", "https-connect"} {
			t.Run(fmt.Sprintf("%d-%s", count, protocol), func(t *testing.T) {
				a, members, candidate := orderedCompleteProposalFixture(t, count, protocol, execution)
				before, state, command := cloneRouterProfileStore(a.profiles), a.state, a.cmd
				original, err := captureDesktopNodeChain(context.Background(), clientRoot(a), members[count-1].Profile, a.profiles.Profiles, nodeChainSelectedReferences(members), "local", nil)
				if err != nil {
					t.Fatal(err)
				}
				oldSource := orderedCompleteProposalSource(t, original)
				position := count - 3
				control, nodes, err := orderedCandidateProposal(members, position, candidate, a.profiles.Profiles)
				if err != nil {
					t.Fatal("complete measured next-hop proposal rejected original retained suffix", err)
				}
				wanted := nodeChainSelectedReferences(members)
				wanted[position+1] = common.MultihopNodeSelection{ID: candidate.ID, Mode: protocol}
				expectedControl := common.CloneRouterProfile(members[count-1].Profile)
				expectedControl.MultihopNodes = wanted
				if !reflect.DeepEqual(nodes, wanted) || !reflect.DeepEqual(control, expectedControl) || control.MultihopExecution != execution {
					t.Fatal("complete proposal changed original suffix policy or requested execution", control.MultihopExecution, execution, nodes)
				}
				profiles := cloneRouterProfileStore(a.profiles).Profiles
				profiles[count-1] = common.CloneRouterProfile(control)
				compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
				if err != nil {
					t.Fatal("complete proposal failed actual original family or execution compiler", err)
				}
				source := orderedCompleteProposalSource(t, compiled)
				wantSchema := map[string]int{"shadowsocks": 2, "socks5": 3, "http-connect": 4, "https-connect": 4}[protocol]
				if source.Schema != wantSchema || len(source.Nodes) != count || len(source.IdentitySources) != count || source.IdentitySources[position+1] != "" {
					t.Fatal("complete proposal lost its independent typed source inventory")
				}
				for i := range source.Nodes {
					if i == position+1 {
						continue
					}
					if source.IdentitySources[i] != oldSource.IdentitySources[i] || i < count-1 && source.Nodes[i] != oldSource.Nodes[i] {
						t.Fatal("next-hop replacement changed another original member or private identity", i)
					}
				}
				record, err := a.orderedCandidateProfileRecordLocked(control, "Complete measured next connection")
				if err != nil || len(record.NodeChain) != count || record.NodeChain[position+1].NodeKind != "external" || record.NodeChain[position+1].NodeProofID != "" || !reflect.DeepEqual(record.Prefs.MultihopNodes, wanted) || record.Prefs.MultihopExecution != execution {
					t.Fatal("complete future profile lost original references or execution", err)
				}
				publication, err := appendOrderedCandidateProfile(a, record, func() error { return compiled.validate(context.Background(), control, profiles) })
				if err != nil || publication == nil {
					t.Fatal("actual complete profile publication failed", err)
				}
				orderedCandidateStoredRecordMatches(t, a, record)
				if !reflect.DeepEqual(before, a.profiles) || a.state != state || a.cmd != command {
					t.Fatal("saving the complete next connection changed the current path")
				}
				loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": record.ID})
				if loaded.Code != http.StatusOK {
					t.Fatal("complete future profile Load failed", loaded.Code, loaded.Body.String())
				}
				final, found := a.profileByIDLocked(control.ID)
				middle, middleFound := a.profileByIDLocked(candidate.ID)
				if !found || !middleFound || final.MultihopExecution != execution || !reflect.DeepEqual(final.MultihopNodes, wanted) || !reflect.DeepEqual(middle, candidate) || a.state.Connected || a.cmd != command {
					t.Fatal("complete Load changed requested execution, original sources or connection authority")
				}
				for i := 0; i < count-1; i++ {
					unchanged, found := a.profileByIDLocked(before.Profiles[i].ID)
					if !found || !reflect.DeepEqual(unchanged, before.Profiles[i]) {
						t.Fatal("Load rewrote an existing private node", i)
					}
				}
				if err := publication.rollback(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestOrderedCandidateCompleteProposalLocal(t *testing.T) {
	testOrderedCandidateCompleteProposal(t, "local")
}

func TestOrderedCandidateCompleteProposalServer(t *testing.T) {
	testOrderedCandidateCompleteProposal(t, "server")
}

func TestOrderedCandidateCompleteProposalCompare(t *testing.T) {
	testOrderedCandidateCompleteProposal(t, "auto")
}

func TestOrderedCandidateCompleteProposalRefusals(t *testing.T) {
	for _, fault := range []string{"early-import", "imported-final", "duplicate-final", "duplicate-prefix", "missing-execution", "unknown-execution", "stale-import", "stale-final", "stale-prefix", "changed-execution"} {
		t.Run(fault, func(t *testing.T) {
			a, members, candidate := orderedCompleteProposalFixture(t, 4, "socks5", "server")
			position, requested := 1, "server"
			switch fault {
			case "early-import":
				position = 0
			case "imported-final":
				position = 2
			case "duplicate-final":
				candidate.ID = members[3].Profile.ID
			case "duplicate-prefix":
				candidate.ID = members[0].Profile.ID
			case "missing-execution":
				requested = ""
			case "unknown-execution":
				requested = "parallel"
			}
			control, nodes, err := orderedCandidateProposalForExecution(members, position, candidate, a.profiles.Profiles, requested)
			if !strings.HasPrefix(fault, "stale-") && fault != "changed-execution" {
				if err == nil {
					t.Fatal("incompatible next-hop proposal shortened or changed its original complete path", fault, nodes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			profiles := cloneRouterProfileStore(a.profiles).Profiles
			profiles[3] = common.CloneRouterProfile(control)
			compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, nodes)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "stale-import":
				profiles[4].External.SOCKS5.Password += "-replacement"
			case "stale-final":
				profiles[3].APIToken += "-replacement"
				control = common.CloneRouterProfile(profiles[3])
			case "stale-prefix":
				profiles[0].APIToken += "-replacement"
			case "changed-execution":
				control.MultihopExecution = "local"
				profiles[3] = common.CloneRouterProfile(control)
			}
			if compiled.validate(context.Background(), control, profiles) == nil {
				t.Fatal("complete future profile adopted a substituted original source or execution", fault)
			}
		})
	}
}

func TestOrderedCandidateProposalCapturedExecution(t *testing.T) {
	for _, requested := range []string{"server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			_, launch := desktopNodeChainLaunchFixture(t, 2, "windows")
			original, err := newDesktopNodeChainExecutionSource(launch.chain, requested)
			if err != nil || original.attach(launch) != nil {
				t.Fatal("original candidate execution fixture", err)
			}
			if launch.chain.selection.Control.MultihopExecution != "local" {
				t.Fatal("fixture must distinguish saved preferences from actual requested execution")
			}
			actual, err := orderedCandidateRequestedExecution(launch)
			if err != nil || actual != requested {
				t.Fatal("candidate proposal borrowed saved preferences instead of captured execution", actual, err)
			}
			copy := *launch
			copy.chain = &desktopNodeChainLaunch{execution: original}
			if _, err := orderedCandidateRequestedExecution(&copy); err == nil {
				t.Fatal("candidate proposal adopted a foreign execution parent")
			}
		})
	}
}
