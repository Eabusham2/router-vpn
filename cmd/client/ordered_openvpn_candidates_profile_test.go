package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func TestOrderedOpenVPNCandidateKeepsOriginalTCPSource(t *testing.T) {
	for _, requested := range []string{"local", "server", "auto"} {
		t.Run(requested, func(t *testing.T) {
			a, nodes, _, _ := desktopOpenVPNExecutionProfiles(t, 4, "wg", "tcp", "off")
			const middle = 2
			original := a.profiles.Profiles[middle]
			candidate := cloneRouterProfile(original)
			candidate.ID = "linked-tcp-openvpn"
			a.profiles.Profiles = append(a.profiles.Profiles, candidate)
			capture := &desktopNodeChainCapture{root: clientRoot(a)}
			var total int
			input, err := capture.compileCandidateMember(context.Background(), candidate, &total)
			if err != nil || total != len(input) || !mobilemultihop.NodeChainCandidateInputSupported(input) {
				t.Fatal("linked original single TCP remote missing from candidate catalog", err)
			}
			udp := cloneRouterProfile(candidate)
			udp.External.OpenVPN.Config = strings.Replace(udp.External.OpenVPN.Config, "proto tcp", "proto udp", 1)
			if _, err := capture.compileCandidateMember(context.Background(), udp, &total); err == nil {
				t.Fatal("UDP source at same endpoint received a TCP score")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := capture.compileCandidateMember(ctx, candidate, &total); !errors.Is(err, context.Canceled) {
				t.Fatal("retired candidate source lost its original cancellation", err)
			}

			members := make([]desktopNodeChainMember, len(nodes))
			for i, row := range nodes {
				members[i] = desktopNodeChainMember{Profile: a.profiles.Profiles[i], Mode: row.Mode}
			}
			before := cloneRouterProfileStore(a.profiles)
			control, proposed, err := orderedCandidateProposalForExecution(members, middle-1, candidate, a.profiles.Profiles, requested)
			if err != nil {
				t.Fatal("source-bound measured original was unavailable as a future route", err)
			}
			expected := append([]common.MultihopNodeSelection(nil), nodes...)
			expected[middle] = common.MultihopNodeSelection{ID: candidate.ID, Mode: "openvpn"}
			if !reflect.DeepEqual(expected, proposed) || control.MultihopExecution != requested || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("proposed route changed a retained member, execution choice or linked source")
			}
			draft := append([]desktopNodeChainMember(nil), members[:middle]...)
			draft = append(draft, members[middle+1:]...)
			draftControl, inserted, err := orderedDraftProposal(requested, draft, middle-1, candidate, a.profiles.Profiles)
			if err != nil || !reflect.DeepEqual(inserted, expected) || draftControl.MultihopExecution != requested || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("adding a measured OpenVPN candidate changed the unsaved draft's suffix, execution or saved profiles", err)
			}
			profiles := cloneRouterProfileStore(a.profiles).Profiles
			profiles[len(nodes)-1] = control
			compiled, err := captureOrderedCandidateProposal(context.Background(), clientRoot(a), control, profiles, proposed)
			if err != nil || compiled == nil {
				t.Fatal("complete proposed OpenVPN route failed its native compiler", err)
			}
			if err := compiled.validate(context.Background(), control, profiles); err != nil {
				t.Fatal("original compiled proposal lost its source", err)
			}
			profiles[len(profiles)-1] = cloneRouterProfile(candidate)
			profiles[len(profiles)-1].External.OpenVPN.Password += " changed"
			if err := compiled.validate(context.Background(), control, profiles); err == nil {
				t.Fatal("replaced original provider credentials retained a prior candidate proposal")
			}
		})
	}
}
