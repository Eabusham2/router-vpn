package main

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// Only the physical observation is modeled here. The shipping prepared-trial
// admission validates the captured transaction, node, runtime and observer.
// The separate process fixture covers refusal before Stop and workspace cleanup.
func TestSpeedLabTorPreparedAdmissionUsesCapturedContextualNetwork(t *testing.T) {
	for _, fault := range []string{"current", "changed", "empty", "error-with-matching-legacy", "legacy-only"} {
		t.Run(fault, func(t *testing.T) {
			operation, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			profile := existingTorImportProfile("captured-tor")
			previous := exec.Command("never-started-original-owner")
			a := &app{connectionContext: operation, cmd: previous,
				profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}}
			temporary := &speedLabTemporaryOwner{current: operation, runtime: previous, network: "captured-network"}
			speedLabTemporaryOwners.Store(a, temporary)
			defer speedLabTemporaryOwners.Delete(a)
			observerFailure := errors.New("captured observer failed")
			contextCalls, legacyCalls := 0, 0
			owner := &desktopTorRuntime{network: temporary.network}
			owner.networkIdentity = func() string {
				legacyCalls++
				if fault == "current" {
					return "foreign-legacy-network"
				}
				return owner.network
			}
			owner.networkIdentityContext = func(ctx context.Context) (string, error) {
				contextCalls++
				deadline, ok := ctx.Deadline()
				originalDeadline, _ := operation.Deadline()
				if ctx != operation || !ok || deadline != originalDeadline || ctx.Err() != nil {
					t.Fatal("prepared network observation replaced its original caller")
				}
				switch fault {
				case "changed":
					return "replacement-network", nil
				case "empty":
					return "", nil
				case "error-with-matching-legacy":
					return owner.network, observerFailure
				default:
					return owner.network, nil
				}
			}
			if fault == "legacy-only" {
				owner.networkIdentityContext = nil
			}
			prepared := &speedLabTorPreparation{
				selection:   &desktopTorSelection{profile: profile, profileToken: desktopTorSourceIdentityToken(profile)},
				command:     exec.Command("never-started-prepared-trial"),
				prelaunch:   &torBridgePrelaunch{workspace: &desktopNodeLaunch{tor: owner}},
				sourceToken: desktopTorSourceIdentityToken(profile), operation: operation,
				temporary: temporary, owned: true, selectedBefore: profile.ID, selectedAfter: profile.ID,
			}
			before := a.state
			err := prepared.currentContext(operation, a, true)
			if fault == "current" {
				if err != nil {
					t.Fatal("unchanged captured contextual observer was rejected", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "Tor Speed Lab physical observation changed") {
				t.Fatal("stale captured contextual network passed prepared admission", fault, err)
			}
			if fault == "error-with-matching-legacy" && !errors.Is(err, observerFailure) {
				t.Fatal("prepared admission discarded the captured observer failure", err)
			}
			wantCalls := 1
			if fault == "legacy-only" {
				wantCalls = 0
			}
			stored, present := speedLabTemporaryOwners.Load(a)
			if contextCalls != wantCalls || legacyCalls != 0 || !present || stored != temporary || a.cmd != previous ||
				a.connectionContext != operation || a.state != before || !reflect.DeepEqual(a.profiles.Profiles[0], profile) ||
				prepared.command.Process != nil || prepared.prelaunch.retired || operation.Err() != nil {
				t.Fatal("prepared admission substituted a legacy observer, owner, source or lifetime", contextCalls, legacyCalls)
			}
		})
	}
}
