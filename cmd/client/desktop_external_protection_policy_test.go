package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"router-vpn/internal/common"
)

func TestDesktopExternalProtectionKeepsCapturedPairAndStrongestMember(t *testing.T) {
	policies := []string{"off", "on-connect", "always"}
	for finalRank, finalPolicy := range policies {
		for entryRank, entryPolicy := range policies {
			t.Run(finalPolicy+"/"+entryPolicy, func(t *testing.T) {
				profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
				profile.KillSwitchPolicy, profile.KillSwitch = finalPolicy, finalPolicy != "off"
				entry.KillSwitchPolicy, entry.KillSwitch = entryPolicy, entryPolicy != "off"
				wanted := finalPolicy
				if entryRank > finalRank {
					wanted = entryPolicy
				}
				before, _ := json.Marshal([]common.RouterProfile{profile, entry})
				if got := desktopExternalProtectionPolicy(profile, entry, false); got != wanted {
					t.Fatal("paired admission downgraded original member", got, wanted)
				}
				if desktopWindowsExternalGraphEligible(profile, entry, false, "") != true {
					t.Fatal("Windows selected final policy instead of captured pair")
				}
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					if desktopExternalRetainedEntryForOS(launch.external, target) != true {
						t.Fatal("retained owner changed aggregate admission", target)
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil {
						t.Fatal(err)
					}
					if launch.external.physical == nil || launch.external.physical.Metadata().KillSwitchPolicy != wanted || launch.profileID != entry.ID || launch.policyProfileID != profile.ID {
						t.Fatal("native capture changed policy or source IDs", target)
					}
					if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
						t.Fatal(err)
					}
					changedFinal, changedEntry := cloneRouterProfile(profile), cloneRouterProfile(entry)
					changedFinal.KillSwitchPolicy = policies[(finalRank+1)%len(policies)]
					changedEntry.KillSwitchPolicy = policies[(entryRank+1)%len(policies)]
					if validateDesktopMacOSExternalSources(changedFinal, entry, launch) == nil || validateDesktopMacOSExternalSources(profile, changedEntry, launch) == nil {
						t.Fatal("changed participant policy reused original source", target)
					}
					saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
					if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
						t.Fatal(err)
					}
					restored, err := compileSpeedLabExternalRestore(saved, exit)
					if err != nil || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
						t.Fatal("restore replaced original pair or session", err)
					}
					if err := prepareDesktopExternalPhysicalCaptured(restored, target); err != nil || restored.external.physical == nil || restored.external.physical.Metadata().KillSwitchPolicy != wanted {
						t.Fatal("restore downgraded strongest original policy", target, err)
					}
				}
				after, _ := json.Marshal([]common.RouterProfile{profile, entry})
				if string(before) != string(after) {
					t.Fatal("aggregation mutated captured profiles or credentials")
				}
			})
		}
	}
}
func TestDesktopExternalProtectionRejectsForeignOrUnprotectedParticipants(t *testing.T) {
	profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
	for _, fault := range []string{"missing-entry", "same-id", "unknown-entry-policy", "unknown-final-policy", "direct-with-entry"} {
		t.Run(fault, func(t *testing.T) {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			direct := false
			switch fault {
			case "missing-entry":
				e = common.RouterProfile{}
			case "same-id":
				e.ID = p.ID
			case "unknown-entry-policy":
				e.KillSwitchPolicy = "invalid"
			case "unknown-final-policy":
				p.KillSwitchPolicy = "invalid"
			case "direct-with-entry":
				direct = true
			}
			if desktopExternalProtectionPolicy(p, e, direct) != "" || desktopWindowsExternalGraphEligible(p, e, direct, "") {
				t.Fatal("foreign captured participant acquired native admission")
			}
		})
	}
	profile.KillSwitchPolicy, profile.KillSwitch = "off", false
	if desktopExternalProtectionPolicy(profile, common.RouterProfile{}, true) != "off" || !desktopWindowsExternalGraphEligible(profile, common.RouterProfile{}, true, "") {
		t.Fatal("direct native Off admission changed")
	}
}

func TestDesktopExternalProtectionPublicRouteUsesActualAggregate(t *testing.T) {
	for _, finalPolicy := range []string{"off", "on-connect"} {
		t.Run(finalPolicy+"-entry-always", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopWindowsExternalFixture(t, "always")
				profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
				profile.ID, profile.KillSwitchPolicy, profile.KillSwitch = "aggregate-final-"+finalPolicy, finalPolicy, finalPolicy != "off"
				entry.ID, entry.KillSwitchPolicy, entry.KillSwitch = "aggregate-entry-always", "always", true
				f.base.a.profiles.Profiles = append(f.base.a.profiles.Profiles, profile, entry)
				f.base.a.profiles.SelectedID = profile.ID
				if err := f.base.a.persistProfilesLocked(); err != nil {
					t.Fatal(err)
				}
				response := windowsSSEntryConnect(f, profile, entry)
				if response.Code != http.StatusOK {
					t.Fatal("actual public route lost aggregate protected host", response.Code, response.Body.String())
				}
				raw, found := desktopExternalRetainedLaunches.Load(f.base.a)
				if !found {
					t.Fatal("aggregate path fell back from retained native host")
				}
				launch := raw.(*desktopNodeLaunch)
				if launch.external.physical.Metadata().KillSwitchPolicy != "always" || launch.policyProfileID != profile.ID || launch.profileID != entry.ID || launch.external.windows.current(true) != nil {
					t.Fatal("public route downgraded captured aggregate or source ownership")
				}
				proof, err := f.base.a.readDesktopExternalProof(launch)
				if err != nil || !proof.EntryProven || !proof.DNSProven || proof.EntryID != entry.ID {
					t.Fatal("aggregate route lost original entry/final proof", err)
				}
				if err := launch.external.windows.Close(context.Background()); err != nil {
					t.Fatal("aggregate original child did not join", err)
				}
			})
		})
	}
}

func TestDesktopExternalProtectionTemporaryGuardKeepsOriginalAggregate(t *testing.T) {
	f := newDesktopWindowsExternalFixture(t, "always")
	a := f.base.a
	captured, err := captureDesktopWindowsExternalHost(a, a.nodeConnectionHost)
	if err != nil || !a.retainedDesktopNodeProtection() {
		t.Fatal("fixture lost original captured protection", err)
	}
	originalSlot, originalJournal := a.nodeProtection, f.store.head
	profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
	policies := []string{"off", "on-connect", "always"}
	request := speedLabRequest{Topology: "system-direct"}
	profile.KillSwitchPolicy, profile.KillSwitch = "on-connect", true
	entry.KillSwitchPolicy, entry.KillSwitch = "always", true
	original := speedLabTemporarySnapshot{Plan: speedLabRestorePlan{external: &speedLabExternalRestore{profile: profile, entry: entry, execution: "local", windowsHost: captured}}}
	if err := a.guardDesktopOwnedNodeTemporary(request, original); err == nil {
		t.Fatal("temporary system-direct bypassed original entry Always")
	}
	for finalRank, finalPolicy := range policies {
		for entryRank, entryPolicy := range policies {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			p.KillSwitchPolicy, p.KillSwitch = finalPolicy, finalPolicy != "off"
			e.KillSwitchPolicy, e.KillSwitch = entryPolicy, entryPolicy != "off"
			saved := &speedLabExternalRestore{profile: p, entry: e, execution: "local", windowsHost: captured}
			snapshot := speedLabTemporarySnapshot{Plan: speedLabRestorePlan{external: saved}}
			rank := finalRank
			if entryRank > rank {
				rank = entryRank
			}
			err := a.guardDesktopOwnedNodeTemporary(request, snapshot)
			if (err == nil) != (rank < 2) {
				t.Fatal("temporary path downgraded original entry protection", finalPolicy, entryPolicy, err)
			}
			if a.nodeProtection != originalSlot || !reflect.DeepEqual(f.store.head, originalJournal) {
				t.Fatal("temporary guard mutated retained original protection")
			}
		}
	}
	profile.KillSwitchPolicy, profile.KillSwitch = "on-connect", true
	entry.KillSwitchPolicy, entry.KillSwitch = "off", false
	for _, fault := range []string{"foreign-app", "retired-controller", "invalid-member"} {
		host := *captured
		e := cloneRouterProfile(entry)
		switch fault {
		case "foreign-app":
			host.app = &app{}
		case "retired-controller":
			host.capture.current = func() error { return context.Canceled }
		case "invalid-member":
			e.KillSwitchPolicy = "unknown"
		}
		snapshot := speedLabTemporarySnapshot{Plan: speedLabRestorePlan{external: &speedLabExternalRestore{profile: profile, entry: e, execution: "local", windowsHost: &host}}}
		if a.guardDesktopOwnedNodeTemporary(request, snapshot) == nil {
			t.Fatal("temporary guard borrowed another owner or member", fault)
		}
	}
}

func TestDesktopExternalOffCapturedOwnerRejectsSubstitution(t *testing.T) {
	for _, paired := range []bool{false, true} {
		for _, fault := range []string{"none", "source", "capture", "expected", "final-policy", "entry-policy", "final-id", "entry-id", "missing-seal", "changed-seal", "changed-shape"} {
			if !paired && (fault == "entry-policy" || fault == "entry-id") {
				continue
			}
			t.Run(fmt.Sprintf("paired-%t/%s", paired, fault), func(t *testing.T) {
				profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
				profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
				entry.KillSwitch, entry.KillSwitchPolicy = false, "off"
				if !paired {
					entry = common.RouterProfile{}
				}
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, !paired, "", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				o := launch.external
				switch fault {
				case "source":
					o.source = append(o.source, ' ')
				case "capture":
					o.capture = append(o.capture, ' ')
				case "expected":
					o.expected.SourceSHA256 = strings.Repeat("a", 64)
				case "final-policy":
					o.profile.KillSwitchPolicy = "always"
				case "entry-policy":
					o.entry.KillSwitchPolicy = "always"
				case "final-id":
					o.profile.ID = "another-final"
				case "entry-id":
					o.entry.ID = "another-entry"
				case "missing-seal":
					o.protection = desktopExternalProtectionCapture{}
				case "changed-seal":
					o.protection.policy = "always"
				case "changed-shape":
					o.selection = "server"
				}
				if (desktopExternalCapturedProtectionPolicy(o) == "off") != (fault == "none" || fault == "changed-shape") {
					t.Fatal("captured Off owner accepted substituted authority", fault)
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					if !desktopExternalOffRequiresRetainedForOS(o, target) {
						t.Fatal("original Off obligation erased", target, fault)
					}
				}
				if desktopWindowsExternalEligible(launch) != (fault == "none") {
					t.Fatal("Windows Off admission bypassed original capture", fault)
				}
			})
		}
	}
}

func TestDesktopExternalOffWindowsRouterKeepsOriginalObligation(t *testing.T) {
	for _, execution := range []string{"local", "server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			profile, initial := desktopExternalNativeFixture(t, "shadowsocks")
			profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + initial.Server + "/node-response", ServerName: "exit.example.test"}
			entry, files := desktopNodeFixture(t, "198.51.100.8")
			profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
			entry.KillSwitch, entry.KillSwitchPolicy = false, "off"
			profile.MultihopExecution, profile.MultihopEntryMode = execution, "wg"
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopWindowsExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if launch.external.predecessor == "" || !desktopWindowsExternalEligible(launch) || !desktopExternalOffRequiresRetainedForOS(launch.external, "windows") {
				t.Fatal("Windows Off lost original paired predecessor")
			}
			if desktopExternalOffRequiresRetainedForOS(launch.external, "linux") || desktopExternalOffRequiresRetainedForOS(launch.external, "darwin") {
				t.Fatal("Windows paired owner widened Unix retained admission")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil || launch.external.physical == nil || launch.external.physical.Metadata().KillSwitchPolicy != "off" {
				t.Fatal("Off paired source lost actual Windows policy", err)
			}
			launch.external.protection = desktopExternalProtectionCapture{}
			launch.external.selection = "unsupported"
			if !desktopExternalOffRequiresRetainedForOS(launch.external, "windows") || desktopWindowsExternalEligible(launch) {
				t.Fatal("mutated Windows paired owner escaped its original obligation")
			}
		})
	}
}
