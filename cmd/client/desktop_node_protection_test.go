package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

type desktopNodeProtectionFixture struct {
	target                            *mobiletor.DesktopWindowsProtectionTarget
	locked                            bool
	readFail                          bool
	closeFail                         bool
	reads, prepared, releases, closes int
}
type desktopNodeProtectionFixtureRelease struct {
	kernel *desktopNodeProtectionFixture
	target mobiletor.DesktopWindowsProtectionTarget
	done   bool
}

func (r *desktopNodeProtectionFixtureRelease) Close(context.Context) error {
	r.kernel.closes++
	if r.kernel.closeFail {
		return errors.New("fixture retained release still joining")
	}
	if r.done {
		return nil
	}
	if r.kernel.locked || r.kernel.target == nil || *r.kernel.target != r.target {
		return errors.New("fixture release found another owner")
	}
	if r.target.Policy == "on-connect" {
		r.kernel.target = nil
	}
	r.done = true
	return nil
}
func (k *desktopNodeProtectionFixture) backend() desktopNodeProtectionBackend {
	return desktopNodeProtectionBackend{
		read: func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
			k.reads++
			if ctx.Err() != nil || k.readFail || k.locked || !reflect.DeepEqual(target, k.target) {
				return errors.New("fixture expected read rejected unknown or live state")
			}
			return nil
		},
		prepared: func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
			k.prepared++
			if ctx.Err() != nil || k.readFail || !k.locked || k.target == nil || *k.target != target {
				return errors.New("fixture prepared read rejected another owner")
			}
			return nil
		},
		release: func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
			k.releases++
			if ctx.Err() != nil || k.locked || k.target == nil || *k.target != target {
				return nil, errors.New("fixture release refused another target")
			}
			return &desktopNodeProtectionFixtureRelease{kernel: k, target: target}, nil
		},
	}
}

func desktopNodeProtectionPolicy(t *testing.T, session, kill string, mtu int) *mobilemultihop.DesktopNodePolicy {
	t.Helper()
	p, files := desktopNodeFixture(t, "198.51.100.8")
	p.KillSwitch, p.KillSwitchPolicy = true, kill
	original, _, err := compileDesktopNode(context.Background(), p, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, strings.Repeat(session, 32), "windows", mtu)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func desktopNodeProtectionInstalled(policy *mobilemultihop.DesktopNodePolicy) mobiletor.DesktopWindowsProtectionTarget {
	meta := policy.Metadata()
	return mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, NetworkID: strings.Repeat("d", 32)}, Policy: meta.KillSwitchPolicy, BaselineSHA256: strings.Repeat("e", 64)}
}
func desktopNodeProtectionRetired(attempt *desktopNodeProtectionAttempt, target *mobiletor.DesktopWindowsProtectionTarget) mobiletor.DesktopProtectionRetirementRecord {
	return mobiletor.DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: attempt.digest, Target: copyDesktopNodeProtectionTarget(target)}
}

func TestDesktopNodeProtectionRestorationUsesLatestJoinedTrialTarget(t *testing.T) {
	kernel := &desktopNodeProtectionFixture{}
	slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
	var previous *mobiletor.DesktopWindowsProtectionTarget
	for _, step := range []struct {
		session string
		mtu     int
	}{{"1", 0}, {"2", 1392}, {"3", 1280}} {
		policy := desktopNodeProtectionPolicy(t, step.session, "always", step.mtu)
		attempt, err := slot.begin(context.Background(), &desktopNodeLaunch{}, policy)
		if err != nil || !reflect.DeepEqual(attempt.transfer.Predecessor, previous) {
			t.Fatal("restored graph reused an obsolete protection predecessor", err)
		}
		if _, err := slot.begin(context.Background(), &desktopNodeLaunch{}, policy); err == nil {
			t.Fatal("active protection attempt was replaced")
		}
		target := desktopNodeProtectionInstalled(policy)
		kernel.target, kernel.locked = copyDesktopNodeProtectionTarget(&target), true
		if err := slot.provePrepared(context.Background(), attempt, target, func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		joined := false
		if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, &target), func(context.Context) error { joined = true; kernel.locked = false; return nil }); err != nil || !joined || slot.active != nil || !reflect.DeepEqual(slot.target, &target) {
			t.Fatal("retirement did not join and independently retain its exact successor", err)
		}
		previous = copyDesktopNodeProtectionTarget(&target)
		// Public result storage cannot mutate the retained private target.
		target.Capture.SessionID = strings.Repeat("f", 32)
		if !reflect.DeepEqual(slot.target, previous) {
			t.Fatal("retained protection followed caller storage")
		}
	}
	if kernel.prepared != 3 || kernel.reads != 6 {
		t.Fatal("native succession skipped an independent boundary", kernel.prepared, kernel.reads)
	}
}

func TestDesktopNodeProtectionFailedRetirementKeepsExactAttempt(t *testing.T) {
	for _, fault := range []string{"join", "read", "foreign-record", "lost-baseline", "replaced-target", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			kernel := &desktopNodeProtectionFixture{}
			slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
			policy := desktopNodeProtectionPolicy(t, "1", "always", 0)
			attempt, err := slot.begin(context.Background(), &desktopNodeLaunch{}, policy)
			if err != nil {
				t.Fatal(err)
			}
			target := desktopNodeProtectionInstalled(policy)
			kernel.target, kernel.locked = copyDesktopNodeProtectionTarget(&target), true
			if err := slot.provePrepared(context.Background(), attempt, target, func() bool { return true }); err != nil {
				t.Fatal(err)
			}
			record := desktopNodeProtectionRetired(attempt, &target)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "foreign-record" {
				record.TransferSHA256 = strings.Repeat("f", 64)
			}
			if fault == "lost-baseline" {
				record.Target = nil
			}
			if fault == "replaced-target" {
				record.Target.BaselineSHA256 = strings.Repeat("f", 64)
			}
			err = slot.finish(ctx, attempt, record, func(context.Context) error {
				if fault == "join" {
					return errors.New("fixture descendants unjoined")
				}
				kernel.locked = false
				if fault == "read" {
					kernel.readFail = true
				}
				if fault == "cancel" {
					cancel()
				}
				return nil
			})
			if err == nil || slot.active != attempt || slot.target != nil || !slot.retained() {
				t.Fatal("failed native retirement discarded its exact pending owner", fault, err)
			}
			if err := slot.release(context.Background()); err == nil || kernel.releases != 0 {
				t.Fatal("pending native child reached protection release")
			}
		})
	}
}

func TestDesktopNodeProtectionReleaseRetriesSameOwnerAndPreservesAlways(t *testing.T) {
	for _, policyName := range []string{"on-connect", "always"} {
		t.Run(policyName, func(t *testing.T) {
			policy := desktopNodeProtectionPolicy(t, "1", policyName, 0)
			target := desktopNodeProtectionInstalled(policy)
			kernel := &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target), closeFail: true}
			slot := &desktopNodeProtectionSlot{backend: kernel.backend(), known: true, target: copyDesktopNodeProtectionTarget(&target)}
			if err := slot.release(context.Background()); err == nil || slot.retirement == nil || !reflect.DeepEqual(slot.target, &target) {
				t.Fatal("failed release dropped its exact native operation")
			}
			captured := slot.retirement
			kernel.closeFail = false
			kernel.readFail = true
			if err := slot.release(context.Background()); err == nil || slot.retirement != captured || kernel.releases != 1 {
				t.Fatal("failed readback reacquired or forgot the original release")
			}
			kernel.readFail = false
			if err := slot.release(context.Background()); err != nil || slot.retirement != nil || kernel.releases != 1 {
				t.Fatal("same captured release did not finish", err)
			}
			if (slot.target != nil) != (policyName == "always") || !reflect.DeepEqual(slot.target, kernel.target) {
				t.Fatal("normal release changed Always or invented absence")
			}
		})
	}
}

func TestDesktopNodeProtectionFailedLaunchCannotAdoptUnknownBaseline(t *testing.T) {
	policy := desktopNodeProtectionPolicy(t, "1", "always", 0)
	for _, installed := range []bool{false, true} {
		kernel := &desktopNodeProtectionFixture{}
		slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
		attempt, err := slot.begin(context.Background(), &desktopNodeLaunch{}, policy)
		if err != nil {
			t.Fatal(err)
		}
		if installed {
			target := desktopNodeProtectionInstalled(policy)
			kernel.target = copyDesktopNodeProtectionTarget(&target)
		}
		joined := false
		err = slot.abandonUnchanged(context.Background(), attempt, func(context.Context) error { joined = true; return nil })
		if !joined || installed && (err == nil || slot.active != attempt) || !installed && (err != nil || slot.active != nil) {
			t.Fatal("failed creation guessed or discarded a committed baseline", installed, err)
		}
	}
	unknown := desktopNodeProtectionInstalled(policy)
	kernel := &desktopNodeProtectionFixture{target: &unknown}
	slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
	if attempt, err := slot.begin(context.Background(), &desktopNodeLaunch{}, policy); err == nil || attempt != nil || slot.active != nil {
		t.Fatal("new controller adopted an unknown retained baseline")
	}
}
