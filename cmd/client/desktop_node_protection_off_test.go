package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// Only the native BFE boundary is modeled. The same source constructors,
// succession slot, canonical target and application save path remain real.
type desktopProtectionOffFixture struct {
	a           *app
	slot        *desktopNodeProtectionSlot
	kernel      *desktopNodeProtectionFixture
	profile     common.RouterProfile
	target      mobiletor.DesktopWindowsProtectionTarget
	owners      []*desktopProtectionOffFixtureOwner
	calls       int
	partial     bool
	nilOwner    bool
	closeFail   bool
	afterMake   func()
	afterRead   func(*mobiletor.DesktopWindowsProtectionTarget)
	beforeClose func(context.Context) error
	attempt     *desktopNodeProtectionAttempt
}

type desktopProtectionOffFixtureOwner struct {
	fixture *desktopProtectionOffFixture
	target  mobiletor.DesktopWindowsProtectionTarget
	armed   bool
	closed  bool
	closes  int
}

func (owner *desktopProtectionOffFixtureOwner) Close(ctx context.Context) error {
	owner.closes++
	if ctx.Err() != nil || owner.fixture.closeFail {
		return errors.Join(ctx.Err(), errors.New("fixture exact Off owner is still joining"))
	}
	if owner.closed {
		return nil
	}
	if owner.fixture.beforeClose != nil {
		if err := owner.fixture.beforeClose(ctx); err != nil {
			return err
		}
	}
	kernel := owner.fixture.kernel
	if !kernel.locked || kernel.target == nil || *kernel.target != owner.target {
		return errors.New("fixture exact Off owner encountered a changed native target")
	}
	if owner.armed {
		kernel.target = nil
	}
	kernel.locked, owner.closed = false, true
	return nil
}

func newDesktopProtectionOffFixture(t *testing.T) *desktopProtectionOffFixture {
	return newDesktopProtectionOffPolicyFixture(t, "always")
}

func newDesktopProtectionOffPolicyFixture(t *testing.T, policyName string) *desktopProtectionOffFixture {
	t.Helper()
	profile, files := desktopNodeFixture(t, "198.51.100.8")
	profile.KillSwitchPolicy, profile.KillSwitch = policyName, true
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	original, _, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := mobilemultihop.NewDesktopNodePolicy(original, strings.Repeat("1", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	f := &desktopProtectionOffFixture{kernel: &desktopNodeProtectionFixture{}, profile: profile}
	backend := f.kernel.backend()
	read := backend.read
	backend.read = func(ctx context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
		err := read(ctx, target)
		if err == nil && f.afterRead != nil {
			f.afterRead(target)
		}
		return err
	}
	backend.recover = func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		f.calls++
		if ctx.Err() != nil || f.kernel.locked || f.kernel.target == nil || *f.kernel.target != target {
			return nil, errors.New("fixture exact recovery rejected a foreign or live target")
		}
		if f.nilOwner {
			return nil, nil
		}
		owner := &desktopProtectionOffFixtureOwner{fixture: f, target: target, armed: !f.partial}
		f.owners = append(f.owners, owner)
		f.kernel.locked = true
		if f.afterMake != nil {
			f.afterMake()
		}
		if f.partial {
			return owner, errors.New("fixture preparation failed after acquiring native work")
		}
		return owner, nil
	}
	f.slot = &desktopNodeProtectionSlot{backend: backend}
	attempt, err := f.slot.begin(context.Background(), &desktopNodeLaunch{ownedNode: &desktopOwnedNodeRuntime{profileToken: desktopOwnedNodeProfileToken(profile)}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.target = desktopNodeProtectionInstalled(policy)
	f.kernel.target, f.kernel.locked = copyDesktopNodeProtectionTarget(&f.target), true
	if err := f.slot.provePrepared(context.Background(), attempt, f.target, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, &f.target), func(context.Context) error {
		f.kernel.locked = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.attempt = attempt
	f.a = &app{nodeProtection: f.slot}
	f.a.cfg.ProfilesFile = filepath.Join(t.TempDir(), "routers.json")
	f.a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	f.a.state.Mode, f.a.state.Phase = "off", "off"
	if err := f.a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *desktopProtectionOffFixture) capture(t *testing.T) *desktopNodeProtectionOff {
	t.Helper()
	revision := profileStartupSettingsToken(f.profile)
	result, err := profileProtectionOffResult(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := f.slot.captureOff(context.Background(), f.profile.ID, revision, profileStartupSettingsToken(result), f.slot.view().token(revision))
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

func TestDesktopProtectionOffRemovesOnlyExplicitJoinedAlways(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	oldToken := f.slot.view().token(profileStartupSettingsToken(f.profile))
	if err := f.slot.release(context.Background()); err != nil || !reflect.DeepEqual(f.kernel.target, &f.target) {
		t.Fatal("normal release changed retained Always", err)
	}
	if oldToken == f.slot.view().token(profileStartupSettingsToken(f.profile)) {
		t.Fatal("normal lifecycle completion did not invalidate its previous revision")
	}
	capture := f.capture(t)
	if err := f.slot.finishOffSave(context.Background(), capture, func() bool { return true }); err == nil {
		t.Fatal("Off save finished before exact native absence")
	}
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || len(f.owners) != 1 || !f.owners[0].closed || f.kernel.target != nil || !capture.removed ||
		!capture.absenceProved || !f.slot.retained() || f.slot.provedEmpty() {
		t.Fatal("explicit Off forgot its joined removal or pending save ownership")
	}
	if _, err := f.slot.begin(context.Background(), &desktopNodeLaunch{}, desktopNodeProtectionPolicy(t, "2", "always", 0)); err == nil {
		t.Fatal("pending Off admitted a replacement connection")
	}
	if err := f.slot.release(context.Background()); err == nil {
		t.Fatal("normal cleanup discarded an accepted unsaved Off")
	}
	if f.capture(t) != capture {
		t.Fatal("same explicit Off reacquired its operation")
	}
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err != nil || f.calls != 1 {
		t.Fatal("pending-save retry performed another native removal", err)
	}
	if _, err := f.a.persistCapturedProtectionOff(context.Background(), f.slot, capture, false); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.finishOffSave(context.Background(), capture, func() bool { return true }); err != nil || f.slot.retained() || !f.slot.provedEmpty() {
		t.Fatal("saved Off did not finish its exact capture", err)
	}
	if err := f.slot.finishOffSave(context.Background(), capture, func() bool { return true }); err == nil {
		t.Fatal("consumed Off capture acquired a second completion")
	}
}

func TestDesktopProtectionOffRejectsChangedCaptureBeforeMutation(t *testing.T) {
	for _, fault := range []string{"profile", "revision", "generation", "target-view", "binding", "unknown", "missing", "active", "retiring", "cancel", "current", "target"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			revision := profileStartupSettingsToken(f.profile)
			token := f.slot.view().token(revision)
			id, ctx := f.profile.ID, context.Background()
			switch fault {
			case "profile":
				id = "another-node"
			case "revision":
				revision = strings.Repeat("e", 64)
			case "generation":
				f.slot.generation++
			case "target-view":
				f.slot.target.BaselineSHA256 = strings.Repeat("f", 64)
			case "binding":
				f.slot.binding.SourceSHA256 = strings.Repeat("f", 64)
			case "unknown":
				f.slot.known = false
			case "missing":
				f.slot.target = nil
			case "active":
				f.slot.active = &desktopNodeProtectionAttempt{}
			case "retiring":
				f.slot.retirement = &desktopNodeProtectionFixtureRelease{}
			case "cancel":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			result, err := profileProtectionOffResult(f.profile)
			if err != nil {
				t.Fatal(err)
			}
			capture, err := f.slot.captureOff(ctx, id, revision, profileStartupSettingsToken(result), token)
			if fault == "current" || fault == "target" {
				if err != nil {
					t.Fatal(err)
				}
				if fault == "target" {
					f.kernel.target.BaselineSHA256 = strings.Repeat("f", 64)
				}
				err = f.slot.applyOff(ctx, capture, func() bool { return fault != "current" })
			}
			if err == nil || f.kernel.target == nil || len(f.owners) != 0 {
				t.Fatal("changed Off authority reached native removal", fault, err)
			}
		})
	}
}

func TestDesktopProtectionOffUnarmedOwnerMustJoinAndReproveOriginal(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	f.partial = true
	capture := f.capture(t)
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.owner == nil || capture.prepared {
		t.Fatal("failed preparation lost its unarmed exact owner")
	}
	owner := capture.owner
	f.closeFail = true
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.owner != owner || f.calls != 1 {
		t.Fatal("unarmed join failure reacquired native authority")
	}
	f.closeFail, f.kernel.readFail = false, true
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.owner != owner || f.calls != 1 {
		t.Fatal("unproved original target discarded failed preparation")
	}
	f.kernel.readFail = false
	f.kernel.target.BaselineSHA256 = strings.Repeat("f", 64)
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.owner != owner || f.calls != 1 {
		t.Fatal("failed Off adopted a replaced original target")
	}
	f.kernel.target, f.partial = copyDesktopNodeProtectionTarget(&f.target), false
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err != nil || f.calls != 2 || capture.owner == owner || !capture.removed {
		t.Fatal("proved unchanged preparation did not permit exactly one fresh removal", err)
	}
}

func TestDesktopProtectionOffArmedCancellationAndReadRetryKeepOwner(t *testing.T) {
	for _, fault := range []string{"constructor-cancel", "close", "read", "read-cancel"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffFixture(t)
			capture := f.capture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "constructor-cancel":
				f.afterMake = cancel
			case "close":
				f.closeFail = true
			case "read":
				f.afterMake = func() { f.kernel.readFail = true }
			case "read-cancel":
				f.afterRead = func(target *mobiletor.DesktopWindowsProtectionTarget) {
					if target == nil {
						cancel()
					}
				}
			}
			if err := f.slot.applyOff(ctx, capture, func() bool { return true }); err == nil || capture.owner == nil || !capture.prepared {
				t.Fatal("armed failure forgot its exact owner or constructor result", err)
			}
			owner := capture.owner
			if fault == "read-cancel" && (!capture.removed || !capture.absenceProved) {
				t.Fatal("cancellation after exact absence hid the unsaved Off state")
			}
			f.closeFail, f.kernel.readFail, f.afterMake, f.afterRead = false, false, nil, nil
			if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err != nil || capture.owner != owner || f.calls != 1 || !capture.removed {
				t.Fatal("armed retry reacquired or forgot the original removal", err)
			}
			f.kernel.target = copyDesktopNodeProtectionTarget(&f.target)
			f.kernel.target.BaselineSHA256 = strings.Repeat("f", 64)
			if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.absenceProved || f.calls != 1 {
				t.Fatal("pending-save retry claimed absence over a replacement baseline")
			}
		})
	}
}

func TestDesktopProtectionOffNilConstructorCannotProveRemoval(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	f.nilOwner = true
	capture := f.capture(t)
	if err := f.slot.applyOff(context.Background(), capture, func() bool { return true }); err == nil || capture.owner != nil || capture.prepared || capture.removed {
		t.Fatal("nil native owner was treated as an armed successful removal")
	}
	if !f.slot.retained() || f.slot.provedEmpty() || !reflect.DeepEqual(f.kernel.target, &f.target) {
		t.Fatal("nil constructor lost its pending exact target")
	}
}
