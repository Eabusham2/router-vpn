package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

// This fixture covers only common lifecycle dispatch. Its private methods
// model the platform boundary; it never claims a native host or TUN proof.
type desktopImportedPlatformFixture struct {
	launch                         *desktopNodeLaunch
	events                         []string
	startErr, currentErr, closeErr error
	done                           chan struct{}
}

func (f *desktopImportedPlatformFixture) Stage(context.Context) error {
	f.events = append(f.events, "stage")
	return nil
}
func (f *desktopImportedPlatformFixture) Start(ctx context.Context) error {
	f.events = append(f.events, "start")
	if f.startErr != nil {
		return f.startErr
	}
	f.launch.command = &exec.Cmd{}
	return ctx.Err()
}
func (f *desktopImportedPlatformFixture) Current(context.Context) error {
	f.events = append(f.events, "current")
	return f.currentErr
}
func (f *desktopImportedPlatformFixture) Prove(context.Context) error {
	f.events = append(f.events, "prove")
	return nil
}
func (f *desktopImportedPlatformFixture) Activate(context.Context) error {
	f.events = append(f.events, "activate")
	return nil
}
func (f *desktopImportedPlatformFixture) Close(context.Context) error {
	f.events = append(f.events, "close")
	if f.closeErr == nil {
		clear(f.launch.config)
		clear(f.launch.metadata)
	}
	return f.closeErr
}
func (f *desktopImportedPlatformFixture) ProcessDone() <-chan struct{}                 { return f.done }
func (f *desktopImportedPlatformFixture) ValidateConfig(context.Context, []byte) error { return nil }
func (f *desktopImportedPlatformFixture) Restore(context.Context) error                { return nil }
func (f *desktopImportedPlatformFixture) RetainMTU(context.Context, *desktopImportedMTUOwner) error {
	return nil
}
func (f *desktopImportedPlatformFixture) MTUCleanupCurrent(context.Context, *desktopImportedMTUOwner) error {
	return nil
}

func TestDesktopImportedPlatformTransitionRejectsForeignRuntime(t *testing.T) {
	a := &app{}
	launch := &desktopNodeLaunch{}
	fixture := &desktopImportedPlatformFixture{launch: launch}
	launch.importedPlatform = fixture
	if err := a.guardDesktopOwnedNodeTransitionContext(context.Background(), launch); err == nil {
		t.Fatal("arbitrary interface implementation bypassed the original platform transition guard")
	}
	if len(fixture.events) != 0 {
		t.Fatal("foreign interface supplied its own transition authorization", fixture.events)
	}
}

func TestDesktopImportedPlatformSpeedLabRetainsOriginalObservation(t *testing.T) {
	session, _ := speedLabCurrentImportedSessionFixture(t)
	a := session.driver.a
	platform := &desktopImportedPlatformFixture{launch: session.native}
	session.native.importedPlatform = platform
	desktopNodeOwners.Delete(a)
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
	if err != nil || identity.Imported == nil || identity.Imported.launch != session.native {
		t.Fatal("Speed Lab lost its actual imported owner", err)
	}
	if err := validateSpeedLabIdentityContext(context.Background(), a, identity); err != nil {
		t.Fatal("original imported platform observation failed", err)
	}
	platform.currentErr = errors.New("original platform replaced")
	if err := validateSpeedLabIdentityContext(context.Background(), a, identity); err == nil {
		t.Fatal("Speed Lab accepted a stale imported platform")
	}
}

func TestDesktopImportedPlatformStartsBeforeDNSRegistration(t *testing.T) {
	for _, scenario := range []string{"complete", "start-failed", "current-failed", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes")}}
			launch := &desktopNodeLaunch{root: root, directory: filepath.Join(root, "run", "captured"), importedEntry: true}
			f := &desktopImportedPlatformFixture{launch: launch, done: make(chan struct{})}
			launch.importedPlatform = f
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "start-failed" {
				f.startErr = errors.New("original start failed")
			}
			if scenario == "current-failed" {
				f.currentErr = errors.New("original session changed")
			}
			if scenario == "cancelled" {
				cancel()
			}
			sel := multihopSelection{Exit: common.RouterProfile{ID: "final"}, ExitMode: "shadowsocks", Native: &nativeMultihopCapture{imported: true}}
			err := startDesktopImportedPlatform(ctx, a, sel, launch)
			_, registered := activeDNSRuntimeIdentities.Load(a)
			defer activeDNSRuntimeIdentities.Delete(a)
			if (err == nil) != (scenario == "complete") || registered != (scenario == "complete") {
				t.Fatalf("registration preceded complete native start/current: %v, %v", err, registered)
			}
			if scenario == "complete" && !reflect.DeepEqual(f.events, []string{"start", "current"}) {
				t.Fatalf("lifecycle order %v", f.events)
			}
			if _, duplicate := desktopNodeOwners.Load(a); duplicate {
				t.Fatal("platform start created a second process owner")
			}
		})
	}
}

func TestDesktopImportedPlatformUsesOriginalJoinAndRetainsFailedCleanup(t *testing.T) {
	launch := &desktopNodeLaunch{config: []byte("private graph"), metadata: []byte("private identity")}
	f := &desktopImportedPlatformFixture{launch: launch, done: make(chan struct{}), closeErr: errors.New("original retirement incomplete")}
	launch.importedPlatform = f
	if desktopNodeProcessDone(launch) != f.done || launch.nodeWaitDone != nil {
		t.Fatal("observation created another command waiter")
	}
	if err := retireUnstartedNativeMultihop(launch); err == nil || string(launch.config) != "private graph" || string(launch.metadata) != "private identity" {
		t.Fatal("failed retirement discarded private authority", err)
	}
	f.closeErr = nil
	if err := retireUnstartedNativeMultihop(launch); err != nil {
		t.Fatal(err)
	}
	close(f.done)
	if !desktopNodeProcessExited(launch) || launch.nodeWaitDone != nil {
		t.Fatal("original joined process was not observed exactly")
	}
}
