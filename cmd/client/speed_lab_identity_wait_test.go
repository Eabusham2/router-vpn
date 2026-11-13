package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestSpeedLabConnectedIdentityWaitRetainsObservationFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &app{state: state{Phase: "off"}}
		started := time.Now()
		identity, err := waitForSpeedLabConnectedIdentity(a, time.Second)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "requires a stable connected VPN") {
			t.Fatal("identity wait discarded its actual failed observation", err)
		}
		if !reflect.DeepEqual(identity, speedLabPathIdentity{}) || time.Since(started) != time.Second {
			t.Fatal("failed observation acquired an identity or changed its original deadline", identity, time.Since(started))
		}
	})
}

func TestSpeedLabConnectedIdentityWaitNamesHeldSessionObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &app{state: state{Connected: true, Phase: "connected", RouterID: "original"}}
		tracker := &sessionTracker{a: a}
		sessionTrackers.Store(a, tracker)
		defer sessionTrackers.Delete(a)
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		started := time.Now()
		identity, err := waitForSpeedLabConnectedIdentity(a, time.Second)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Speed Lab identity session observation") {
			t.Fatal("identity wait lost the exact held observation stage", err)
		}
		if !reflect.DeepEqual(identity, speedLabPathIdentity{}) || time.Since(started) != time.Second {
			t.Fatal("held observation escaped the original deadline", identity, time.Since(started))
		}
	})
}

func TestSpeedLabConnectedIdentityWaitPreservesPreexistingCancellation(t *testing.T) {
	a := &app{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.connectionContext = ctx
	identity, err := waitForSpeedLabConnectedIdentity(a, time.Second)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(identity, speedLabPathIdentity{}) {
		t.Fatal("expired identity observation lost its caller or fabricated a path", identity, err)
	}
}

func TestSpeedLabTorProofObservationRetainsHeldReaderStage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &app{}
		launch := &desktopNodeLaunch{tor: &desktopTorRuntime{}}
		launch.tor.proofMu.Lock()
		defer launch.tor.proofMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		started := time.Now()
		_, err := a.readDesktopTorProofContext(ctx, launch)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Tor proof reader lock") {
			t.Fatal("Tor proof lost its held reader stage or original caller", err)
		}
		if time.Since(started) != time.Second {
			t.Fatal("held Tor reader changed its caller deadline", time.Since(started))
		}
	})
}
