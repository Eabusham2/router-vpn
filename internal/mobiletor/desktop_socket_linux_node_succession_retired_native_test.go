//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"testing"
)

func TestDesktopLinuxGuardianKernelNodeRetiredSuccession(t *testing.T) {
	t.Run("uncommitted-originals", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		removed, err := old.ObserveRetiredSuccession(context.Background(), next)
		if err != nil || removed || old.removed || next.removed {
			t.Fatal("closed uncommitted original tables became a new native mutation", removed, err)
		}
		if err := old.ObserveClosed(context.Background()); err != nil {
			t.Fatal("readback changed its original predecessor", err)
		}
		if err := next.ObserveClosed(context.Background()); err != nil {
			t.Fatal("readback changed its original candidate", err)
		}
	})
	t.Run("committed-original-and-live-candidate", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := old.Supersede(context.Background(), next); err != nil {
			t.Fatal(err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err == nil || removed {
			t.Fatal("live original successor became a closed retirement receipt", removed, err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err != nil || !removed {
				t.Fatal("acknowledged original succession lost its retired candidate", removed, err)
			}
		}
		if err := next.ObserveClosed(context.Background()); err != nil {
			t.Fatal("committed readback changed successor protection", err)
		}
	})
	t.Run("foreign-candidate", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		foreign := linuxNodeBaselineFixture(t, false)
		foreignSource := linuxNodeBaselineSource(t, foreign, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := old.Supersede(context.Background(), next); err != nil {
			t.Fatal(err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := foreignSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), foreign); err == nil || removed {
			t.Fatal("acknowledged deletion adopted a different retained candidate", removed, err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err != nil || !removed {
			t.Fatal("rejected foreign receipt damaged its original succession", removed, err)
		}
	})
	t.Run("unacknowledged-absence", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", old.nft.table()}, ""); err != nil {
			t.Fatal(err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err == nil || removed || old.removed {
			t.Fatal("unacknowledged native absence manufactured an original commit receipt", removed, err)
		}
		if err := next.ObserveClosed(context.Background()); err != nil {
			t.Fatal("unknown predecessor removal changed the retained candidate", err)
		}
	})
	t.Run("replaced-original-table", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := old.Supersede(context.Background(), next); err != nil {
			t.Fatal(err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		replacement, err := NewDesktopLinuxNodeBaseline(context.Background(), old.nft.Capture, false)
		if replacement != nil {
			defer replacement.Close(context.Background())
		}
		if err != nil {
			t.Fatal(err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err == nil || removed {
			t.Fatal("old acknowledged receipt erased a same-name replacement", removed, err)
		}
		if err := replacement.ObserveClosed(context.Background()); err != nil {
			t.Fatal("readback mutated replacement protection", err)
		}
	})
	t.Run("cancelled-and-closed-native-owner", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if removed, err := old.ObserveRetiredSuccession(cancelled, next); err == nil || removed {
			t.Fatal("cancelled readback entered its retained native owners", removed, err)
		}
		if err := old.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if removed, err := old.ObserveRetiredSuccession(context.Background(), next); err == nil || removed {
			t.Fatal("closed original namespace and netlink objects authorized readback", removed, err)
		}
	})
}
