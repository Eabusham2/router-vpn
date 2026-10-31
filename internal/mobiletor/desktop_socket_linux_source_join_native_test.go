//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDesktopLinuxGuardianKernelNodeSourceJoin(t *testing.T) {
	t.Run("complete-original-source", func(t *testing.T) {
		baseline := linuxNodeBaselineFixture(t, false)
		source := linuxNodeBaselineSource(t, baseline, false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		original, err := source.ObservePreparedGuardian(ctx, source.capture)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.ObserveJoinedSource(ctx, source.capture); err == nil {
			t.Fatal("live original source fabricated its native join")
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		joined, err := source.ObserveJoinedSource(ctx, source.capture)
		if err != nil || joined.Validate() != nil || joined.Original == nil || *joined.Original != original ||
			joined.ProcessID != uint32(source.command.Process.Pid) || source.command.ProcessState == nil ||
			!desktopLinuxJoined(source.joined) || !desktopLinuxJoined(source.monitorDone) {
			t.Fatal("joined source lost its actual original command or native birth record", err)
		}
		foreign := source.capture
		foreign.SourceSHA256 = strings.Repeat("a", 64)
		if _, err := source.ObserveJoinedSource(ctx, foreign); err == nil {
			t.Fatal("joined original source transferred to another selected path")
		}
		// A source's native close is part of the receipt. Successful Cmd.Wait
		// alone cannot substitute for the retained descriptor retirement.
		source.nativeGuardian.closed = false
		_, err = source.ObserveJoinedSource(ctx, source.capture)
		source.nativeGuardian.closed = true
		if err == nil {
			t.Fatal("actual process exit hid unacknowledged native witness teardown")
		}
		copy := joined.Clone()
		copy.Original.Guardian.StartTicks++
		if *joined.Original != original {
			t.Fatal("joined source comparison aliased a returned caller copy")
		}
		if err := baseline.ObserveClosed(ctx); err != nil {
			t.Fatal("joined original source left its parent baseline open", err)
		}
		if err := baseline.Release(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("incomplete-created-source-without-baseline", func(t *testing.T) {
		// Remove this fixture's exact table before actual construction. The
		// real guardian starts, rejects the absent baseline and returns a
		// partial source. No mocked process, PID or native join supplies proof.
		baseline := linuxNodeBaselineFixture(t, false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := baseline.Release(ctx); err != nil {
			t.Fatal(err)
		}
		physical, err := net.InterfaceByName("rvpn-test")
		if err != nil {
			t.Fatal(err)
		}
		options := DesktopLinuxSocketOptions{Interfaces: []DesktopLinuxSocketInterface{{Name: physical.Name, Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}}}
		source, err := NewDesktopLinuxNodeSocketPolicy(ctx, baseline.nft.Capture, options)
		if source != nil {
			t.Cleanup(func() {
				if err := source.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
		}
		if err == nil || source == nil || source.command == nil || source.command.Process == nil || source.nativeGuardian == nil || source.nativeGuardian.complete {
			t.Fatal("missing baseline did not preserve an actual incomplete created source", err)
		}
		if _, err := source.ObserveJoinedSource(ctx, source.capture); err == nil {
			t.Fatal("partial constructor fabricated a join before source cleanup")
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		joined, err := source.ObserveJoinedSource(ctx, source.capture)
		if err != nil || joined.Original != nil || joined.Validate() != nil || joined.ProcessID != uint32(source.command.Process.Pid) ||
			source.command.ProcessState == nil || !desktopLinuxJoined(source.joined) || source.nativeGuardian.pidfd != nil {
			t.Fatal("partial original constructor lost its joined command or invented a complete identity", err)
		}
		if _, err := source.ObserveRetiredGuardian(ctx, source.capture); err == nil {
			t.Fatal("partial source join fabricated a complete prepared guardian")
		}
		if err := ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
			t.Fatal("incomplete original source changed independently observed absence", err)
		}
	})
	t.Run("crashed-original-still-requires-source-close", func(t *testing.T) {
		baseline := linuxNodeBaselineFixture(t, false)
		source := linuxNodeBaselineSource(t, baseline, false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := source.command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-source.joined:
		}
		if _, err := source.ObserveJoinedSource(ctx, source.capture); err == nil {
			t.Fatal("crashed process exit bypassed its original source cleanup")
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		joined, err := source.ObserveJoinedSource(ctx, source.capture)
		if err != nil || joined.Original == nil || joined.ProcessID != uint32(source.command.Process.Pid) {
			t.Fatal("actual crashed source cleanup lost its original command", err)
		}
		if err := baseline.Release(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
