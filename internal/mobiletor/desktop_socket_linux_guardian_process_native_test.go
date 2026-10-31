//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopLinuxGuardianKernelNodeProcessWitness(t *testing.T) {
	t.Run("original-created-guardian-and-joined-retirement", func(t *testing.T) {
		baseline := linuxNodeBaselineFixture(t, false)
		source := linuxNodeBaselineSource(t, baseline, false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		record, err := source.ObservePreparedGuardian(ctx, source.capture)
		if err != nil || record.Validate() != nil || record.Engine.ProcessID != os.Getpid() || record.Guardian.ProcessID != source.command.Process.Pid ||
			record.Guardian.ProcParentID != record.Engine.ProcProcessID || record.Guardian.ProcessID == record.Guardian.ProcProcessID {
			t.Fatal("guardian proof lost its original clone, engine or real nested PID mapping", err)
		}
		foreign := source.capture
		foreign.SourceSHA256 = strings.Repeat("f", 64)
		if _, err := source.ObservePreparedGuardian(ctx, foreign); err == nil {
			t.Fatal("guardian native identity transferred to another captured path")
		}
		if _, err := source.ObserveRetiredGuardian(ctx, source.capture); err == nil {
			t.Fatal("live guardian fabricated joined process retirement")
		}
		if err := source.nativeGuardian.capture(ctx, source.command.Process.Pid); err == nil {
			t.Fatal("original guardian clone witness could be recaptured")
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := source.ObservePreparedGuardian(ctx, source.capture); err == nil {
			t.Fatal("joined guardian retained live admission")
		}
		retired, err := source.ObserveRetiredGuardian(ctx, source.capture)
		if err != nil || retired != record || source.nativeGuardian.child != nil || source.nativeGuardian.parent != nil || !source.nativeGuardian.closed {
			t.Fatal("joined guardian lost its original identity or retained native witnesses", err)
		}
		if err := baseline.Release(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dead-guardian-is-not-a-cached-live-proof", func(t *testing.T) {
		baseline := linuxNodeBaselineFixture(t, false)
		source := linuxNodeBaselineSource(t, baseline, false)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		record, err := source.ObservePreparedGuardian(ctx, source.capture)
		if err != nil {
			t.Fatal(err)
		}
		// The fixture retains the actual Cmd created by production. It never
		// opens or kills another process by a decoded numeric PID.
		if err := source.command.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-source.joined:
		case <-ctx.Done():
			t.Fatal("original crashed guardian did not join", ctx.Err())
		}
		if _, err := source.nativeGuardian.observe(ctx, false); err == nil {
			t.Fatal("dead guardian passed its retained native pidfd/task witness")
		}
		if _, err := source.ObserveRetiredGuardian(ctx, source.capture); err == nil {
			t.Fatal("guardian process exit fabricated descriptor and firewall retirement")
		}
		if err := source.Close(ctx); err != nil {
			t.Fatal(err)
		}
		retired, err := source.ObserveRetiredGuardian(ctx, source.capture)
		if err != nil || retired != record {
			t.Fatal("exact crashed guardian cleanup lost its captured process", err)
		}
		if err := baseline.Release(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
