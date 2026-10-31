//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"testing"
)

func TestDesktopLinuxGuardianKernelNodeCreationJournalReceipt(t *testing.T) {
	for _, homeLAN := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed-LAN", true: "selected-LAN"}[homeLAN], func(t *testing.T) {
			baseline := linuxNodeBaselineFixture(t, homeLAN)
			created, err := baseline.Created(context.Background())
			if err != nil || created.Validate() != nil || created.Capture != baseline.nft.Capture || created.HomeLAN != homeLAN ||
				created.TableHandle != baseline.nft.TableHandle || created.ChainHandle != baseline.nft.ChainHandle {
				t.Fatal("original exclusive creation lost its journal receipt", err)
			}
			again, err := baseline.Created(context.Background())
			if err != nil || again != created {
				t.Fatal("original creation observation changed without a native mutation", err)
			}
			duplicate, err := NewDesktopLinuxNodeBaseline(context.Background(), baseline.nft.Capture, homeLAN)
			if duplicate == nil || err == nil {
				t.Fatal("duplicate constructor acquired the original table", err)
			}
			if _, err := duplicate.Created(context.Background()); err == nil {
				t.Fatal("failed creation adopted a matching table into its durable receipt")
			}
			if err := duplicate.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			source := linuxNodeBaselineSource(t, baseline, homeLAN)
			prepared, err := source.ObservePreparedProtection(context.Background(), source.capture)
			if err != nil || !created.MatchesPrepared(prepared) {
				t.Fatal("original creation and actual guardian disagree on their baseline", err)
			}
			if _, err := baseline.Created(context.Background()); err == nil {
				t.Fatal("already bound guardian was relabelled as a fresh creation")
			}
			if err := source.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := baseline.Created(context.Background()); err == nil {
				t.Fatal("guardian retirement reset the original creation phase")
			}
			if err := baseline.Release(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("replacement-is-not-original-creation", func(t *testing.T) {
		baseline := linuxNodeBaselineFixture(t, false)
		original, err := baseline.Created(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", original.TableName}, ""); err != nil {
			t.Fatal(err)
		}
		replacement, err := NewDesktopLinuxNodeBaseline(context.Background(), original.Capture, false)
		if replacement != nil {
			defer replacement.Close(context.Background())
		}
		if err != nil {
			t.Fatal(err)
		}
		next, err := replacement.Created(context.Background())
		if err != nil || next.TableHandle == original.TableHandle {
			t.Fatal("native replacement did not obtain its own exclusive identity", err)
		}
		if _, err := baseline.Created(context.Background()); err == nil {
			t.Fatal("same-name native replacement became the original creation receipt")
		}
		if err := baseline.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if again, err := replacement.Created(context.Background()); err != nil || again != next {
			t.Fatal("old creator teardown altered its replacement", err)
		}
		if err := replacement.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}
