//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func linuxBootstrapNativeRules(t *testing.T, ctx context.Context, table string) map[string]uint64 {
	t.Helper()
	rows, err := desktopLinuxNFTReadTable(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]uint64{}
	for _, row := range rows {
		rule, ok := row["rule"].(map[string]any)
		if !ok {
			continue
		}
		label, ok := rule["comment"].(string)
		handle := desktopLinuxNumber(rule["handle"])
		if !ok || label == "" || rules[label] != 0 || handle == 0 || handle > 1<<53-1 || rule["family"] != "inet" || rule["table"] != table || rule["chain"] != "output" {
			t.Fatal("actual fixture has an ambiguous native rule", rule)
		}
		rules[label] = handle
	}
	return rules
}

// The fixture owns an unhooked table in the runner's fresh network namespace.
// It uses real nftables mutations and the shipping retained Netlink endpoint;
// names/comments below locate fixture assertions, not production authority.
func TestDesktopLinuxGuardianKernelStandardBootstrapConditionalRemoval(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("bootstrap conditional removal requires the explicit isolated namespace runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	table := linuxBootstrapTransactionTable()
	desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("add table inet %s\nadd chain inet %s output\nadd rule inet %s output counter drop comment \"fixture-baseline\"\nadd rule inet %s output meta mark 4026531841 accept comment \"fixture-bootstrap\"\n", table, table, table, table))
	t.Cleanup(func() {
		_, _ = desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", table}, "")
	})
	n, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := n.close(); err != nil {
			t.Error(err)
		}
	}()
	original := linuxBootstrapNativeRules(t, ctx, table)
	if len(original) != 2 || original["fixture-baseline"] == 0 || original["fixture-bootstrap"] == 0 {
		t.Fatal("fixture omitted independent baseline and bootstrap rules", original)
	}
	handle := original["fixture-bootstrap"]
	check := func(t *testing.T, label string) {
		t.Helper()
		got := linuxBootstrapNativeRules(t, ctx, table)
		if got["fixture-baseline"] != original["fixture-baseline"] || got[label] != handle {
			t.Fatal("conditional removal changed the captured baseline or retained rule", got)
		}
	}
	t.Run("stale-ruleset", func(t *testing.T) {
		before, err := n.generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("add rule inet %s output counter drop comment \"fixture-intervening\"\n", table))
		if ack, sent, err := n.deleteBootstrapRule(ctx, before, table, handle); ack || !sent || !errors.Is(err, syscall.ERESTART) {
			t.Fatal("stale bootstrap generation did not reject the actual conditional transaction", ack, sent, err)
		}
		check(t, "fixture-bootstrap")
		extra := linuxBootstrapNativeRules(t, ctx, table)["fixture-intervening"]
		if extra == 0 {
			t.Fatal("stale transaction removed an intervening rule")
		}
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("delete rule inet %s output handle %d\n", table, extra))
	})
	t.Run("same-handle-replacement", func(t *testing.T) {
		before, err := n.generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("replace rule inet %s output handle %d meta mark 4026531842 drop comment \"fixture-replacement\"\n", table, handle))
		if ack, sent, err := n.deleteBootstrapRule(ctx, before, table, handle); ack || !sent || !errors.Is(err, syscall.ERESTART) {
			t.Fatal("old inventory deleted a same-handle replacement", ack, sent, err)
		}
		check(t, "fixture-replacement")
		// Only this fixture creator restores its own deliberately changed rule.
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("replace rule inet %s output handle %d meta mark 4026531841 accept comment \"fixture-bootstrap\"\n", table, handle))
	})
	t.Run("cancelled", func(t *testing.T) {
		current, err := n.generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if ack, sent, err := n.deleteBootstrapRule(cancelled, current, table, handle); ack || sent || err == nil {
			t.Fatal("cancelled cleanup sent a native mutation", ack, sent, err)
		}
		check(t, "fixture-bootstrap")
	})
	t.Run("committed", func(t *testing.T) {
		current, err := n.generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ack, sent, err := n.deleteBootstrapRule(ctx, current, table, handle); !ack || !sent || err != nil {
			t.Fatal("exact bootstrap removal lacks its original committed receipt", ack, sent, err)
		}
		got := linuxBootstrapNativeRules(t, ctx, table)
		if len(got) != 1 || got["fixture-baseline"] != original["fixture-baseline"] {
			t.Fatal("exact bootstrap removal did not preserve the original baseline", got)
		}
	})
	t.Run("retired-handle", func(t *testing.T) {
		current, err := n.generation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ack, sent, err := n.deleteBootstrapRule(ctx, current, table, handle); ack || !sent || !errors.Is(err, syscall.ENOENT) {
			t.Fatal("retired bootstrap handle acquired another native rule", ack, sent, err)
		}
		got := linuxBootstrapNativeRules(t, ctx, table)
		if len(got) != 1 || got["fixture-baseline"] != original["fixture-baseline"] {
			t.Fatal("retired cleanup changed baseline", got)
		}
	})
	t.Run("closed-endpoint", func(t *testing.T) {
		if err := n.close(); err != nil {
			t.Fatal(err)
		}
		if ack, sent, err := n.deleteBootstrapRule(ctx, 1, table, handle); ack || sent || err == nil {
			t.Fatal("closed bootstrap endpoint adopted a new transport", ack, sent, err)
		}
	})
}
