//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func linuxBaselineNativeHandle(t *testing.T, ctx context.Context) uint64 {
	t.Helper()
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-a", "list", "table", "inet", "rvpn_baseline_transaction"}, "")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		NFTables []struct {
			Table *struct {
				Family, Name string
				Handle       uint64
			}
		}
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	var handle uint64
	for _, entry := range result.NFTables {
		if entry.Table == nil {
			continue
		}
		if handle != 0 || entry.Table.Family != "inet" || entry.Table.Name != "rvpn_baseline_transaction" {
			t.Fatal("ambiguous actual test table")
		}
		handle = entry.Table.Handle
	}
	if handle == 0 || handle > 1<<53-1 {
		t.Fatal("actual test table has no exact native handle")
	}
	return handle
}

func TestDesktopLinuxGuardianKernelBaselineTransactions(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("Linux baseline transactions require the explicit isolated namespace runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := n.close(); err != nil {
			t.Error(err)
		}
	}()
	before, err := n.generation(ctx)
	if err != nil || before == 0 {
		t.Fatal("actual kernel did not supply its generation", before, err)
	}
	desktopLinuxProtectionNativeCommand(t, "add table inet rvpn_baseline_transaction\n")
	t.Cleanup(func() {
		_, _ = desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", "rvpn_baseline_transaction"}, "")
	})
	handle := linuxBaselineNativeHandle(t, ctx)
	if ack, sent, err := n.delete(ctx, before, handle); ack || !sent || !errors.Is(err, syscall.ERESTART) {
		t.Fatal("stale ruleset generation did not reject the actual conditional transaction", ack, sent, err)
	}
	if got := linuxBaselineNativeHandle(t, ctx); got != handle {
		t.Fatal("stale transaction changed the exact table")
	}
	current, err := n.generation(ctx)
	if err != nil || current == before {
		t.Fatal("actual committed ruleset change did not advance generation", current, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if ack, sent, err := n.delete(cancelled, current, handle); ack || sent || err == nil {
		t.Fatal("cancelled transaction reached the actual kernel", ack, sent, err)
	}
	if got := linuxBaselineNativeHandle(t, ctx); got != handle {
		t.Fatal("cancelled transaction changed its table")
	}
	if ack, sent, err := n.delete(ctx, current, handle); !ack || !sent || err != nil {
		t.Fatal("exact transaction lacked its native commit receipt", ack, sent, err)
	}
	if _, err := desktopLinuxNFTCommand(ctx, []string{"list", "table", "inet", "rvpn_baseline_transaction"}, ""); err == nil {
		t.Fatal("committed deletion left its original table")
	}
	desktopLinuxProtectionNativeCommand(t, "add table inet rvpn_baseline_transaction\n")
	replacement := linuxBaselineNativeHandle(t, ctx)
	if replacement == handle {
		t.Fatal("kernel reused the deleted test handle")
	}
	current, err = n.generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ack, sent, err := n.delete(ctx, current, handle); ack || !sent || !errors.Is(err, syscall.ENOENT) {
		t.Fatal("retired handle deleted or adopted a same-name replacement", ack, sent, err)
	}
	if got := linuxBaselineNativeHandle(t, ctx); got != replacement {
		t.Fatal("old deletion removed the replacement table")
	}
	// Concurrent observers share the same native socket and sequence stream;
	// no reply may be consumed or deadline reset by another operation.
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if got, err := n.generation(ctx); err != nil || got != current {
				t.Errorf("serialized native generation lost its receipt: %d %v", got, err)
			}
		}()
	}
	group.Wait()
	if ack, sent, err := n.delete(ctx, current, replacement); !ack || !sent || err != nil {
		t.Fatal("replacement's own exact deletion failed", ack, sent, err)
	}
	if err := n.close(); err != nil {
		t.Fatal(err)
	}
	if generation, err := n.generation(ctx); generation != 0 || err == nil {
		t.Fatal("closed endpoint acquired another owner")
	}
	// Retain actual descriptor inventory evidence across repeated open/close.
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		endpoint, err := desktopLinuxOpenBaselineNetlink()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := endpoint.generation(ctx); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.close(); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.close(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(files) {
		t.Fatal("native baseline endpoint teardown leaked descriptors", len(files), len(after), err)
	}
}
