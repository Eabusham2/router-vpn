//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"testing"
)

func linuxStandardProtectionFixture(t *testing.T, lease *os.File) *DesktopLinuxStandardProtection {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("standard native policy requires isolated privileged namespace runner")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	capture := desktopSocketFixtureCapture()
	capture.SessionID = hex.EncodeToString(nonce[:])
	p, err := NewDesktopLinuxStandardProtection(context.Background(), capture.SessionID, capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, false, lease)
	if p != nil {
		t.Cleanup(func() {
			_ = p.Close(context.Background())
			rows, readErr := desktopLinuxNFTReadTable(context.Background(), desktopLinuxStandardTable(capture))
			if readErr == nil && len(rows) > 0 {
				_, _ = desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", desktopLinuxStandardTable(capture)}, "")
			}
		})
	}
	if err != nil || p == nil {
		t.Fatal("actual standard exclusive creation failed", err)
	}
	return p
}
func TestDesktopLinuxGuardianKernelStandardProtectionCreator(t *testing.T) {
	lease, err := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx := context.Background()
	old := linuxStandardProtectionFixture(t, lease)
	if err := ReadDesktopLinuxProtectionAbsence(ctx); err == nil {
		t.Fatal("standard policy was invisible to global absence")
	}
	if err := ReadDesktopLinuxStandardAndLegacyProtectionAbsence(ctx); err == nil {
		t.Fatal("standard policy was invisible to scoped absence")
	}
	receipt, err := old.Receipt(ctx)
	if err != nil || receipt.CreationGeneration == 0 || receipt.TableHandle == 0 || receipt.NamespaceInode == 0 {
		t.Fatal("native creation lost handles/generation/namespace", err)
	}
	duplicate, err := NewDesktopLinuxStandardProtection(ctx, receipt.Session, receipt.ConfigSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, false, lease)
	if err == nil || duplicate == nil || duplicate.Release(ctx, lease) == nil {
		t.Fatal("duplicate native creation adopted original table", err)
	}
	_ = duplicate.Close(ctx)
	// The same live creator may resume a read-only observation; no matching
	// table can grant this ability to an unacknowledged/serialized replacement.
	old.baseline.complete = false
	old.generation = 0
	if _, err := old.Receipt(ctx); err != nil {
		t.Fatal("retained acknowledged creator could not finish readback", err)
	}
	unknown := &DesktopLinuxStandardProtection{baseline: old.baseline}
	if _, err := unknown.Receipt(ctx); err == nil {
		t.Fatal("readback without original acknowledgement recovered creator")
	}
	next := linuxStandardProtectionFixture(t, lease)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := old.Supersede(cancelled, next, lease); err == nil {
		t.Fatal("cancelled succession deleted predecessor")
	}
	if err := old.Current(ctx, lease); err != nil {
		t.Fatal("cancelled succession changed predecessor", err)
	}
	if err := old.Supersede(ctx, next, lease); err != nil {
		t.Fatal("native acknowledged successor could not retire predecessor", err)
	}
	if err := old.Supersede(ctx, next, lease); err != nil {
		t.Fatal("same acknowledged succession retry failed", err)
	}
	if err := next.Current(ctx, lease); err != nil {
		t.Fatal("succession lost its exact remaining policy", err)
	}
	if err := next.Release(ctx, lease); err != nil {
		t.Fatal("original next creator could not release", err)
	}
	if err := next.Release(ctx, lease); err != nil {
		t.Fatal("original acknowledged deletion was not idempotent", err)
	}
}

func TestDesktopLinuxGuardianKernelStandardScopedAbsence(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("scoped native absence requires isolated privileged namespace")
	}
	ctx := context.Background()
	for _, name := range []string{"router_vpn_node_scope_fixture", "router_vpn_standard_foreign", desktopLinuxNFTTable} {
		if _, err := desktopLinuxNFTCommand(ctx, []string{"add", "table", "inet", name}, ""); err != nil {
			t.Fatal(err)
		}
		scoped := ReadDesktopLinuxStandardAndLegacyProtectionAbsence(ctx)
		full := ReadDesktopLinuxProtectionAbsence(ctx)
		_, deletion := desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", name}, "")
		if deletion != nil {
			t.Fatal(deletion)
		}
		if name == "router_vpn_node_scope_fixture" {
			if scoped != nil || full == nil {
				t.Fatal("scoped observer claimed node-family absence", scoped, full)
			}
		} else if scoped == nil || full == nil {
			t.Fatal("scoped observer hid actual foreign standard/shared table", name, scoped, full)
		}
	}
	if err := ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestDesktopLinuxGuardianKernelStandardReplacementCannotBeDeleted(t *testing.T) {
	lease, err := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx := context.Background()
	original := linuxStandardProtectionFixture(t, lease)
	r, err := original.Receipt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", r.Table}, ""); err != nil {
		t.Fatal(err)
	}
	replacement, err := NewDesktopLinuxStandardProtection(ctx, r.Session, r.ConfigSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.2")}, false, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close(ctx)
	if err := original.Release(ctx, lease); err == nil {
		t.Fatal("same-name new native table became old creator authority")
	}
	if err := replacement.Current(ctx, lease); err != nil {
		t.Fatal("old retirement changed replacement", err)
	}
	if err := replacement.Release(ctx, lease); err != nil {
		t.Fatal(err)
	}
}
