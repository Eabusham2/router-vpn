//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
)

func desktopLinuxOffFixture(t *testing.T) (*DesktopLinuxSocketPolicy, []map[string]any, []map[string]any) {
	t.Helper()
	p, prepared, retired := desktopLinuxProtectionFixture(t)
	n := p.nft
	n.TableName, n.HostProtectionOff, n.DenyHandle = desktopLinuxNodeTable(n.Capture), true, 301
	p.options.HostProtectionOff = true
	for _, rows := range [][]map[string]any{prepared, retired} {
		for _, row := range rows {
			for kind, raw := range row {
				object := raw.(map[string]any)
				if kind == "table" {
					object["name"] = n.table()
				}
				if kind == "chain" || kind == "rule" || kind == "set" {
					object["table"] = n.table()
				}
				if kind == "chain" {
					object["policy"] = "accept"
				}
			}
		}
	}
	// Real nft insert semantics place all permits first, the isolated UID deny
	// second, then the original baseline exemptions. Sets have no packet order.
	prefix := 3 + len(n.Baseline)
	rows := append([]map[string]any{}, prepared[:3]...)
	rows = append(rows, prepared[prefix:]...)
	rows = append(rows, map[string]any{"rule": map[string]any{"family": "inet", "table": n.table(), "chain": "output", "handle": float64(n.DenyHandle), "comment": n.comment("deny"), "expr": n.denyExpressions()}})
	rows = append(rows, prepared[3:prefix]...)
	return p, rows, retired
}

func TestDesktopLinuxOffOriginalUIDInventory(t *testing.T) {
	for _, fault := range []string{"original", "missing-deny", "foreign-uid", "broad-drop", "foreign-handle", "deny-after-exemption", "permit-after-deny", "duplicate-deny", "host-drop", "protected-mode", "extra-foreign-rule", "same-prefix-accept", "retired", "retired-deny-remains"} {
		t.Run(fault, func(t *testing.T) {
			p, rows, retired := desktopLinuxOffFixture(t)
			n := p.nft
			denyIndex := 3 + 8
			deny := rows[denyIndex]["rule"].(map[string]any)
			prepared := true
			switch fault {
			case "missing-deny":
				rows = append(rows[:denyIndex], rows[denyIndex+1:]...)
			case "foreign-uid":
				deny["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(n.UID + 1)
			case "broad-drop":
				deny["expr"] = []any{map[string]any{"drop": nil}}
			case "foreign-handle":
				deny["handle"] = float64(n.DenyHandle + 1)
			case "deny-after-exemption":
				rows[denyIndex], rows[denyIndex+1] = rows[denyIndex+1], rows[denyIndex]
			case "permit-after-deny":
				rows[3], rows[denyIndex] = rows[denyIndex], rows[3]
			case "duplicate-deny":
				rows = append(rows, rows[denyIndex])
			case "host-drop":
				rows[2]["chain"].(map[string]any)["policy"] = "drop"
			case "protected-mode":
				n.HostProtectionOff = false
			case "extra-foreign-rule":
				rows = append(rows, map[string]any{"rule": map[string]any{"family": "inet", "table": n.table(), "chain": "output", "handle": float64(999), "expr": []any{map[string]any{"accept": nil}}}})
			case "same-prefix-accept":
				foreign := map[string]any{"rule": map[string]any{"family": "inet", "table": n.table(), "chain": "output", "handle": float64(999), "comment": n.comment("foreign"), "expr": []any{map[string]any{"accept": nil}}}}
				rows = append(rows[:3], append([]map[string]any{foreign}, rows[3:]...)...)
			case "retired":
				rows = retired
				prepared = false
			case "retired-deny-remains":
				rows = append(retired, rows[denyIndex])
				prepared = false
			}
			err := desktopLinuxProtectionRows(n, rows, prepared)
			valid := fault == "original" || fault == "retired"
			if (err == nil) != valid {
				t.Fatal("Off inventory lost exact original UID/host/retirement semantics", fault, err)
			}
			if prepared {
				if err := n.verifyRows(rows, true); (err == nil) != valid {
					t.Fatal("active grant inventory accepted foreign or changed original rule", fault, err)
				}
			}
			if fault == "original" {
				if err := n.verifyRows(rows, true); err != nil {
					t.Fatal(err)
				}
				record, err := p.protectionRecord()
				if err != nil || !record.HostProtectionOff {
					t.Fatal("original Off record lost selection", err)
				}
				p.options.HostProtectionOff = false
				if _, err := p.protectionRecord(); err == nil {
					t.Fatal("changed selection reused nonblocking owner")
				}
			}
		})
	}
}

func TestDesktopLinuxOffCreationCannotAdoptProtectedReceipt(t *testing.T) {
	capture, options, protected := linuxNodeCreationReceipt(t, false)
	options.HostProtectionOff = true
	if _, err := desktopLinuxNodeBaselineReceipt(protected, capture, options); err == nil {
		t.Fatal("Off adopted protected creation")
	}
	off := []byte(strings.Replace(string(protected), `"policy":"drop"`, `"policy":"accept"`, 1))
	n, err := desktopLinuxNodeBaselineReceipt(off, capture, options)
	if err != nil || !n.HostProtectionOff {
		t.Fatal("exact nonblocking creation lost mode", err)
	}
	options.HostProtectionOff = false
	if _, err := desktopLinuxNodeBaselineReceipt(off, capture, options); err == nil {
		t.Fatal("protected owner adopted Off creation")
	}
	p, _, _ := desktopLinuxOffFixture(t)
	record, err := p.protectionRecord()
	if err != nil {
		t.Fatal(err)
	}
	created := DesktopLinuxNodeCreationRecord{Capture: record.Capture, HostProtectionOff: true, TableName: record.TableName, TableHandle: record.TableHandle, ChainHandle: record.ChainHandle, BaselineSHA256: record.BaselineSHA256}
	if !created.MatchesPrepared(record) {
		t.Fatal("original Off creation rejected prepared owner")
	}
	created.HostProtectionOff = false
	if created.MatchesPrepared(record) {
		t.Fatal("Off prepared owner substituted protected creation")
	}
	// Existing protected records retain their exact old JSON field set.
	record.HostProtectionOff = false
	record.DenyHandle = 0
	body, _ := json.Marshal(record)
	if strings.Contains(string(body), "host_protection_off") {
		t.Fatal("protected serialization changed")
	}
}

// Real kernel descriptors prove that wrapper closure cannot retire an alias.
// No nft or native guardian permission is simulated by this descriptor test.
func TestDesktopLinuxOffDescriptorRetirementRequiresAllOriginalAliases(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	returned := os.NewFile(uintptr(fd), "off-original-returned")
	defer returned.Close()
	capture, owner := desktopSocketFixtureCapture(), desktopSocketFixturePolicy().owner
	p := &DesktopLinuxSocketPolicy{capture: capture, owner: owner, uid: uint32(os.Geteuid()), options: DesktopLinuxSocketOptions{HostProtectionOff: true}}
	creation := DesktopSocketCreation{Capture: capture, Binding: DesktopSocketBinding{Owner: owner}, SocketID: strings.Repeat("f", 32), Network: "udp"}
	p.mu.Lock()
	err = p.retainOffDescriptor(creation, returned)
	p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	retained := p.offSockets[creation.SocketID].file
	defer retained.Close()
	flags, _, flagErr := syscall.Syscall(syscall.SYS_FCNTL, retained.Fd(), syscall.F_GETFD, 0)
	if flagErr != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("original retained reference can escape concurrent exec", flags, flagErr)
	}
	duplicate, err := syscall.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if duplicate >= 0 {
			syscall.Close(duplicate)
		}
	}()
	if err := returned.Close(); err != nil {
		t.Fatal(err)
	}
	if p.offDescriptorsRetired() {
		t.Fatal("wrapper closure erased original native retention")
	}
	if err := p.releaseOffDescriptor(context.Background(), creation); err == nil {
		t.Fatal("live kernel duplicate acknowledged original retirement")
	}
	if p.offSockets[creation.SocketID].file != retained {
		t.Fatal("failed join replaced retained native owner")
	}
	foreign := creation
	foreign.Capture.SourceSHA256 = strings.Repeat("e", 64)
	if err := p.releaseOffDescriptor(context.Background(), foreign); err == nil {
		t.Fatal("foreign capture released original descriptor")
	}
	if err := syscall.Close(duplicate); err != nil {
		t.Fatal(err)
	}
	duplicate = -1
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.releaseOffDescriptor(cancelled, creation); err == nil {
		t.Fatal("cancelled retirement mutated original owner")
	}
	if err := p.releaseOffDescriptor(context.Background(), creation); err != nil {
		t.Fatal("all original aliases closed but retirement did not join", err)
	}
	if !p.offDescriptorsRetired() {
		t.Fatal("joined original socket remained pending")
	}
	if _, err := retained.Stat(); err == nil {
		t.Fatal("successful retirement kept original kernel duplicate")
	}
}
