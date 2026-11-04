//go:build linux

package desktopnetwork

import (
	"context"
	"syscall"
	"testing"
)

// Called only from the mandatory isolated namespace fixture. This exercises
// the original subscribed socket and real kernel rule notifications; a final
// unchanged routing snapshot cannot substitute for both observed transitions.
func networkNativeIPv6RuleObserver(t *testing.T, ctx context.Context) {
	t.Helper()
	owner, native := networkNativeOwner(t, ctx)
	raw, err := native.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var address syscall.Sockaddr
	var observed error
	if err := raw.Control(func(fd uintptr) {
		address, observed = syscall.Getsockname(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	bound, ok := address.(*syscall.SockaddrNetlink)
	if observed != nil || !ok || bound.Pid == 0 ||
		bound.Groups&(1<<(syscall.RTNLGRP_IPV6_RULE-1)) == 0 ||
		bound.Groups&(1<<(syscall.RTNLGRP_ND_USEROPT-1)) != 0 {
		t.Fatal("original observer missed IPv6 rules or subscribed to unrelated neighbor messages", observed)
	}
	if err := owner.Begin(ctx, nil); err != nil {
		t.Fatal(err)
	}
	created := false
	t.Cleanup(func() {
		if created {
			networkNativeIP(t, "-6", "rule", "delete", "priority", "11001", "from", "2001:db8:64::/64", "lookup", "2023")
		}
	})
	networkNativeIP(t, "-6", "rule", "add", "priority", "11001", "from", "2001:db8:64::/64", "lookup", "2023")
	created = true
	networkNativeIP(t, "-6", "rule", "delete", "priority", "11001", "from", "2001:db8:64::/64", "lookup", "2023")
	created = false
	if err := native.Barrier(ctx); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	events := append([]Event(nil), owner.events...)
	owner.mu.Unlock()
	var rules []Event
	for _, event := range events {
		if event.Kind == "rule" && event.Object.Family == 6 && event.Object.Priority == 11001 && event.Object.Table == 2023 {
			rules = append(rules, event)
		}
	}
	if len(rules) != 2 || rules[0].Action != "add" || rules[1].Action != "delete" || rules[0].Object != rules[1].Object {
		t.Fatal("original socket did not deliver both exact IPv6 rule transitions", rules)
	}
	current, err := native.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range current.Objects {
		if object == rules[0].Object {
			t.Fatal("actual fixture rule did not retire before the final snapshot")
		}
	}
	if err := owner.End(ctx, nil); err == nil {
		t.Fatal("IPv6 rule away-and-back was absorbed into an unchanged snapshot")
	}
	if err := owner.Current(); err == nil {
		t.Fatal("IPv6 rule restoration cleared the original failure latch")
	}
}
