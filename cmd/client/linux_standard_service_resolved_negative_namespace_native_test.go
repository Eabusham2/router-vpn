//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const installedPrivateNegativeRelease = "/run/routervpn-private-negative-complete"
const installedPrivateNegativeReceipt = "verified installed private-TLD original negative RPC and joined cleanup: "

func linuxHostTUNPrivateNegativeCase(scenario string) bool {
	switch scenario {
	case "service-boot-resolved-dnssec-private-tld-negative-nxdomain-a", "service-boot-resolved-dnssec-private-tld-negative-nxdomain-aaaa", "service-boot-resolved-dnssec-private-tld-negative-nodata-a", "service-boot-resolved-dnssec-private-tld-negative-nodata-aaaa":
		return true
	}
	return false
}

// This is the shipping authenticated bootstrap conversation, before Connect's
// compilation deliberately replaces detailed lookup errors. No RPC, helper,
// validator, physical socket or retirement callback is substituted.
func linuxHostTUNPrivateNegativeBootstrap(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, scenario string) (failure error) {
	if !linuxHostTUNPrivateNegativeCase(scenario) {
		return nil
	}
	// Match compileDesktopNode's shipping lookup window without renewing
	// the outer operation. The same owner also bounds its cleanup.
	work, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = work
	if _, err := os.Lstat(installedPrivateNegativeRelease); !errors.Is(err, os.ErrNotExist) {
		return errors.New("negative fixture release was already present")
	}
	operation, finish, err := a.beginConnectionTransaction()
	if err != nil {
		return err
	}
	defer finish()
	profile := cloneRouterProfile(a.profiles.Profiles[0])
	before, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json"), 64<<10)
	if err != nil {
		return err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil {
		return err
	}
	b, err := captureLinuxBootBootstrapClient(ctx, a, parent, operation, profile, linuxHostTUNMode(scenario), network)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, b.cleanup(ctx)) }()
	answers, handled, lookupErr := b.lookup(ctx, profile.Endpoint)
	const expected = "captured DNS has no usable A or AAAA answer\ncaptured system resolver returned no endpoint address"
	if !handled || len(answers) != 0 || lookupErr == nil || lookupErr.Error() != expected {
		return fmt.Errorf("installed negative RPC did not return its exact accepted no-address result: handled=%t addresses=%d cause=%v", handled, len(answers), lookupErr)
	}
	if err = b.cleanup(ctx); err != nil {
		return err
	}
	if !b.cleanupAcknowledged || !b.closed.Load() {
		return errors.New("installed negative original cleanup was not acknowledged")
	}
	if _, present := linuxStandardBootBootstraps.Load(a); present {
		return errors.New("installed negative retained original bootstrap registration")
	}
	after, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json"), 64<<10)
	if err != nil || !bytes.Equal(before, after) {
		return errors.Join(err, errors.New("negative lookup replaced original durable protection"))
	}
	current, err := physicalNetworkIdentityContext(ctx)
	if err != nil || current != network {
		return errors.Join(err, errors.New("negative lookup changed original physical network"))
	}
	if err = parent.Current(ctx); err != nil {
		return err
	}
	view := a.captureLinuxStandardServiceProtection(ctx)
	if view == nil || view.Failure != nil || !view.Owned || !view.Active || view.Policy != "always" {
		return errors.New("negative lookup lost original retained boot protection")
	}
	a.mu.Lock()
	bad := a.cmd != nil || a.state.Connected || a.profiles.Profiles[0].UseCount != profile.UseCount
	a.mu.Unlock()
	if bad {
		return errors.New("negative lookup adopted a Node or changed original usage")
	}
	// The independent peer changes only its answer after exact original cleanup.
	// A fresh ordinary Connect then exercises the unchanged successful lifecycle.
	file, err := os.OpenFile(installedPrivateNegativeRelease, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(strings.TrimPrefix(scenario, "service-boot-resolved-dnssec-private-tld-negative-"))
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, installedPrivateNegativeReceipt+scenario)
	return nil
}
