//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/standardengine"
	"strings"
	"time"
)

// The namespace caller installs the actual verified generated native engine.
// Only public Internet reachability is modeled. Its real TUN, SOCKS transport,
// selected DNS exchange, original startup ledger, retained kernel epoch and
// production remote constructor/RPC/Stop all execute against a private peer.
func linuxStandardServiceControllerRouteFixture(owned *linuxOwnedController, action string) error {
	root := linuxOwnedControllerRoot
	a := &app{localController: owned, cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes"), StateFile: filepath.Join(root, "state.json")}}
	body, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
	if err != nil {
		return err
	}
	if err = decodeRelayControlJSON(body, &a.profiles); err != nil {
		return err
	}
	for i := range a.profiles.Profiles {
		applyProfileDefaults(&a.profiles.Profiles[i])
	}
	a.state = state{Mode: "off", Phase: "off"}
	if action == "off" {
		get := httptest.NewRecorder()
		a.profileProtectionSettings(get, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
		var view profileProtectionSettings
		if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &view) != nil || view.ProtectionStatus != "retained" || view.EffectivePolicy != "always" {
			return fmt.Errorf("actual service-held boot Always was invisible: %d %s", get.Code, get.Body.String())
		}
		body, _ := json.Marshal(map[string]string{"profile_id": view.ProfileID, "profile_token": view.ProfileToken, "kill_switch_policy": "off"})
		post := httptest.NewRecorder()
		a.profileProtectionSettings(post, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)))
		if post.Code != http.StatusOK {
			return fmt.Errorf("actual boot creator UI Off failed: %d %s", post.Code, post.Body.String())
		}
		if _, err := os.Lstat(filepath.Join(root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("UI Off did not retire original native saved state")
		}
		saved, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
		var store common.RouterProfileStore
		if err != nil || json.Unmarshal(saved, &store) != nil || len(store.Profiles) != 1 || store.Profiles[0].KillSwitch || store.Profiles[0].KillSwitchPolicy != "off" {
			return errors.New("UI Off did not persist actual original result")
		}
		fmt.Fprintln(os.Stdout, "standard-service-route-joined")
		return nil
	}
	if action != "1" && action != "failure" && action != "network-failure" && action != "route-change" && action != "pre-rpc-network-failure" {
		return errors.New("unknown native service fixture action")
	}
	body, err = os.ReadFile(filepath.Join(root, "modes.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(body, &a.modes); err != nil {
		return err
	}
	exit := validTestStandardExit("socks5")
	request, _ := json.Marshal(standardExitConnectRequest{StandardExitID: exit.ID, Direct: true})
	response := httptest.NewRecorder()
	var capturedController *linuxStandardServiceLaunch
	prepare := func(a *app, command *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
		captured, err := prepareLegacyStandardExitOwner(a, command, mode, base, id)
		if err != nil {
			return captured, err
		}
		capturedController, _ = captured.(*linuxStandardServiceLaunch)
		if action == "pre-rpc-network-failure" {
			if capturedController == nil || capturedController.prepared.requestEpoch == nil {
				return captured, errors.New("native pre-RPC fixture omitted original controller epoch")
			}
			operation := a.connectionOperationContextOrBackground()
			before, err := exec.CommandContext(operation, "/usr/sbin/ip", "-j", "link", "show", "dev", "rvphysical").CombinedOutput()
			if err != nil {
				return captured, err
			}
			for _, mtu := range []string{"1400", "1500"} {
				if output, err := exec.CommandContext(operation, "/usr/sbin/ip", "link", "set", "dev", "rvphysical", "mtu", mtu).CombinedOutput(); err != nil {
					return captured, fmt.Errorf("actual pre-RPC physical event: %w %s", err, output)
				}
			}
			after, err := exec.CommandContext(operation, "/usr/sbin/ip", "-j", "link", "show", "dev", "rvphysical").CombinedOutput()
			if err != nil || !bytes.Equal(before, after) {
				return captured, errors.New("pre-RPC native fixture did not restore identical topology")
			}
		}
		return captured, nil
	}
	a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(request)), platformStandardExitRuntime{
		prepareLegacy: prepare,
		prove:         func(*app, string) error { return nil },
		proveDNS: func(ctx context.Context, captured legacyStandardExitLaunch) error {
			// Exercise the shipping service proof and observer installation.
			// The installed pinned core routes its actual selected resolver
			// exchange through the private authenticated SOCKS peer.
			return captured.(*linuxStandardServiceLaunch).ProveSelectedDNS(ctx)
		},
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	})
	if action == "pre-rpc-network-failure" {
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "network") || capturedController == nil || capturedController.attempted || !capturedController.joined || !capturedController.copiesClosed || !capturedController.prepared.requestEpoch.closed || a.cmd != nil || a.state.Connected {
			return fmt.Errorf("pre-RPC native ABA did not reject and join original preparation: %d %s", response.Code, response.Body.String())
		}
		fmt.Fprintln(os.Stdout, "standard-service-route-joined")
		return nil
	}
	if response.Code != http.StatusOK {
		return fmt.Errorf("shipping service Connect failed: %d %s", response.Code, response.Body.String())
	}
	raw, exists := linuxStandardServiceOwners.Load(a)
	owner, ok := raw.(*linuxStandardServiceLaunch)
	if !exists || !ok || owner.Command().Process != nil || !a.state.Connected {
		return errors.New("shipping controller did not retain actual remote engine ownership")
	}
	epoch := owner.prepared.requestEpoch
	if epoch == nil || !epoch.ready || epoch.closed || epoch.startup == nil {
		return errors.New("installed controller omitted original child routing ledger adoption")
	}
	capture, err := standardengine.DecodeCapture(epoch.startup.Capture, standardengine.SHA256(epoch.startup.Capture))
	if err != nil || capture.Session != owner.request.Session || capture.ConfigSHA256 != owner.request.ConfigSHA256 {
		return errors.New("installed controller adopted another source/session ledger")
	}
	if _, err := standardengine.DecodeReady(epoch.startup.Ready, standardengine.SHA256(epoch.startup.Capture)); err != nil {
		return err
	}
	if action == "failure" || action == "network-failure" || action == "route-change" {
		if err = linuxStandardServiceControllerFailureFixture(a, owner, action); err != nil {
			return err
		}
	}
	var foreignBefore []byte
	if action == "route-change" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		foreignBefore, err = linuxStandardForeignRouteCurrent(ctx)
		cancel()
		if err != nil {
			return err
		}
	}
	if err = a.stopMode(); err != nil {
		return fmt.Errorf("shipping service Stop failed: %w", err)
	}
	if action == "route-change" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		after, readErr := linuxStandardForeignRouteCurrent(ctx)
		cancel()
		if readErr != nil || !bytes.Equal(foreignBefore, after) {
			return errors.New("explicit Stop removed or changed disjoint foreign routing")
		}
	}
	if a.state.Connected || a.cmd != nil || !owner.joined {
		return errors.New("shipping original remote cleanup did not join before Off")
	}
	if _, err = os.Stat(filepath.Join(root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("shipping On-connect Stop retained its state after acknowledged service release")
	}
	if action == "failure" || action == "network-failure" || action == "route-change" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		view := a.captureLinuxStandardServiceProtection(ctx)
		if view == nil || !view.Available || view.Failure != nil || view.Owned || view.Active || !view.AbsenceProved {
			return errors.New("explicit Stop did not prove original service protection absence")
		}
	}
	fmt.Fprintln(os.Stdout, "standard-service-route-joined")
	return nil
}

// The controller monitor is joined before a real physical link ABA, so only
// the original service watcher can perform this automatic retirement. The
// protection-view RPC validates the service's live creator, not saved metadata.
func linuxStandardServiceControllerFailureFixture(a *app, owner *linuxStandardServiceLaunch, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, exists := linuxStandardServiceMonitors.Load(owner)
	monitor, ok := raw.(*linuxStandardServiceMonitor)
	if !exists || !ok || monitor.owner != owner {
		return errors.New("service failure fixture lost original controller monitor")
	}
	if err := owner.stopMonitor(ctx); err != nil {
		return err
	}
	select {
	case <-monitor.finished:
	case <-ctx.Done():
		return errors.New("original controller monitor did not join before original network event")
	}
	owner.mu.Lock()
	joined := owner.joined
	owner.mu.Unlock()
	if joined {
		return errors.New("controller cleanup substituted for service-side retirement")
	}
	original := a.captureLinuxStandardServiceProtection(ctx)
	if original == nil || !original.Available || original.Failure != nil || !original.Owned || !original.Active || original.Pending || original.Removed || original.Policy != "on-connect" {
		return errors.New("actual service had no original active On-connect creator")
	}
	owner.mu.Lock()
	sameService := original.client != nil && original.client.peer != nil && owner.peer != nil && original.client.peer.record == owner.peer.record
	owner.mu.Unlock()
	if !sameService {
		return errors.New("protection observation replaced the original engine service peer")
	}
	statePath := filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json")
	saved, err := os.Open(statePath)
	if err != nil {
		return err
	}
	defer saved.Close()
	info, err := saved.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return errors.New("original native saved protection was not bounded and regular")
	}
	body, err := io.ReadAll(io.LimitReader(saved, (64<<10)+1))
	var state legacyExitProtectionState
	if err != nil || json.Unmarshal(body, &state) != nil || state.Policy != "on-connect" || state.Owner.Receipt.Session != owner.request.Session || state.Owner.Receipt.ConfigSHA256 != owner.request.ConfigSHA256 || state.Owner.Receipt.TableHandle == 0 {
		return errors.New("original service saved protection lost its acknowledged creation")
	}
	var foreignBefore []byte
	if action == "failure" {
		trigger := filepath.Join(linuxOwnedControllerRoot, "run", "standard-service-fixture-exit")
		file, err := os.OpenFile(trigger, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString(owner.request.Session)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return err
		}
	} else if action == "route-change" {
		if output, err := exec.CommandContext(ctx, "ip", "route", "add", "198.18.77.0/24", "via", "203.0.113.1", "dev", "rvphysical").CombinedOutput(); err != nil {
			return fmt.Errorf("actual disjoint foreign route: %w %s", err, output)
		}
		foreignBefore, err = linuxStandardForeignRouteCurrent(ctx)
		if err != nil {
			return err
		}
	} else {
		for _, mtu := range []string{"1496", "1500"} {
			command := exec.CommandContext(ctx, "ip", "link", "set", "rvphysical", "mtu", mtu)
			if output, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("actual original physical link ABA: %w %s", err, output)
			}
		}
	}
	for {
		view := a.captureLinuxStandardServiceProtection(ctx)
		if !original.same(view) || !view.Owned || view.Pending || view.Removed || view.AbsenceProved {
			return errors.New("automatic service retirement released or replaced original On-connect creator")
		}
		if !view.Active {
			break // The service reports this only after its original retirement joined.
		}
		select {
		case <-ctx.Done():
			return errors.New("service did not join the original network-invalidated original engine")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if action == "route-change" {
		after, err := linuxStandardForeignRouteCurrent(ctx)
		if err != nil || !bytes.Equal(foreignBefore, after) {
			return errors.New("original engine retirement changed disjoint foreign routing")
		}
	}
	named, err := os.Lstat(statePath)
	after, readErr := os.ReadFile(statePath)
	if err != nil || readErr != nil || !os.SameFile(info, named) || !bytes.Equal(body, after) {
		return errors.New("automatic retirement lost the exact original saved protection inode or body")
	}

	if action == "failure" {
		witness, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "run", "standard-service-fixture-signaled"), 64)
		if err != nil || string(witness) != owner.request.Session {
			return errors.New("installed engine did not exit through its exact original creation pidfd")
		}
	}
	if _, err = os.Lstat(owner.request.Directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("service claimed joined engine before original workspace retirement")
	}
	owner.mu.Lock()
	err = owner.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "current", Session: owner.request.Session}, nil)
	joined = owner.joined
	owner.mu.Unlock()
	if err == nil || joined {
		return errors.New("retired service engine stayed current or controller cleanup substituted for service watch")
	}
	return nil
}

func linuxStandardForeignRouteCurrent(ctx context.Context) ([]byte, error) {
	raw, err := exec.CommandContext(ctx, "ip", "-j", "route", "show", "exact", "198.18.77.0/24").CombinedOutput()
	var rows []struct {
		Destination string `json:"dst"`
		Gateway     string `json:"gateway"`
		Device      string `json:"dev"`
	}
	if err != nil || json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Destination != "198.18.77.0/24" || rows[0].Gateway != "203.0.113.1" || rows[0].Device != "rvphysical" {
		return nil, errors.New("actual disjoint foreign route is no longer present")
	}
	return raw, ctx.Err()
}
