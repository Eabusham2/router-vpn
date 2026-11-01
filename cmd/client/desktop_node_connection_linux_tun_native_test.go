//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

// Both HTTP handlers below execute the shipping dispatch and all actual
// installed native owners. No preparation, process, readiness, health, Stop or
// kernel callback is substituted. The outer peer independently counts the
// encrypted DNS and Router responses before this original runtime is stopped.
func linuxHostTUNPublicConnection(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture,
	controller *ownedDesktopController, gate *os.File, scenario string) (failure error) {
	cover := linuxHostTUNCoverCase(scenario)
	raw, err := readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 20 {
		return errors.Join(err, errors.New("installed public Connect lost the original runtime catalog"))
	}
	if cover {
		options := httptest.NewRecorder()
		a.options(options, httptest.NewRequest(http.MethodPost, "/api/options", strings.NewReader(`{"daita":true}`)).WithContext(ctx))
		if options.Code != http.StatusOK || strings.TrimSpace(options.Body.String()) != `{"ok":true}` {
			return errors.New("public cover selection did not reach its actual runtime option handler")
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"`+linuxHostTUNMode(scenario)+`"}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	a.connect(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"ok":true}` {
		return fmt.Errorf("installed public Connect failed its real handler: %d: %s", response.Code, response.Body.String())
	}
	a.operationMu.Lock()
	locked := true
	defer func() {
		if locked {
			a.operationMu.Unlock()
		}
	}()
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, command)
	if err != nil || !handled || path == nil || path.sessionParent.parent != parent.parent || path.host == nil {
		return errors.Join(err, errors.New("installed public Connect used a legacy or unproved runtime"))
	}
	host, session, journal := path.host, path.session, path.journal
	var monitor *desktopLinuxNodeMonitor
	defer func() {
		if failure != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			failure = errors.Join(failure, retireDesktopLinuxNodeRestore(cleanup, session, host))
		}
	}()
	if err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.connectionContext != nil || a.connectionCancel != nil || host.activation == nil ||
			host.activation.operation.Err() == nil || host.activation.lifetime.Err() != nil || host.monitor == nil || host.monitor.Load() == nil ||
			host.policy == nil || host.ready == nil || host.ready.MTU != 1376 || host.policy.Metadata().RestoredMTU != 0 ||
			a.cmd != command || !a.state.Connected || a.state.Phase != "connected" ||
			a.profiles.Profiles[0].UseCount != 1 || a.daitaCancel != nil || a.state.DAITA != cover ||
			host.options[0] != cover || host.savedOptions[0] || a.profiles.Profiles[0].DAITAEnabled ||
			(host.ready.CoverServices == 1) != cover || (host.ready.CoverSHA256 != "") != cover {
			return errors.New("public Connect omitted its completed request, independent monitor, usage or actual fixed MTU")
		}
		monitor = host.monitor.Load()
		return nil
	}); err != nil {
		return err
	}
	// An incompatible legacy graph must refuse before Stop while this exact
	// selected source and protection remain active. It cannot manufacture a
	// fresh session or discard this one merely to pass a legacy launch check.
	if a.guardDesktopOwnedNodeTransition(nil) == nil || host.Current(ctx) != nil {
		return errors.New("public Linux connection allowed an unsupported legacy successor to consume its source")
	}
	view, err := linuxHostTUNMTUView(ctx, a, host)
	if err != nil {
		return err
	}
	dns, err := linuxHostTUNDNSObservation(ctx, a, host)
	if err != nil {
		return err
	}
	result := linuxHostTUNResult{Stage: "ready", Scenario: scenario, SessionID: path.selection.SessionID,
		Outcome: "proved", Ready: &path.ready, Activation: "retained-after-request", DNSProof: &dns, MTUView: &view, Public: true}
	result.StartLayer, result.Physical, err = linuxHostTUNLayerSource(ctx, host, scenario)
	if err != nil {
		return err
	}
	if cover {
		result.Cover = "native-active"
	}
	a.operationMu.Unlock()
	locked = false
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 2); err != nil {
		return err
	}
	if scenario == "cover-replies-lost" {
		// The independent peer has stopped UDP replies. The actual native
		// worker must invalidate the original child and its installed monitor
		// must retire that exact source while retaining fail-closed protection.
		wait, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		select {
		case <-wait.Done():
			return errors.New("dead native cover did not retire its original active source")
		case <-monitor.finished:
		}
		if err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.state.Connected || a.state.Phase != "failed" || a.state.LastError == "" || a.cmd != nil ||
				session.active != nil || session.predecessor != host.transaction || !host.closed ||
				host.activation.lifetime.Err() == nil {
				return errors.New("dead native cover left Connected or retired a replacement source")
			}
			return nil
		}); err != nil {
			return err
		}
		result.Cover = "retired-after-reply-loss"
	}
	stop := httptest.NewRecorder()
	a.disconnect(stop, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil).WithContext(ctx))
	if stop.Code != http.StatusOK || strings.TrimSpace(stop.Body.String()) != `{"ok":true}` {
		return fmt.Errorf("installed public Disconnect failed its real handler: %d: %s", stop.Code, stop.Body.String())
	}
	if linuxHostTUNOffCase(scenario) {
		result.ProtectionOff, err = linuxHostTUNPublicProtectionOff(ctx, a, session, host, scenario)
		if err != nil {
			return err
		}
	}
	a.operationMu.Lock()
	locked = true
	if err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if session.active != nil || session.predecessor != nil || a.cmd != nil || a.state.Connected || a.state.Phase != "off" ||
			!host.closed || !host.released || host.source != nil || host.policy != nil || host.activation.lifetime.Err() == nil {
			return errors.New("public Disconnect retained its source, process, active state or On-connect protection")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
		return err
	}
	if _, err := os.Lstat(host.launch.directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("public Disconnect retained its original private workspace")
	}
	settled, err := linuxHostTUNJournal(ctx, journal, host.transaction)
	if err != nil || settled.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, result.SessionID) != nil {
		return errors.Join(err, errors.New("public Disconnect did not release the exact joined native source"))
	}
	result.Journal = &settled
	if err := a.guardDesktopOwnedNodeTransition(nil); err != nil {
		return errors.Join(err, errors.New("public Disconnect did not release its empty session for legacy paths"))
	}
	// Usage persistence is read from the actual private file, not inferred from
	// the public response or the in-memory increment alone.
	store, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "routers.json"), 64<<10)
	var persisted common.RouterProfileStore
	if err != nil || json.Unmarshal(store, &persisted) != nil || len(persisted.Profiles) != 1 ||
		persisted.SelectedID != path.launch.profileID || persisted.Profiles[0].ID != path.launch.profileID || persisted.Profiles[0].UseCount != 1 {
		return errors.Join(err, errors.New("public Connect did not persist its original node usage"))
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	result.Stage = "retired"
	return json.NewEncoder(os.Stdout).Encode(result)
}
