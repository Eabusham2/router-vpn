//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type linuxHostTUNRestoreResult struct {
	PreviousSession string `json:"previous_session"`
	SourceSHA256    string `json:"source_sha256"`
	RestoredMTU     int    `json:"restored_mtu"`
	FreshSession    string `json:"fresh_session"`
	Execution       string `json:"execution"`
	Cleared         bool   `json:"cleared"`
}

func linuxHostTUNRestoreCheck(ctx context.Context, session *desktopLinuxNodeSession, host *desktopLinuxNodeHost, check func() error) error {
	if err := session.enter(ctx); err != nil {
		return err
	}
	defer func() { session.gate <- struct{}{} }()
	if err := host.enter(ctx); err != nil {
		return err
	}
	defer func() { host.gate <- struct{}{} }()
	return check()
}

// This enters the real Speed Lab temporary-owner and restoration paths. The
// completed installed bundle, native process, TUN, DNS, private Router proof
// and journal are not substituted by test callbacks. The caller has finished
// the first Connect request and no longer holds operationMu.
func linuxHostTUNSealedRestore(ctx context.Context, a *app, session *desktopLinuxNodeSession,
	previous *desktopLinuxNodeHost) (fresh *desktopLinuxNodeHost, result linuxHostTUNRestoreResult, failure error) {
	if session == nil || session.active != previous || previous == nil || previous.ready == nil ||
		previous.policy == nil || previous.Current(ctx) != nil {
		return nil, result, errors.New("installed restoration lost its original active retained session")
	}
	// Commit a genuinely observed Auto MTU that differs from both configured
	// 1280 and historical 9000. Restoration must carry this actual value.
	a.operationMu.Lock()
	measurement, err := linuxHostTUNMTUConsumer(ctx, a, previous, "mtu-commit")
	a.operationMu.Unlock()
	if err != nil || measurement.FinalMTU != 1300 || measurement.Outcome != "committed-candidate" {
		return nil, result, errors.Join(err, errors.New("installed restoration lost its committed original live MTU"))
	}
	tracker := sessionTrackerFor(a)
	tracker.observe(tracker.capture())
	_, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		return nil, result, err
	}
	defer finish()
	saved := snapshot.Plan.linux
	if saved == nil || saved.session != session || saved.journal != session.journal || saved.parent != session.parent ||
		saved.mtu != measurement.FinalMTU || snapshot.Plan.request.Mode != previous.launch.mode || snapshot.Plan.request.Execution != "local" {
		return nil, result, errors.New("installed Speed Lab did not freeze its original execution and observed MTU")
	}
	sealed := append([]byte(nil), saved.source...)
	defer clear(sealed)
	copyToClear := saved.source
	result.PreviousSession, result.SourceSHA256 = previous.selection.SessionID, previous.selection.SourceSHA256
	result.RestoredMTU, result.Execution = saved.mtu, snapshot.Plan.request.Execution
	oldWorkspace, oldJournal := previous.launch.directory, session.journal
	// Today's generated graph is no longer usable. Successful restoration must
	// still reconstruct the independently retained exact previously proved one.
	asset := "sing-box.json"
	if saved.mode == "wg" {
		asset = "wg.conf"
	}
	generated := filepath.Join(linuxOwnedControllerRoot, "generated", snapshot.Plan.profile.ID, saved.mode, asset)
	if err := os.WriteFile(generated, []byte("not the captured private graph\n"), 0600); err != nil {
		return nil, result, err
	}
	if saved.mode == "hysteria2" {
		// The restored TLS trust must come from the sealed original source,
		// including its certificate, rather than today's generated files.
		if err := os.WriteFile(filepath.Join(filepath.Dir(generated), "cert.pem"), []byte("not the captured private CA\n"), 0600); err != nil {
			return nil, result, err
		}
	}
	if err := a.speedLabSuspendPrevious(snapshot, false); err != nil {
		return nil, result, err
	}
	if session.active != nil || previous.activation.lifetime.Err() == nil || a.cmd != nil || a.state.Connected ||
		len(previous.source) != 0 || previous.policy != nil {
		return nil, result, errors.New("installed temporary test did not join and clear only its original host")
	}
	if _, err := os.Lstat(oldWorkspace); !errors.Is(err, os.ErrNotExist) {
		return nil, result, errors.New("installed temporary test retained the previous private workspace")
	}
	// A cancelled measurement may restore through the still-current owning
	// intent. It must not reuse the cancelled test context as native authority.
	snapshot.Owner.cancelTest()
	if err := a.speedLabRestoreTemporary(snapshot); err != nil {
		return nil, result, err
	}
	fresh = saved.restored
	defer func() {
		if failure != nil && fresh != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			failure = errors.Join(failure, retireDesktopLinuxNodeRestore(cleanup, session, fresh))
		}
	}()
	if err := currentDesktopLinuxRestoredHost(ctx, a, session, oldJournal, fresh); err != nil {
		return fresh, result, err
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, fresh, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if fresh == previous || fresh.ready == nil || fresh.policy == nil || fresh.process == previous.process ||
			fresh.activation == nil || fresh.activation == previous.activation || fresh.proof == nil || fresh.proof == previous.proof ||
			fresh.selection.SessionID == result.PreviousSession || fresh.selection.SourceSHA256 != result.SourceSHA256 ||
			fresh.ready.SessionID != fresh.selection.SessionID || fresh.ready.MTU != 1300 || fresh.policy.Metadata().RestoredMTU != 1300 ||
			!bytes.Equal(fresh.source, sealed) || session.active != fresh || session.journal != oldJournal ||
			!reflect.DeepEqual(a.profiles, snapshot.Profiles) || a.cmd != fresh.launch.command || !a.state.Connected {
			return errors.New("installed restoration reused old authority or replaced the frozen source, live MTU or private profile")
		}
		if _, duplicate := desktopNodeOwners.Load(a); duplicate {
			return errors.New("installed restoration installed a competing legacy owner")
		}
		result.FreshSession = fresh.selection.SessionID
		return nil
	}); err != nil {
		return fresh, result, err
	}
	finish()
	if !saved.cleared || saved.source != nil || !bytes.Equal(copyToClear, make([]byte, len(copyToClear))) ||
		a.restartCapturedDesktopLinuxNode(snapshot.Plan, "speed-lab:restore") == nil {
		return fresh, result, errors.New("finished installed restoration retained the copied secret or allowed replay")
	}
	if err := currentDesktopLinuxRestoredHost(ctx, a, session, oldJournal, fresh); err != nil {
		return fresh, result, err
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, fresh, func() error {
		if !bytes.Equal(fresh.source, sealed) || fresh.activation == nil || fresh.activation.lifetime.Err() != nil {
			return errors.New("finished installed restoration erased the new source or active lifetime")
		}
		return nil
	}); err != nil {
		return fresh, result, err
	}
	result.Cleared = true
	return fresh, result, nil
}
