//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// These are actual lease/interface observations, not invented benchmark data.
// The installed-host driver separately requires the complete pinned bundle,
// selected DNS and Router proofs, original command join and TUN absence.
type linuxHostTUNMTUResult struct {
	OriginalMTU   int    `json:"original_mtu"`
	CandidateMTU  int    `json:"candidate_mtu"`
	FinalMTU      int    `json:"final_mtu"`
	InitialIndex  int    `json:"initial_index"`
	FinalIndex    int    `json:"final_index"`
	InitialReader uint64 `json:"initial_reader"`
	FinalReader   uint64 `json:"final_reader"`
	Outcome       string `json:"outcome"`
	StopHeld      bool   `json:"stop_held"`
}

// The native mailbox mutates its retained record while holding this same host
// gate. An HTTP response or a joined Stop request does not replace that lock.
func linuxHostTUNMTUCheck(ctx context.Context, host *desktopLinuxNodeHost, check func() error) error {
	if err := host.enter(ctx); err != nil {
		return err
	}
	defer func() { host.gate <- struct{}{} }()
	return check()
}

func linuxHostTUNMTUConsumer(ctx context.Context, a *app, host *desktopLinuxNodeHost, scenario string) (result linuxHostTUNMTUResult, failure error) {
	if scenario != "mtu-rollback" && scenario != "mtu-commit" && scenario != "mtu-stale-profile" && scenario != "mtu-stale-network" && scenario != "mtu-hold" && scenario != "mtu-retire-undrained" {
		return result, errors.New("installed MTU consumer has no captured scenario")
	}
	if err := host.Current(ctx); err != nil {
		return result, err
	}
	if _, duplicate := desktopNodeOwners.Load(a); duplicate {
		return result, errors.New("installed Linux MTU consumer created a second native process owner")
	}
	tracker := sessionTrackerFor(a)
	tracker.observe(tracker.capture())
	snapshot, err := captureMTURetestSnapshot(a)
	if err != nil {
		return result, err
	}
	lock := mtuRetestLockFor(a)
	lock.Lock()
	locked := true
	defer func() {
		if locked {
			lock.Unlock()
		}
	}()
	live, err := captureMTUConnectionSnapshot(a, snapshot)
	if err != nil || live.nodeRecord == nil || live.nodeRecord.Active || desktopLinuxNodeTUNCurrent(*live.nodeRecord) != nil {
		return result, errors.Join(err, errors.New("installed MTU consumer lost its original active native snapshot"))
	}
	// A same-name route/value cannot replace the exact reader captured above.
	for _, changed := range []string{"index", "value", "path"} {
		foreign := live
		copy := *live.nodeRecord
		foreign.nodeRecord = &copy
		switch changed {
		case "index":
			copy.Index++
		case "value":
			foreign.OriginalMTU++
		case "path":
			copy.Path = "foreign-original-reader"
		}
		rejected, err := captureMTULiveOwner(a, snapshot, foreign)
		retainedErr := linuxHostTUNMTUCheck(ctx, host, func() error {
			if host.mtu != nil {
				return errors.New("rejected MTU capture retained a native lease")
			}
			return nil
		})
		if err == nil || rejected != nil || retainedErr != nil {
			return result, errors.New("installed MTU capture accepted a substituted original reader")
		}
	}
	owner, err := captureMTULiveOwner(a, snapshot, live)
	if owner != nil {
		defer func() { failure = errors.Join(failure, owner.Close()) }()
	}
	if err != nil {
		return result, err
	}
	native, ok := owner.kernel.(*desktopLinuxNodeMTUOwner)
	if !ok {
		return result, errors.New("installed MTU bridge did not retain its original host and native begin lease")
	}
	if err := linuxHostTUNMTUCheck(ctx, host, func() error {
		if native.host != host || native != host.mtu || !native.native.record.Active || native.native.record.Reader != live.nodeRecord.Reader {
			return errors.New("installed MTU bridge did not retain its original host and native begin lease")
		}
		return nil
	}); err != nil {
		return result, err
	}
	result.OriginalMTU, result.InitialIndex, result.InitialReader = live.OriginalMTU, live.nodeRecord.Index, live.nodeRecord.Reader
	candidate := 1280
	if candidate == live.OriginalMTU {
		candidate = 1300
	}
	result.CandidateMTU = candidate
	code, raw, err := mtuCapabilityCall(ctx, owner, http.MethodPost, "", "Bearer "+owner.token, fmt.Sprintf(`{"action":"set","mtu":%d}`, candidate))
	var readback mtuOwnerReply
	if err != nil || code != http.StatusOK || json.Unmarshal(raw, &readback) != nil || readback.Owner != owner.token ||
		readback.MTU != candidate || readback.Interface != live.Interface || readback.Index < 1 || owner.ValidateMTU(candidate) != nil || host.Current(ctx) != nil {
		return result, errors.Join(err, errors.New("installed MTU HTTP bridge did not prove the actual new native TUN reader"))
	}
	if err := linuxHostTUNMTUCheck(ctx, host, func() error {
		if native.native.record.Reader <= result.InitialReader || desktopLinuxNodeTUNCurrent(native.native.record) != nil {
			return errors.New("installed MTU mutation fabricated a new reader or kernel readback")
		}
		return nil
	}); err != nil {
		return result, err
	}
	if scenario == "mtu-retire-undrained" {
		// An active real source/TUN cannot borrow a stopped label or a future
		// retirement. This refusal precedes the original graceful stop below.
		if err := linuxHostTUNMTUCheck(ctx, host, func() error {
			before := native.native.record
			if native.finishRetirementLocked(ctx) == nil || host.mtu != native || native.closed || native.native.record != before {
				return errors.New("installed MTU lease discharged before authenticated original source retirement")
			}
			return nil
		}); err != nil {
			return result, err
		}
		if err := requestDesktopLinuxNodeStop(ctx, host.process); err != nil {
			return result, err
		}
		// The child removes this exact owned readiness file on entering graph
		// cleanup, before it waits for the parent's original ACK. Absence here
		// only orders the test; it supplies no retirement/discharge authority.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			_, readErr := readDesktopRuntimeFile(host.launch, "node-ready.json", 16384)
			if errors.Is(readErr, os.ErrNotExist) {
				break
			}
			if readErr != nil {
				return result, readErr
			}
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-ticker.C:
			}
		}
		lock.Unlock()
		locked = false
		if err := a.stopModeWithIntent(false); err != nil {
			return result, err
		}
		var lastIndex int
		if err := linuxHostTUNMTUCheck(ctx, host, func() error {
			if host.mtu != nil || !native.closed || !native.native.runtimeRetired || native.restored || native.cleanup != (mtuKernelState{}) {
				return errors.New("installed MTU retirement omitted its exact original discharge or invented rollback")
			}
			lastIndex = native.native.record.Index
			return nil
		}); err != nil {
			return result, err
		}
		select {
		case <-host.process.joined:
		default:
			return result, errors.New("installed MTU discharge preceded original Cmd.Wait")
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			return result, err
		}
		for _, iface := range interfaces {
			if iface.Name == live.Interface || iface.Index == live.nodeRecord.Index || iface.Index == lastIndex {
				return result, errors.New("installed MTU retirement retained or replaced its original TUN")
			}
		}
		if err := owner.Close(); err != nil {
			return result, err
		}
		owner.mu.Lock()
		claimedMTU := owner.restored || owner.committed || !owner.closed
		owner.mu.Unlock()
		if _, retained := mtuLiveOwners.Load(a); retained || claimedMTU {
			return result, errors.New("installed MTU retirement retained its registry or invented a final measured value")
		}
		if err := native.session.enter(ctx); err != nil {
			return result, err
		}
		active := native.session.active
		native.session.gate <- struct{}{}
		a.mu.Lock()
		stopped := a.cmd == nil && !a.state.Connected && a.state.Phase == "off"
		a.mu.Unlock()
		if active != nil || !stopped {
			return result, errors.New("installed MTU fallback bypassed the original ordinary Stop completion")
		}
		result.Outcome = "retired-original"
		// Zero final fields describe no live TUN/readback, never a zero MTU.
		return result, nil
	}
	if scenario == "mtu-stale-profile" {
		a.mu.Lock()
		profile, found := a.profileByIDLocked(snapshot.Profile.ID)
		if !found || profile.AdGuardIPv4 != snapshot.Profile.AdGuardIPv4 {
			a.mu.Unlock()
			return result, errors.New("installed MTU profile replacement lost its captured original")
		}
		for index := range a.profiles.Profiles {
			if a.profiles.Profiles[index].ID == profile.ID {
				a.profiles.Profiles[index].AdGuardIPv4 = "192.168.50.134"
			}
		}
		a.mu.Unlock()
	} else if scenario == "mtu-stale-network" {
		if output, err := exec.CommandContext(ctx, "ip", "addr", "add", "192.168.210.5/32", "dev", "rvpn-test").CombinedOutput(); err != nil {
			return result, fmt.Errorf("installed MTU original namespace network change: %v: %s", err, output)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(cleanup, "ip", "addr", "del", "192.168.210.5/32", "dev", "rvpn-test").CombinedOutput(); err != nil {
				failure = errors.Join(failure, fmt.Errorf("installed MTU original namespace cleanup: %v: %s", err, output))
			}
		}()
	}
	if scenario == "mtu-stale-profile" || scenario == "mtu-stale-network" {
		if owner.Validate() == nil || owner.Commit() == nil {
			return result, errors.New("installed MTU consumer accepted a replaced profile/network for new adoption")
		}
		code, _, _ := mtuCapabilityCall(ctx, owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1290}`)
		if code == http.StatusOK {
			return result, errors.New("stale installed MTU owner mutated a replacement path")
		}
	}
	if scenario == "mtu-hold" {
		type held struct {
			release func()
			command *exec.Cmd
			err     error
		}
		done := make(chan held, 1)
		go func() {
			release, command, err := a.holdMTUForStop()
			done <- held{release, command, err}
		}()
		joined := false
		defer func() {
			if !joined {
				if locked {
					lock.Unlock()
					locked = false
				}
				outcome := <-done
				if outcome.release != nil {
					outcome.release()
				}
				failure = errors.Join(failure, outcome.err)
			}
		}()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for !mtuSuspended(a) {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-ticker.C:
			}
		}
		activeErr := linuxHostTUNMTUCheck(ctx, host, func() error {
			if !native.native.record.Active {
				return errors.New("held MTU lease is no longer active")
			}
			return nil
		})
		if host.Current(ctx) != nil || activeErr != nil {
			return result, errors.New("Stop retired the actual engine before its held MTU lease drained")
		}
		select {
		case <-host.process.joined:
			return result, errors.New("Stop joined the original engine before its held MTU rollback")
		case outcome := <-done:
			joined = true
			if outcome.release != nil {
				outcome.release()
			}
			return result, errors.Join(outcome.err, errors.New("Stop passed the original active MTU hold before release"))
		default:
		}
		lock.Unlock()
		locked = false
		outcome := <-done
		joined = true
		if outcome.release != nil {
			defer outcome.release()
		}
		if outcome.err != nil || outcome.release == nil || outcome.command != host.process.command {
			return result, errors.Join(outcome.err, errors.New("Stop changed its original runtime while draining the native lease"))
		}
		result.StopHeld = true
	} else if scenario == "mtu-commit" {
		if err := owner.Commit(); err != nil {
			return result, err
		}
	}
	if err := owner.Close(); err != nil {
		return result, err
	}
	if retained, exists := mtuLiveOwners.Load(a); exists || retained != nil {
		return result, errors.New("installed MTU cleanup did not discharge its exact retained lease")
	}
	var final desktopNodeMTURecord
	if err := linuxHostTUNMTUCheck(ctx, host, func() error {
		if host.mtu != nil || !native.closed {
			return errors.New("installed MTU cleanup did not discharge its exact retained lease")
		}
		var readErr error
		final, readErr = readDesktopNodeMTU(host.launch)
		if readErr != nil || final.Active || final.Path != live.nodeRecord.Path || final.Session != live.nodeRecord.Session ||
			final.Config != live.nodeRecord.Config || final.Reader <= result.InitialReader || desktopLinuxNodeTUNCurrent(final) != nil {
			return errors.Join(readErr, errors.New("installed MTU final readback belongs to another native path"))
		}
		return nil
	}); err != nil {
		return result, err
	}
	wanted, restored := result.OriginalMTU, true
	result.Outcome = "restored-original"
	if scenario == "mtu-commit" {
		wanted, restored, result.Outcome = candidate, false, "committed-candidate"
	}
	owner.mu.Lock()
	ownerRestored := owner.restored
	owner.mu.Unlock()
	if final.MTU != wanted || final.Restored != restored || ownerRestored != restored {
		return result, errors.New("installed MTU consumer lost the actual committed or rolled-back kernel value")
	}
	result.FinalMTU, result.FinalIndex, result.FinalReader = final.MTU, final.Index, final.Reader
	return result, nil
}
