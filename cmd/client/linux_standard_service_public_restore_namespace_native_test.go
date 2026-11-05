//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
)

const standardPublicShapePath = "/run/routervpn-standard-public-shape.json"

type standardPublicShape struct {
	Receipt                         string
	Preferred                       int
	NamespaceDevice, NamespaceInode uint64
}

// The fixture delays actual bytes/acknowledgements, never supplies a synthetic
// rate or winner. Only the original controller publishes its verified current
// receipt. Kernel index/name/MTU and namespace must still match at the peer.
func standardPublicShapeTransfer() error {
	until := time.Now().Add(500 * time.Millisecond)
	for {
		raw, err := os.ReadFile(standardPublicShapePath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var shape standardPublicShape
		if json.Unmarshal(raw, &shape) != nil || shape.Preferred != 1280 {
			return errors.New("invalid captured test transfer model")
		}
		receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(shape.Receipt)
		if err != nil {
			return err
		}
		namespace, err := os.Stat("/proc/self/ns/net")
		if err != nil {
			return err
		}
		identity, ok := namespace.Sys().(*syscall.Stat_t)
		if !ok || uint64(identity.Dev) != shape.NamespaceDevice || identity.Ino != shape.NamespaceInode {
			return errors.New("test transfer model changed namespace")
		}
		iface, err := net.InterfaceByIndex(int(receipt.Index))
		if err == nil && iface.Name == receipt.Name && iface.MTU == receipt.MTU {
			if receipt.MTU != shape.Preferred {
				// At most 250ms per complete payload, within the unchanged native
				// candidate budget. Peer teardown joins this bounded fixture delay.
				timer := time.NewTimer(250 * time.Millisecond)
				<-timer.C
			}
			return nil
		}
		if !time.Now().Before(until) {
			return errors.New("test transfer model lost exact current TUN")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func beginStandardPublicShaping(parent context.Context, launch *linuxStandardServiceLaunch) (func() error, error) {
	ctx, cancel := context.WithCancel(parent)
	pending := errors.New("test transfer model observation expired")
	publish := func() (failure error) {
		call, finish := context.WithTimeout(ctx, 250*time.Millisecond)
		defer finish()
		defer func() {
			if common.ObservationContextExpired(call, failure) {
				failure = pending
			}
		}()
		if err := desktopnetwork.LockContext(call, &launch.mu); err != nil {
			return err
		}
		// An admitted candidate temporarily has no completed receipt. Keep the
		// last published identity until its original transition has settled;
		// never manufacture a Ready receipt from this temporary absence.
		if epoch := launch.prepared.requestEpoch; epoch.mtuTransition != nil {
			failure := epoch.failure
			launch.mu.Unlock()
			if failure != nil {
				return failure
			}
			return pending
		}
		_, _, _, err := captureLinuxStandardServiceMTUReadbackLocked(call, launch)
		if err != nil {
			launch.mu.Unlock()
			return err
		}
		namespace, ok := launch.prepared.namespaceInfo.Sys().(*syscall.Stat_t)
		if !ok {
			launch.mu.Unlock()
			return errors.New("original test namespace missing")
		}
		shape := standardPublicShape{Receipt: launch.prepared.requestEpoch.mtuReceipt, Preferred: 1280, NamespaceDevice: uint64(namespace.Dev), NamespaceInode: namespace.Ino}
		launch.mu.Unlock()
		raw, err := json.Marshal(shape)
		if err != nil {
			return err
		}
		if err = os.WriteFile(standardPublicShapePath+".pending", raw, 0600); err != nil {
			return err
		}
		return os.Rename(standardPublicShapePath+".pending", standardPublicShapePath)
	}
	if err := publish(); err != nil {
		cancel()
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		timer := time.NewTicker(10 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-timer.C:
				if err := publish(); err != nil && err != pending {
					done <- err
					return
				}
			}
		}
	}()
	return func() error {
		cancel()
		err := <-done
		_ = os.Remove(standardPublicShapePath)
		_ = os.Remove(standardPublicShapePath + ".pending")
		return err
	}, nil
}

type standardPublicChild struct {
	fd    *os.File
	pid   int
	start uint64
}

func (p *standardPublicChild) exited() (bool, error) { return legacyExitPIDFDState(p.fd) }

// This pidfd is read-only evidence for cancellation timing. It grants no Start,
// Stop or adoption authority. Parentage, exact retained capture argv, and start
// identity bracket pidfd opening; ambiguous or changed children are refused.
func captureStandardPublicChild(ctx context.Context, launch *linuxStandardServiceLaunch) (result *standardPublicChild, failure error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, errors.New("native fixture requires proved pidfd ABI")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.mu); err != nil {
		return nil, err
	}
	defer launch.mu.Unlock()
	if err := launch.peer.Current(ctx); err != nil {
		return nil, err
	}
	capture := standardengine.SHA256(launch.prepared.requestEpoch.startup.Capture)
	directories, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var found *standardPublicChild
	defer func() {
		if failure != nil && found != nil {
			found.fd.Close()
		}
	}()
	for _, entry := range directories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		path := filepath.Join("/proc", entry.Name())
		raw, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			continue
		}
		before, err := linuxprocess.ParseStat(raw)
		if err != nil || before.ParentID != launch.peer.record.ProcProcessID {
			continue
		}
		args, err := os.ReadFile(filepath.Join(path, "cmdline"))
		if err != nil {
			continue
		}
		parts := bytes.Split(bytes.TrimSuffix(args, []byte{0}), []byte{0})
		if len(parts) != 4 || filepath.Base(string(parts[0])) != nativeBinaryName() || string(parts[1]) != "routervpn-standard" || string(parts[2]) != "--capture-sha256" || string(parts[3]) != capture {
			continue
		}
		descriptor, _, errno := syscall.Syscall(434, uintptr(pid), 0, 0)
		if errno != 0 {
			return nil, os.NewSyscallError("test pidfd_open", errno)
		}
		fd := os.NewFile(descriptor, "read-only-original-test-child")
		afterRaw, err := os.ReadFile(filepath.Join(path, "stat"))
		after, parseErr := linuxprocess.ParseStat(afterRaw)
		afterArgs, argsErr := os.ReadFile(filepath.Join(path, "cmdline"))
		if err != nil || parseErr != nil || argsErr != nil || before.ProcessID != after.ProcessID || before.ParentID != after.ParentID || before.Start != after.Start || !bytes.Equal(args, afterArgs) {
			fd.Close()
			return nil, errors.New("test child changed around original pidfd")
		}
		witness := &standardPublicChild{fd: fd, pid: pid, start: before.Start}
		ended, err := witness.exited()
		if err != nil || ended {
			fd.Close()
			return nil, errors.Join(err, errors.New("test child already retired"))
		}
		if found != nil {
			fd.Close()
			return nil, errors.New("ambiguous original native child")
		}
		found = witness
	}
	if found == nil {
		return nil, errors.New("original captured native child not found")
	}
	return found, nil
}

func prepareStandardPublicRestoreProfiles(a *app) error {
	a.mu.Lock()
	spare := common.CloneRouterProfile(a.profiles.Profiles[0])
	spare.ID = "spare-policy"
	spare.Name = "Unselected private policy"
	spare.MTUPolicy = "fixed"
	spare.HomeLANCIDRs = []string{"192.168.200.0/24"}
	a.profiles.Profiles = append(a.profiles.Profiles, spare)
	store := cloneRouterProfileStore(a.profiles)
	a.mu.Unlock()
	return a.speedLabWriteStore(store)
}

func linuxStandardServiceNativePublicRestoreFixture(a *app, original *linuxStandardServiceLaunch) (*linuxStandardServiceLaunch, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	mux := http.NewServeMux()
	registerMTURetestRoute(mux, a)
	for {
		if raw, found := linuxStandardServiceMTUUIs.Load(original); found {
			ui := raw.(*linuxStandardServiceMTUUI)
			if err := desktopnetwork.LockContext(ctx, &ui.mu); err != nil {
				return nil, err
			}
			ready, busy, attempted := ui.completed, ui.running || ui.autoWaiting, ui.autoAttempted
			ui.mu.Unlock()
			if ready && !busy {
				break
			}
			if attempted && !busy {
				return nil, errors.New("original Auto failed before restore fixture")
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	finishShape, err := beginStandardPublicShaping(ctx, original)
	if err != nil {
		return nil, err
	}
	live, profile, _, err := captureLinuxStandardServiceMTUReadback(ctx, original)
	if err != nil {
		finishShape()
		return nil, err
	}
	retest := standardPublicCall(ctx, mux, "/api/mtu/retest", mtuViewRequest{Request: strings.Repeat("c", 32), Session: live.Session, Profile: profile.ID})
	shapeErr := finishShape()
	var result struct {
		OK     bool             `json:"ok"`
		MTU    int              `json:"effective_mtu"`
		Result mobilemtu.Status `json:"result"`
	}
	if shapeErr != nil || retest.Code != http.StatusOK || json.Unmarshal(retest.Body.Bytes(), &result) != nil || !result.OK || !result.Result.Measured || result.MTU != 1280 {
		return nil, fmt.Errorf("actual nondefault Auto winner missing: %v %d %s", shapeErr, retest.Code, retest.Body.String())
	}
	before, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, original)
	if err != nil || before.MTU != 1280 {
		return nil, errors.Join(err, errors.New("nondefault winner lacks actual TUN readback"))
	}
	child, err := captureStandardPublicChild(ctx, original)
	if err != nil {
		return nil, err
	}
	defer child.fd.Close()
	// Preserve a selected browsing profile distinct from the active policy. The
	// transaction must temporarily select its captured policy, then restore both.
	if err = desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	a.profiles.SelectedID = "spare-policy"
	profiles := cloneRouterProfileStore(a.profiles)
	prior := a.state
	a.mu.Unlock()
	if err = a.speedLabWriteStore(profiles); err != nil {
		return nil, err
	}
	tokens := map[string]string{}
	for _, p := range profiles.Profiles {
		tokens[p.ID] = publicProfileToken(p)
	}
	request, stopRequest := context.WithCancel(ctx)
	defer stopRequest()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- standardPublicCall(request, mux, "/api/speed-lab/run", speedLabRequest{Scope: "temporary", Topology: "system-direct", DurationMode: "custom", MinSeconds: 1, MaxSeconds: 1, ExpectedSelectedNodeID: profiles.SelectedID, ExpectedProfileTokens: tokens})
	}()
	for {
		if err = desktopnetwork.LockContext(ctx, &original.mu); err != nil {
			stopRequest()
			<-done
			return nil, err
		}
		joined := original.joined
		original.mu.Unlock()
		exited, exitErr := child.exited()
		if exitErr != nil {
			stopRequest()
			<-done
			return nil, exitErr
		}
		if joined && exited {
			break
		}
		select {
		case response := <-done:
			return nil, fmt.Errorf("temporary test ended before original child joined: %d %s", response.Code, response.Body.String())
		case <-ctx.Done():
			stopRequest()
			<-done
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	stopRequest() // HTTP test cancellation; never the separate reconnect intent.
	response := <-done
	if response.Code != http.StatusConflict || !strings.Contains(strings.ToLower(response.Body.String()), "cancel") {
		return nil, fmt.Errorf("cancelled temporary test did not report its own cancellation: %d %s", response.Code, response.Body.String())
	}
	fresh, found, err := linuxStandardMTULaunch(a)
	if err != nil || !found || fresh == original || fresh.request.Session == original.request.Session || fresh.request.NetworkID != original.request.NetworkID || fresh.request.ProfileID != original.request.ProfileID || !fresh.dnsProved || fresh.speedLabPolicy == nil || fresh.speedLabPolicy.profileDigest != original.speedLabPolicy.profileDigest || fresh.speedLabPolicy.exitRaw != original.speedLabPolicy.exitRaw {
		return nil, errors.Join(err, errors.New("temporary cancellation did not restore fresh original service source"))
	}
	restored, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, fresh)
	if err != nil || restored.MTU != 1280 || restored.Session == before.Session {
		return nil, errors.Join(err, errors.New("temporary cancellation lost proved nondefault MTU"))
	}
	ready, err := standardengine.DecodeReady(fresh.prepared.requestEpoch.startup.Ready, standardengine.SHA256(fresh.prepared.requestEpoch.startup.Capture))
	if err != nil {
		return nil, err
	}
	startup, err := desktopnetwork.ParseDesktopNetworkReceipt(ready.NetworkReceipt)
	if err != nil || startup.MTU == 1280 {
		return nil, errors.Join(err, errors.New("fresh startup did not independently require MTU restoration"))
	}
	replacement, err := captureStandardPublicChild(ctx, fresh)
	if err != nil {
		return nil, err
	}
	defer replacement.fd.Close()
	if replacement.pid == child.pid && replacement.start == child.start {
		return nil, errors.New("restore reused the retired original child")
	}
	if fresh.prepared.requestEpoch.observer == original.prepared.requestEpoch.observer {
		return nil, errors.New("fresh connection borrowed retired original observer")
	}
	if err = desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	after, store := a.state, cloneRouterProfileStore(a.profiles)
	a.mu.Unlock()
	if !reflect.DeepEqual(store, profiles) || !after.Connected || after.Phase != "connected" || after.RouterID != prior.RouterID || after.Mode != prior.Mode || after.LogicalMode != prior.LogicalMode || after.RuntimeMode != prior.RuntimeMode || after.Base != prior.Base || after.DAITA != prior.DAITA || after.Jumbo != prior.Jumbo || after.Socks != prior.Socks {
		return nil, errors.New("restore changed complete profiles, selection or logical connection")
	}
	disk, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
	var persisted common.RouterProfileStore
	if err != nil || json.Unmarshal(disk, &persisted) != nil || !reflect.DeepEqual(persisted, profiles) {
		return nil, errors.Join(err, errors.New("restore did not persist complete original profiles"))
	}
	identity, _, _, err := captureStandardServiceSpeedLabCallerContext(ctx, a)
	if err != nil {
		return nil, err
	}
	if err = verifySpeedLabPath(ctx, a, identity); err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stdout, "standard-service-public-cancelled-speedlab-restored")
	return fresh, nil
}
