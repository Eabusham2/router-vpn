package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"time"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
)

type desktopImportedDNSRequest struct {
	Operation  string `json:"operation,omitempty"`
	Schema     int    `json:"schema"`
	Session    string `json:"session_id"`
	Config     string `json:"config_sha256"`
	Path       string `json:"path_id"`
	Reader     uint64 `json:"reader"`
	MTU        int    `json:"mtu"`
	Request    string `json:"request_id"`
	Generation uint64 `json:"generation"`
	Deadline   int64  `json:"deadline_at"`
}

type desktopImportedDNSResult struct {
	OpenVPN *nativeopenvpn.PacketObservation `json:"openvpn,omitempty"`
	desktopImportedDNSRequest
	Status       string  `json:"status"`
	Interface    string  `json:"interface"`
	Index        int     `json:"index"`
	ProvedAt     int64   `json:"proved_at"`
	Milliseconds float64 `json:"milliseconds"`
}

func (a *app) proveImportedNativeDNS(parent context.Context, selection multihopSelection, command *exec.Cmd) (float64, error) {
	if selection.Native == nil || !selection.Native.imported {
		return 0, errors.New("selected final DNS has no original imported graph")
	}
	graph, ok := getActiveMultihopGraph(a)
	owner, err := capturedNativeMultihopRuntimeContext(parent, a, command, graph)
	if !ok || err != nil || owner.selection.Native != selection.Native || !owner.launch.importedEntry {
		return 0, errors.New("selected final DNS has no retained original process")
	}
	current := func(ctx context.Context) error {
		if ctx.Err() != nil || !a.nativeMultihopProofOwnerCurrentContext(ctx, selection, command) || desktopNodeProcessExited(owner.launch) {
			return errors.New("selected final DNS lost its current source or process")
		}
		actual, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
		if err != nil || actual != owner {
			return errors.New("selected final DNS lost its original network generation")
		}
		selected, err := expectedDNSSelection(selection.Exit)
		if err != nil {
			return err
		}
		raw, err := readDesktopRuntimeFileContext(ctx, owner.launch, "sing-box.json", 4<<20)
		if err != nil {
			return err
		}
		return verifySingBoxDNSConfigBytes(raw, selected)
	}
	if err := a.observeImportedOpenVPN(parent, selection, command); err != nil {
		return 0, err
	}
	elapsed, err := exchangeDesktopImportedDNS(parent, owner.launch, current)
	if err != nil {
		return 0, err
	}
	if err := a.observeImportedOpenVPN(parent, selection, command); err != nil {
		return 0, err
	}
	return elapsed, parent.Err()
}

// All network work is done by the same retained Box. This parent exchanges
// only private files and can never substitute a successful OS resolver lookup.
func exchangeDesktopImportedDNS(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error) (float64, error) {
	return exchangeDesktopImportedDNSWithPublisher(parent, launch, current, publishDesktopImportedDNSMessage)
}

func exchangeDesktopImportedDNSWithPublisher(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error,
	publish func(context.Context, *desktopNodeLaunch, string, []byte) error) (float64, error) {
	result, err := exchangeDesktopImportedNativeWithPublisher(parent, launch, current, "", publish)
	if err != nil {
		return 0, err
	}
	return result.Milliseconds, nil
}

func exchangeDesktopImportedNativeWithPublisher(parent context.Context, launch *desktopNodeLaunch, current func(context.Context) error, operation string,
	publish func(context.Context, *desktopNodeLaunch, string, []byte) error) (*desktopImportedDNSResult, error) {
	if parent == nil || parent.Err() != nil || launch == nil || launch.directoryRoot == nil || !launch.importedEntry || current == nil || publish == nil || operation != "" && operation != "openvpn-observe" {
		return nil, errors.New("imported DNS requires its live original caller")
	}
	// Keep room for the native heartbeat which follows the bounded query.
	ctx, cancel := context.WithTimeout(parent, 7*time.Second)
	defer cancel()
	if err := mobilemtu.LockContext(ctx, &launch.importedDNSMu); err != nil {
		return nil, err
	}
	defer launch.importedDNSMu.Unlock()
	source, err := launch.directoryRoot.Lstat("sing-box.json")
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context) error {
		if err := current(ctx); err != nil {
			return err
		}
		body, err := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", 4<<20)
		actual, statErr := launch.directoryRoot.Lstat("sing-box.json")
		digest := sha256.Sum256(body)
		if err != nil || statErr != nil || !os.SameFile(source, actual) || hex.EncodeToString(digest[:]) != launch.configSHA256 {
			return errors.New("imported DNS graph was replaced")
		}
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var live desktopNodeMTURecord
	for {
		if err := check(ctx); err != nil {
			return nil, err
		}
		live, err = readDesktopNodeMTUContext(ctx, launch)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("imported DNS could not capture the native TUN reader")
		case <-ticker.C:
		}
	}
	if live.Active || live.Failure != "" {
		return nil, errors.New("imported DNS cannot borrow an active or failed MTU transaction")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	if launch.importedDNSGeneration == ^uint64(0) {
		return nil, errors.New("imported DNS request generation exhausted")
	}
	deadline, _ := ctx.Deadline()
	if queryLimit := time.Now().Add(5 * time.Second); queryLimit.Before(deadline) {
		deadline = queryLimit
	}
	request := desktopImportedDNSRequest{Operation: operation, Schema: 1, Session: live.Session, Config: live.Config, Path: live.Path,
		Reader: live.Reader, MTU: live.MTU, Request: nonce, Generation: launch.importedDNSGeneration + 1, Deadline: deadline.UnixMilli()}
	raw, _ := json.Marshal(request)
	// The native reader can finish immediately after Link, even while this
	// publisher is descheduled. Bound the receipt before making it visible.
	started := time.Now().UnixMilli()
	if err := publish(ctx, launch, "node-dns-request.json", raw); err != nil {
		return nil, err
	}
	launch.importedDNSGeneration = request.Generation
	readResult := func(ctx context.Context) (*desktopImportedDNSResult, error) {
		body, err := readDesktopRuntimeFileContext(ctx, launch, "node-dns-result.json", 4096)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var result desktopImportedDNSResult
		if decodeRelayControlJSON(body, &result) != nil {
			return nil, errors.New("imported DNS result is malformed")
		}
		if result.Request != request.Request {
			if result.Request == launch.importedDNSLast {
				return nil, nil
			}
			return nil, errors.New("imported DNS result belongs to another request")
		}
		// A same-tick observation or unsuccessful completion may join its
		// exact request. Only a passing selected-DNS result supplies an RTT.
		if result.desktopImportedDNSRequest != request || operation == "" && result.OpenVPN != nil || operation == "openvpn-observe" && result.Status == "passed" && (result.OpenVPN == nil || result.OpenVPN.Validate() != nil) || result.Interface != live.Interface || result.Index != live.Index ||
			result.ProvedAt < started-1 || result.ProvedAt > time.Now().Add(time.Second).UnixMilli() ||
			math.IsNaN(result.Milliseconds) || math.IsInf(result.Milliseconds, 0) || result.Milliseconds < 0 || result.Milliseconds > 7000 ||
			operation == "" && result.Status == "passed" && result.Milliseconds == 0 ||
			result.Status != "passed" && result.Status != "failed" && result.Status != "cancelled" {
			return nil, errors.New("imported DNS result changed its original request or TUN owner")
		}
		if _, err := readDesktopRuntimeFileContext(ctx, launch, "node-dns-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return nil, nil // A result is not joined until the exact request has been consumed.
		}
		return &result, nil
	}
	drain := func(cause error) (*desktopImportedDNSResult, error) {
		joined, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		// If the original result already joined, do not leave a late cancel for
		// the next query. Otherwise O_EXCL preserves the original cancellation.
		if result, err := readResult(joined); err == nil && result != nil {
			launch.importedDNSLast = request.Request
			return nil, cause
		}
		if err := publish(joined, launch, "node-dns-cancel.json", raw); err != nil {
			return nil, errors.Join(cause, err)
		}
		for {
			if result, err := readResult(joined); err != nil {
				// A malformed or replaced result is never completion evidence.
				// Keep the old request owned until its worker drains or Stop joins.
			} else if result != nil {
				launch.importedDNSLast = request.Request
				return nil, errors.Join(cause, retireDesktopImportedDNSCancel(launch, raw))
			}
			if closed, _ := readDesktopNodeStopped(launch); closed {
				return nil, cause
			}
			select {
			case <-joined.Done():
				return nil, errors.Join(cause, errors.New("imported DNS native query did not acknowledge drain"))
			case <-ticker.C:
			}
		}
	}
	for {
		if err := check(ctx); err != nil {
			return drain(err)
		}
		result, err := readResult(ctx)
		if err != nil {
			return drain(err)
		}
		if result != nil {
			launch.importedDNSLast = request.Request
			if result.Status != "passed" || result.ProvedAt > request.Deadline {
				return nil, errors.New("selected final native DNS query did not pass")
			}
			// The native loop publishes its next heartbeat after the joined
			// DNS result. A long query can age the prior heartbeat; wait for the
			// same exact reader instead of treating that ordering as a failure.
			var after desktopNodeMTURecord
			for {
				after, err = readDesktopImportedDNSHeartbeatContext(ctx, launch, live)
				if err == nil {
					break
				}
				if !errors.Is(err, errImportedDNSHeartbeatPending) {
					return nil, err
				}
				if err := check(ctx); err != nil {
					return nil, err
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-ticker.C:
				}
			}
			if after.Path != live.Path || after.Reader != live.Reader || after.Interface != live.Interface || after.Index != live.Index || after.MTU != live.MTU || after.Active || after.Failure != "" {
				return nil, errors.New("selected DNS query completed for a replaced TUN reader")
			}
			if err := check(ctx); err != nil {
				return nil, err
			}
			return result, nil
		}
		select {
		case <-ctx.Done():
			return drain(ctx.Err())
		case <-ticker.C:
		}
	}
}

var errImportedDNSHeartbeatPending = errors.New("original DNS TUN heartbeat has not refreshed")

func readDesktopImportedDNSHeartbeat(launch *desktopNodeLaunch, expected desktopNodeMTURecord) (desktopNodeMTURecord, error) {
	return readDesktopImportedDNSHeartbeatContext(context.Background(), launch, expected)
}

func readDesktopImportedDNSHeartbeatContext(ctx context.Context, launch *desktopNodeLaunch, expected desktopNodeMTURecord) (desktopNodeMTURecord, error) {
	var record desktopNodeMTURecord
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-mtu-status.json", desktopNodeMTURecordLimit)
	if err != nil || decodeRelayControlJSON(raw, &record) != nil {
		return record, errors.New("selected DNS TUN heartbeat was removed or malformed")
	}
	if record.Schema != 1 || record.Session != expected.Session || record.Config != expected.Config || record.Path != expected.Path ||
		record.Reader != expected.Reader || record.Interface != expected.Interface || record.Index != expected.Index || record.MTU != expected.MTU || record.Active || record.Failure != "" {
		return record, errors.New("selected DNS TUN reader or MTU transaction changed")
	}
	if record.Heartbeat < time.Now().Add(-2*time.Second).UnixMilli() {
		return record, errImportedDNSHeartbeatPending
	}
	return readDesktopNodeMTUContext(ctx, launch)
}

func publishDesktopImportedDNSMessage(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte) error {
	return publishDesktopImportedDNSWithWriter(ctx, launch, name, raw, func(file *os.File, body []byte) error {
		_, err := file.Write(body)
		return err
	})
}

// Complete and sync a private inode before making its public mailbox name
// visible. Link is atomic and refuses an existing destination on all desktop
// platforms; Rename could overwrite a replacement owner's request.
func publishDesktopImportedDNSWithWriter(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte, write func(*os.File, []byte) error) error {
	if launch == nil || launch.directoryRoot == nil || (name != "node-dns-request.json" && name != "node-dns-cancel.json") || len(raw) == 0 || len(raw) > 4096 || write == nil {
		return errors.New("invalid imported DNS message")
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	temporary := "." + name + ".pending"
	file, err := launch.directoryRoot.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	defer func() {
		_ = file.Close()
		if actual, err := launch.directoryRoot.Lstat(temporary); err == nil && info != nil && os.SameFile(info, actual) {
			_ = launch.directoryRoot.Remove(temporary)
		}
	}()
	if statErr != nil {
		return statErr
	}
	if err := write(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	actual, err := launch.directoryRoot.Lstat(temporary)
	if err != nil || !os.SameFile(info, actual) || actual.Size() != int64(len(raw)) {
		return errors.New("imported DNS private message changed before publication")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	// After Link the native consumer may immediately consume the public name.
	// The caller owns cancellation/drain even if its context ends right now.
	return launch.directoryRoot.Link(temporary, name)
}

// Cancellation can race an already completed native query. Remove only this
// exact caller's late cancel after its result/request has joined.
func retireDesktopImportedDNSCancel(launch *desktopNodeLaunch, expected []byte) error {
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	before, err := launch.directoryRoot.Lstat("node-dns-cancel.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	actual, readErr := readDesktopRuntimeSnapshot(launch.directoryRoot, "node-dns-cancel.json", 4096)
	after, statErr := launch.directoryRoot.Lstat("node-dns-cancel.json")
	if err != nil || readErr != nil || statErr != nil || !os.SameFile(before, after) || string(actual) != string(expected) {
		return errors.New("imported DNS cancellation file changed before drain")
	}
	return launch.directoryRoot.Remove("node-dns-cancel.json")
}

func proveDesktopImportedDNSObservation(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	if a == nil {
		return result, false
	}
	raw, exists := desktopNodeOwners.Load(a)
	launch, ok := raw.(*desktopNodeLaunch)
	graph, found := getActiveMultihopGraph(a)
	imported := ok && launch != nil && launch.importedEntry || found && graph.ImportedEntry
	if retained, present := nativeMultihopOwners.Load(a); present {
		if owner, valid := retained.(*nativeMultihopRuntime); valid && owner != nil && owner.selection.Native != nil && owner.selection.Native.imported {
			imported = true
		}
	}
	if registered, present := activeDNSRuntimeIdentities.Load(a); present {
		if identity, valid := registered.(activeDNSRuntimeIdentity); valid && identity.ImportedEntry {
			imported = true
		}
	}
	if !imported && observed.Mode == "multihop" && observed.Profile.MultihopEnabled {
		a.mu.Lock()
		entry, present := a.profileByIDLocked(observed.Profile.MultihopEntryID)
		imported = present && entry.NodeKind == "external"
		a.mu.Unlock()
	}
	if !imported {
		return result, false
	}
	if !exists || !ok || launch == nil || !launch.importedEntry {
		result.Reason = "imported DNS lost its original retained process; an OS lookup cannot replace it"
		return result, true
	}
	owner, err := capturedNativeMultihopRuntime(a, launch.command, graph)
	if !found || err != nil || !observed.Connected || observed.Phase != "connected" || observed.RouterID != launch.profileID || runtimeID != launch.mode ||
		mtuProfileSnapshotToken(observed.Profile) != mtuProfileSnapshotToken(owner.selection.Exit) {
		result.Reason = "selected DNS observation lost the original imported final"
		return result, true
	}
	result.LatencyMs, err = a.proveImportedNativeDNS(ctx, owner.selection, launch.command)
	if err != nil {
		result.Reason = err.Error()
		return result, true
	}
	result.Status, result.Reason = "passed", "a fresh uncached query through the original retained native DNS router proved the captured final resolver"
	return result, true
}
