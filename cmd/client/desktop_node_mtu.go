package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
)

const desktopNodeMTURecordLimit = 32 << 10

type desktopNodeMTURecord struct {
	OpenVPN        nativeopenvpn.PacketObservation `json:"openvpn,omitzero"`
	NetworkReceipt string                          `json:"network_receipt,omitempty"`
	Schema         int                             `json:"schema"`
	Session        string                          `json:"session_id"`
	Config         string                          `json:"config_sha256"`
	Path           string                          `json:"path_id"`
	Generation     uint64                          `json:"generation"`
	Request        string                          `json:"request_id"`
	Lease          string                          `json:"lease_id"`
	Active         bool                            `json:"active"`
	Restored       bool                            `json:"restored"`
	Expired        bool                            `json:"expired,omitempty"`
	Reader         uint64                          `json:"reader"`
	Interface      string                          `json:"interface"`
	Index          int                             `json:"index"`
	MTU            int                             `json:"mtu"`
	Heartbeat      int64                           `json:"heartbeat_at"`
	Failure        string                          `json:"failure,omitempty"`
}
type desktopNodeMTUCommand struct {
	Schema           int    `json:"schema"`
	Session          string `json:"session_id"`
	Config           string `json:"config_sha256"`
	Path             string `json:"path_id"`
	Generation       uint64 `json:"generation"`
	Request          string `json:"request_id"`
	Lease            string `json:"lease_id"`
	Action           string `json:"action"`
	Reader           uint64 `json:"reader"`
	MTU              int    `json:"expected_mtu"`
	Value            int    `json:"value,omitempty"`
	RevertToken      string `json:"revert_token,omitempty"`
	CommitRequest    string `json:"commit_request,omitempty"`
	CommitGeneration uint64 `json:"commit_generation,omitempty"`
}
type desktopNodeMTUOwner struct {
	mu                sync.Mutex
	launch            *desktopNodeLaunch
	record            desktopNodeMTURecord
	family            int
	originalMTU       int
	lease             string
	pending           *desktopNodeMTUCommand
	unconfirmedCommit *desktopNodeMTUCommand
	closed, committed bool
	runtimeRetired    bool
	// Installed once by the original ordered Darwin host before exposing this
	// lease. Its caller already holds host.gate, then this owner's mu. The
	// verifier must observe the exact native proof and kernel successor without
	// reacquiring the host gate or discovering a replacement owner.
	verifyReaderChange func(context.Context, desktopNodeMTURecord, desktopNodeMTURecord) error
}

var errDesktopNodeMTUExpired = errors.New("captured native MTU lease expired and its original value was restored")

func readDesktopNodeMTU(launch *desktopNodeLaunch) (desktopNodeMTURecord, error) {
	return readDesktopNodeMTUWith(launch, readDesktopRuntimeFile)
}

func readDesktopNodeMTUContext(ctx context.Context, launch *desktopNodeLaunch) (desktopNodeMTURecord, error) {
	if ctx == nil {
		return desktopNodeMTURecord{}, errors.New("native TUN observation has no original caller")
	}
	record, err := readDesktopNodeMTUWith(launch, func(launch *desktopNodeLaunch, name string, limit int64) ([]byte, error) {
		return readDesktopRuntimeFileContext(ctx, launch, name, limit)
	})
	return record, errors.Join(err, ctx.Err())
}

func readDesktopNodeMTUWith(launch *desktopNodeLaunch, read func(*desktopNodeLaunch, string, int64) ([]byte, error)) (desktopNodeMTURecord, error) {
	var record desktopNodeMTURecord
	if launch == nil || !desktopMTURequestPattern.MatchString(launch.mtuSession) || launch.external != nil {
		return record, errors.New("ordinary node has no captured native TUN owner")
	}
	raw, err := read(launch, "node-mtu-status.json", desktopNodeMTURecordLimit)
	if err != nil || decodeRelayControlJSON(raw, &record) != nil {
		return record, errors.New("native TUN readback is unavailable")
	}
	now := time.Now().UnixMilli()
	if record.Schema != 1 || record.Session != launch.mtuSession || record.Config != launch.configSHA256 || !desktopMTUPathPattern.MatchString(record.Path) || record.Reader < 1 || record.Index < 1 || record.MTU < 1280 || record.MTU > 9000 || validateMTULiveInterface(record.Interface) != nil || record.Heartbeat > now+2000 || record.Heartbeat < now-2000 || record.Request != "" && !desktopMTURequestPattern.MatchString(record.Request) || record.Lease != "" && !desktopMTURequestPattern.MatchString(record.Lease) || len(record.Failure) > 256 {
		return record, errors.New("native TUN record is stale or belongs to another runtime")
	}
	if prefix := launch.candidatePrefix; prefix != nil {
		if launch.chain != nil || prefix.policy == nil || prefix.policy.Validate() != nil || record.Active || record.Generation != 0 || record.Request != "" || record.Lease != "" || record.Reader != 1 || record.Restored || record.Expired || record.Failure != "" || record.NetworkReceipt == "" {
			return record, errors.New("candidate prefix changed its closed original native TUN observation")
		}
		meta := prefix.policy.Metadata()
		if meta.SessionID != record.Session || meta.ConfigSHA256 != record.Config {
			return record, errors.New("candidate prefix TUN belongs to another source")
		}
	}
	if record.NetworkReceipt != "" {
		network, err := desktopnetwork.ParseDesktopNetworkReceipt(record.NetworkReceipt)
		if err != nil || network.TargetOS != runtime.GOOS || network.Name != record.Interface || network.Index != uint32(record.Index) || network.MTU != record.MTU {
			return record, errors.New("native routing receipt changed its exact TUN reader")
		}
	}
	return record, nil
}
func openDesktopNodeMTUOwner(launch *desktopNodeLaunch, live mtuLiveSnapshot, token string) (mtuKernelOwner, error) {
	return openDesktopNodeMTUOwnerContext(context.Background(), launch, live, token)
}

func openDesktopNodeMTUOwnerContext(ctx context.Context, launch *desktopNodeLaunch, live mtuLiveSnapshot, token string) (mtuKernelOwner, error) {
	if launch != nil && launch.candidatePrefix != nil {
		return nil, errors.New("candidate prefix retains its original measurement TUN; a separate optimizer is unavailable")
	}
	record, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil {
		return nil, err
	}
	if record.Active || record.Interface != live.Interface || record.MTU != live.OriginalMTU || live.Family != 4 && live.Family != 6 {
		return nil, errors.New("native TUN was replaced or already has an active MTU lease")
	}
	owner := &desktopNodeMTUOwner{launch: launch, record: record, family: live.Family, originalMTU: record.MTU, lease: token}
	if err = owner.exchangeContext(ctx, "begin", 0); err != nil {
		return owner, err
	}
	return owner, nil
}
func (owner *desktopNodeMTUOwner) state() mtuKernelState {
	r := owner.record
	return mtuKernelState{Interface: r.Interface, Family: owner.family, Index: r.Index, MTU: r.MTU, Identity: fmt.Sprintf("%s/%s/%d", r.Session, r.Path, r.Reader)}
}
func (owner *desktopNodeMTUOwner) readLocked() (mtuKernelState, error) {
	return owner.readLockedContext(context.Background())
}

func (owner *desktopNodeMTUOwner) readLockedContext(ctx context.Context) (mtuKernelState, error) {
	if owner.closed || owner.pending != nil {
		return mtuKernelState{}, errors.New("native MTU lease is closed or its last command has not drained")
	}
	if closed, err := readDesktopNodeStoppedContext(ctx, owner.launch); err != nil || closed {
		return mtuKernelState{}, errors.Join(err, errors.New("captured native TUN has retired or its close receipt is invalid"))
	}
	r, err := readDesktopNodeMTUContext(ctx, owner.launch)
	expiry := owner.committed && owner.record.Expired && owner.record.Restored && !owner.record.Active && owner.record.MTU == owner.originalMTU
	if err != nil || r.Session != owner.record.Session || r.Config != owner.record.Config || r.Path != owner.record.Path || r.Reader != owner.record.Reader || r.Interface != owner.record.Interface || r.Index != owner.record.Index || r.MTU != owner.record.MTU || r.Generation != owner.record.Generation || r.Request != owner.record.Request || r.Failure != owner.record.Failure || r.Failure != "" && !expiry || r.Lease != owner.lease || r.Active != owner.record.Active || r.Restored != owner.record.Restored || r.Expired != owner.record.Expired || !owner.committed && !r.Active {
		return mtuKernelState{}, errors.Join(err, errors.New("captured native TUN lease or reader changed"))
	}
	return owner.state(), ctx.Err()
}
func (owner *desktopNodeMTUOwner) Read() (mtuKernelState, error) {
	return owner.ReadContext(context.Background())
}

func (owner *desktopNodeMTUOwner) ReadContext(ctx context.Context) (mtuKernelState, error) {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return mtuKernelState{}, err
	}
	defer owner.mu.Unlock()
	return owner.readLockedContext(ctx)
}
func (owner *desktopNodeMTUOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
	return owner.ChangeContext(context.Background(), expected, mtu)
}

func (owner *desktopNodeMTUOwner) ChangeContext(ctx context.Context, expected mtuKernelState, mtu int) (mtuKernelState, error) {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return mtuKernelState{}, err
	}
	defer owner.mu.Unlock()
	current, err := owner.readLockedContext(ctx)
	if err != nil || current != expected || mtu < 1280 || mtu > 9000 {
		return current, errors.Join(err, errors.New("native MTU mutation lost its captured reader"))
	}
	err = owner.exchangeContext(ctx, "set", mtu)
	return owner.state(), err
}
func (owner *desktopNodeMTUOwner) Commit() error {
	return owner.commitWithValidation(nil)
}

// The Linux host must retain the exact unconfirmed revert capability until
// the post-command original host/kernel observation also succeeds. Other
// consumers preserve their existing commit contract through Commit above.
func (owner *desktopNodeMTUOwner) CommitContext(ctx context.Context) error {
	return owner.commitWithValidationContext(ctx, nil)
}

func (owner *desktopNodeMTUOwner) commitWithValidation(current func() error) error {
	var check func(context.Context) error
	if current != nil {
		check = func(context.Context) error { return current() }
	}
	return owner.commitWithValidationContext(context.Background(), check)
}

func (owner *desktopNodeMTUOwner) commitWithValidationContext(ctx context.Context, current func(context.Context) error) error {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	defer owner.mu.Unlock()
	if _, err := owner.readLockedContext(ctx); err != nil {
		return err
	}
	if owner.committed {
		if owner.record.Restored {
			return errors.New("restored native MTU lease cannot be committed")
		}
		return nil
	}
	if err := owner.exchangeContext(ctx, "commit", 0); err != nil {
		return err
	}
	if current != nil {
		if err := current(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owner.committed = true
	owner.discardCommitRevert()
	return nil
}

func (owner *desktopNodeMTUOwner) Restore() (mtuKernelState, error) {
	return owner.RestoreContext(context.Background())
}

func (owner *desktopNodeMTUOwner) RestoreContext(ctx context.Context) (mtuKernelState, error) {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return mtuKernelState{}, err
	}
	defer owner.mu.Unlock()
	if owner.closed {
		return mtuKernelState{}, errors.New("native MTU owner is closed")
	}
	return owner.restoreLockedContext(ctx)
}

func (owner *desktopNodeMTUOwner) restoreLocked() (mtuKernelState, error) {
	return owner.restoreLockedContext(context.Background())
}

func (owner *desktopNodeMTUOwner) restoreLockedContext(ctx context.Context) (mtuKernelState, error) {
	if owner.committed {
		if !owner.record.Restored {
			return mtuKernelState{}, errors.New("confirmed native MTU commit cannot be reverted")
		}
		return owner.readLockedContext(ctx)
	}
	if record, err := readDesktopNodeMTUContext(ctx, owner.launch); err == nil && record.Expired {
		if restored, expiryErr := owner.acceptExpiredRestorationContext(ctx, record); expiryErr != nil {
			return mtuKernelState{}, expiryErr
		} else if restored {
			return owner.readLockedContext(ctx)
		}
	}
	if owner.pending != nil {
		if err := owner.drainContext(ctx); err != nil && owner.pending != nil {
			return mtuKernelState{}, err
		}
	}
	if owner.committed && owner.record.Restored {
		return owner.readLockedContext(ctx)
	}
	action, value := "rollback", 0
	if !owner.record.Active {
		if owner.unconfirmedCommit == nil || !desktopMTURequestPattern.MatchString(owner.unconfirmedCommit.RevertToken) {
			return mtuKernelState{}, errors.New("inactive native MTU lease has no owned unconfirmed commit to restore")
		}
		action, value = "revert-unconfirmed-commit", owner.originalMTU
	}
	if err := owner.exchangeContext(ctx, action, value); err != nil {
		return mtuKernelState{}, err
	}
	// The lease is now explicitly inactive with the original readback. Retain
	// that receipt for the controller's final validation before releasing it.
	owner.committed = true
	owner.discardCommitRevert()
	return owner.readLockedContext(ctx)
}
func (owner *desktopNodeMTUOwner) Close() error {
	return owner.CloseContext(context.Background())
}

func (owner *desktopNodeMTUOwner) CloseContext(ctx context.Context) error {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if closed, err := readDesktopNodeStoppedContext(ctx, owner.launch); err != nil {
		return err
	} else if closed {
		// This exact child already closed Box/TUN. There is no live interface to
		// restore and no permission to manufacture a numeric MTU receipt.
		owner.closed, owner.runtimeRetired = true, true
		owner.pending = nil
		owner.discardCommitRevert()
		return nil
	}
	var commandFailure error
	if owner.pending != nil {
		if err := owner.drainContext(ctx); err != nil {
			if owner.pending != nil {
				return err
			}
			if !errors.Is(err, errDesktopNodeMTUExpired) {
				commandFailure = err
			}
		}
	}
	if !owner.committed {
		if _, err := owner.restoreLockedContext(ctx); err != nil {
			return errors.Join(commandFailure, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(commandFailure, err)
	}
	owner.closed = true
	return commandFailure
}

// Called only after checked Close. No caller can use this receipt to mutate the
// closed lease; the parent uses it to label late cleanup as an actual rollback.
func (owner *desktopNodeMTUOwner) CleanupRestored() (mtuKernelState, bool) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.cleanupRestoredLocked()
}

func (owner *desktopNodeMTUOwner) CleanupRestoredContext(ctx context.Context) (mtuKernelState, bool, error) {
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return mtuKernelState{}, false, err
	}
	defer owner.mu.Unlock()
	state, restored := owner.cleanupRestoredLocked()
	return state, restored, ctx.Err()
}

func (owner *desktopNodeMTUOwner) cleanupRestoredLocked() (mtuKernelState, bool) {
	if !owner.closed || owner.runtimeRetired || !owner.committed || owner.pending != nil || owner.unconfirmedCommit != nil || owner.record.Active || !owner.record.Restored || owner.record.Failure != "" && !owner.record.Expired || owner.record.MTU != owner.originalMTU {
		return mtuKernelState{}, false
	}
	return owner.state(), true
}

func (owner *desktopNodeMTUOwner) discardCommitRevert() {
	if owner.unconfirmedCommit != nil {
		owner.unconfirmedCommit.RevertToken = ""
		owner.unconfirmedCommit = nil
	}
}

// Only the retained ordered Darwin host can authorize a different kernel name.
// Fixed-name targets and every ordinary/imported family retain their original
// interface contract. The mailbox/nonce, lease and reader bounds are checked by
// the caller before this proof, and no owner state changes until it succeeds.
func (owner *desktopNodeMTUOwner) verifyReaderChangeContext(ctx context.Context, next desktopNodeMTURecord) error {
	if ctx == nil {
		return errors.New("native MTU reader succession has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	previous := owner.record
	if next.Interface == previous.Interface {
		return nil
	}
	launch := owner.launch
	if owner.verifyReaderChange == nil || launch == nil || launch.chain == nil || launch.chain.platform == nil ||
		!launch.chain.hasPolicy() || launch.chain.policyMetadata().TargetOS != "darwin" ||
		launch.external != nil || launch.importedEntry || launch.importedPlatform != nil || launch.tor != nil ||
		next.Reader <= previous.Reader || !desktopNodeChainDarwinInterfaceName(previous.Interface) ||
		!desktopNodeChainDarwinInterfaceName(next.Interface) {
		return errors.New("native MTU acknowledgement changed its captured interface")
	}
	meta := launch.chain.policyMetadata()
	if meta.SessionID != previous.Session || meta.ConfigSHA256 != previous.Config {
		return errors.New("native MTU reader succession changed its original ordered policy")
	}
	if err := owner.verifyReaderChange(ctx, previous, next); err != nil {
		return err
	}
	return ctx.Err()
}

func (owner *desktopNodeMTUOwner) acceptExpiredRestoration(record desktopNodeMTURecord) (bool, error) {
	return owner.acceptExpiredRestorationContext(context.Background(), record)
}

func (owner *desktopNodeMTUOwner) acceptExpiredRestorationContext(ctx context.Context, record desktopNodeMTURecord) (bool, error) {
	if !record.Expired {
		return false, nil
	}
	bad := errors.New("native MTU expiry did not prove this captured lease's original reader")
	if owner.committed && !owner.record.Restored || record.Active || !record.Restored || record.MTU != owner.originalMTU || record.Session != owner.record.Session || record.Config != owner.record.Config || record.Path != owner.record.Path || record.Lease != owner.lease || (record.Failure != "captured MTU lease expired; original MTU restored" && record.Failure != "captured TUN operation rejected") {
		return false, bad
	}
	matching := record.Generation == owner.record.Generation && record.Request == owner.record.Request
	maximum := owner.record.Reader + 1
	if pending := owner.pending; pending != nil && record.Generation == pending.Generation && record.Request == pending.Request {
		matching = true
		// One pending owned mutation can have replaced its reader before the
		// fixed lease expiry restores the original through one further reader.
		if pending.Action == "set" || pending.Action == "rollback" {
			maximum++
		}
	}
	if !matching || record.Reader < owner.record.Reader || record.Reader > maximum || record.Reader == owner.record.Reader && (record.Index != owner.record.Index || record.MTU != owner.record.MTU) {
		return false, bad
	}
	if _, err := readDesktopRuntimeFileContext(ctx, owner.launch, "node-mtu-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return false, nil // The child must consume a pending command first.
		}
		return false, err
	}
	if err := owner.verifyReaderChangeContext(ctx, record); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	owner.record, owner.pending, owner.committed = record, nil, true
	owner.discardCommitRevert()
	return true, nil
}
func (owner *desktopNodeMTUOwner) exchange(action string, value int) error {
	return owner.exchangeContext(context.Background(), action, value)
}

func (owner *desktopNodeMTUOwner) exchangeContext(ctx context.Context, action string, value int) error {
	if ctx == nil {
		return errors.New("native MTU command has no caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if owner.pending != nil {
		return errors.New("another native MTU command is still draining")
	}
	identifier, err := randomHex(16)
	if err != nil {
		return err
	}
	r := owner.record
	command := desktopNodeMTUCommand{Schema: 1, Session: r.Session, Config: r.Config, Path: r.Path, Generation: r.Generation + 1, Request: identifier, Lease: owner.lease, Action: action, Reader: r.Reader, MTU: r.MTU, Value: value}
	if action == "commit" {
		if owner.unconfirmedCommit != nil {
			return errors.New("an earlier native MTU commit is still unresolved")
		}
		command.RevertToken, err = randomHex(16)
		if err != nil {
			return err
		}
	} else if action == "revert-unconfirmed-commit" {
		previous := owner.unconfirmedCommit
		if owner.committed || previous == nil || previous.Action != "commit" || previous.Lease != owner.lease || previous.Session != r.Session || previous.Config != r.Config || previous.Path != r.Path || !desktopMTURequestPattern.MatchString(previous.RevertToken) {
			return errors.New("native commit revert has no exact unresolved owner")
		}
		command.RevertToken, command.CommitRequest, command.CommitGeneration = previous.RevertToken, previous.Request, previous.Generation
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	defer clear(raw)
	if action == "commit" {
		capture := command
		owner.unconfirmedCommit = &capture
	}
	owner.pending = &command
	// A consume-before-final-stat race is accepted only by drain's matching
	// acknowledgement and confirmed removal of this immutable request file.
	entered, writeErr := writeDesktopRuntimeFileAdmissionContext(ctx, owner.launch, "node-mtu-request.json", raw, true)
	if !entered {
		owner.pending = nil
		if action == "commit" {
			owner.discardCommitRevert()
		}
		if action == "begin" {
			// This owner never acquired a native lease. Close must not wait
			// for an unissued nonce or manufacture a rollback of another lease.
			owner.closed = true
		}
		return writeErr
	}
	err = owner.drainContext(ctx)
	if err != nil && writeErr != nil {
		return errors.Join(writeErr, err)
	}
	return err
}
func (owner *desktopNodeMTUOwner) drain() error {
	return owner.drainContext(context.Background())
}

func (owner *desktopNodeMTUOwner) drainContext(parent context.Context) error {
	if parent == nil {
		return errors.New("native MTU drain has no caller")
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	command := owner.pending
	if command == nil {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if closed, err := readDesktopNodeStoppedContext(ctx, owner.launch); err != nil || closed {
			return errors.Join(err, errors.New("native TUN retired before this command; checked Close must release its owner"))
		}
		record, err := readDesktopNodeMTUContext(ctx, owner.launch)
		if err == nil && record.Expired {
			if restored, expiryErr := owner.acceptExpiredRestorationContext(ctx, record); expiryErr != nil {
				return expiryErr
			} else if restored {
				return errDesktopNodeMTUExpired
			}
		}
		if err == nil && record.Generation == command.Generation && record.Request == command.Request && record.Config == command.Config && record.Path == command.Path {
			// Do not issue another operation until the child has consumed the
			// precise command; its response is published before its input is removed.
			if _, err := readDesktopRuntimeFileContext(ctx, owner.launch, "node-mtu-request.json", 4096); errors.Is(err, os.ErrNotExist) {
				// A matching nonce alone is not ownership. Do not replace the
				// captured reader/lease with a foreign or contradictory response.
				if record.Lease != owner.lease || record.Reader < owner.record.Reader || record.Reader > owner.record.Reader+1 || (record.Reader == owner.record.Reader && record.Index != owner.record.Index) {
					return errors.New("native MTU acknowledgement changed its captured owner")
				}
				if record.Failure != "" {
					// A rejected mutation may have returned an actual rollback
					// reader. Keep it only inside this same active lease.
					if !record.Active && (command.Action != "revert-unconfirmed-commit" || record.Restored || owner.unconfirmedCommit == nil) {
						return errors.New("failed native MTU command abandoned its active lease")
					}
					if err := owner.verifyReaderChangeContext(ctx, record); err != nil {
						return err
					}
					if err := ctx.Err(); err != nil {
						return err
					}
					owner.pending, owner.record = nil, record
					if command.Action == "commit" {
						owner.discardCommitRevert()
					}
					return errors.New("native TUN rejected the captured MTU command")
				}
				restoring := command.Action == "rollback" || command.Action == "revert-unconfirmed-commit"
				if record.Expired || (command.Action == "begin" || command.Action == "set") != record.Active || command.Action == "set" && record.MTU != command.Value || (command.Action == "begin" || command.Action == "commit") && (record.Reader != owner.record.Reader || record.MTU != command.MTU) || restoring && (!record.Restored || record.MTU != owner.originalMTU) || !restoring && record.Restored || (command.Action == "set" || restoring) && record.MTU != owner.record.MTU && record.Reader != owner.record.Reader+1 {
					return errors.New("native MTU acknowledgement changed its lease or requested value")
				}
				if err := owner.verifyReaderChangeContext(ctx, record); err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				owner.pending, owner.record = nil, record
				if restoring {
					owner.committed = true
					owner.discardCommitRevert()
				}
				return nil
			}
		}
		if desktopExternalDirectoryCurrent(owner.launch) != nil {
			return errors.New("native TUN workspace was replaced")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func desktopNodeProcessDone(launch *desktopNodeLaunch) <-chan struct{} {
	if launch != nil && launch.candidatePrefix != nil && launch.candidatePrefix.platform != nil {
		return launch.candidatePrefix.platform.processDone()
	}
	if launch != nil && launch.chain != nil && launch.chain.platform != nil {
		return launch.chain.platform.processDone()
	}
	if launch != nil && launch.importedPlatform != nil {
		return launch.importedPlatform.ProcessDone()
	}
	if launch == nil || launch.command == nil || launch.command.Process == nil && !desktopOwnedNodeCreated(launch) {
		return nil
	}
	launch.nodeWaitOnce.Do(func() {
		launch.nodeWaitDone = make(chan struct{})
		go func() {
			if process := desktopOwnedNodeProcess(launch); process != nil {
				_, _ = process.Wait(context.Background())
			} else {
				_ = launch.command.Wait()
			}
			close(launch.nodeWaitDone)
		}()
	})
	return launch.nodeWaitDone
}

func desktopNodeProcessExited(launch *desktopNodeLaunch) bool {
	select {
	case <-desktopNodeProcessDone(launch):
		return true
	default:
		return false
	}
}

func readDesktopNodeStopped(launch *desktopNodeLaunch) (bool, error) {
	return readDesktopNodeStoppedContext(context.Background(), launch)
}

func readDesktopNodeStoppedContext(ctx context.Context, launch *desktopNodeLaunch) (bool, error) {
	if ctx == nil {
		return false, errors.New("native Router node close has no original caller")
	}
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "stopped.json", 1024)
	if errors.Is(err, os.ErrNotExist) {
		return false, ctx.Err()
	}
	var record desktopExternalStop
	if err != nil || decodeRelayControlJSON(raw, &record) != nil || record.Schema != 1 || record.SessionID != launch.mtuSession || record.SourceSHA256 != launch.configSHA256 || !record.Closed {
		return false, errors.Join(err, ctx.Err(), errors.New("native Router node close belongs to another runtime"))
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return false, err
	}
	launch.nodeStopAcknowledged = true
	launch.workspaceMu.Unlock()
	return true, nil
}

func prepareDesktopNodeStop(a *app, command *exec.Cmd) error {
	raw, exists := desktopNodeOwners.Load(a)
	if !exists {
		return nil
	}
	launch, ok := raw.(*desktopNodeLaunch)
	if ok && launch != nil && launch.ownedNode != nil {
		return a.prepareDesktopOwnedNodeStop(launch, command)
	}
	if !ok || launch == nil || launch.external != nil || launch.mtuSession == "" || launch.command == nil || launch.command.Process == nil {
		return nil
	}
	current := func() error {
		if raw, exists := desktopNodeOwners.Load(a); !exists || raw != launch || command != nil && launch.command != command {
			return errors.New("native Router node cleanup lost its captured owner")
		}
		a.mu.Lock()
		owned := a.cmd == nil || a.cmd == launch.command
		a.mu.Unlock()
		if !owned {
			return errors.New("native Router node cleanup cannot alter a replacement connection")
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	acknowledged := launch.nodeStopAcknowledged
	launch.workspaceMu.Unlock()
	if acknowledged {
		if _, err := os.Lstat(launch.directory); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	if closed, err := readDesktopNodeStopped(launch); err != nil || closed {
		return errors.Join(err, current())
	}
	request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: launch.mtuSession, SourceSHA256: launch.configSHA256})
	if err := writeDesktopRuntimeFile(launch, "stop.json", request, true); err != nil {
		return err
	}
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := current(); err != nil {
			return err
		}
		if closed, err := readDesktopNodeStopped(launch); err != nil || closed {
			return errors.Join(err, current())
		}
		if desktopNodeProcessExited(launch) {
			return errors.New("native Router node exited without checked cleanup; protection and private ownership retained")
		}
		select {
		case <-deadline.C:
			return errors.New("native Router node close is still pending; ownership retained")
		case <-ticker.C:
		}
	}
}

func nativeNodeMTUEnvironment(environment []string, session, config string) []string {
	clean := environment[:0]
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		if !strings.EqualFold(name, "HOMEVPN_NODE_SESSION") && !strings.EqualFold(name, "HOMEVPN_NODE_CONFIG_SHA256") {
			clean = append(clean, value)
		}
	}
	return append(clean, "HOMEVPN_NODE_SESSION="+session, "HOMEVPN_NODE_CONFIG_SHA256="+config)
}
