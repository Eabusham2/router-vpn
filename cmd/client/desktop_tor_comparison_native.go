package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"router-vpn/internal/mobiletor"
)

// A comparison is a retained claim on one native runtime, not on the currently
// selected profile. Even a failed publication may have reached that process.
// All non-nil constructor results therefore require Close, including errors.
type desktopTorComparisonClient struct {
	app    *app
	launch *desktopNodeLaunch
	base   mobiletor.DesktopTorCompareRequest
	life   context.Context
	cancel context.CancelFunc

	operation  sync.Mutex
	mu         sync.Mutex
	last       *desktopTorComparisonAction
	previous   *mobiletor.DesktopTorCompareStatus
	identity   string
	prepared   bool
	closed     bool
	cancelled  bool
	cancelDone chan struct{}
}

var _ mobiletor.Comparison = (*desktopTorComparisonClient)(nil)

type desktopTorComparisonAction struct {
	request mobiletor.DesktopTorCompareRequest
	issued  chan struct{}
	// Access to result is serialized by operation. issued is closed only after
	// publication returns; cancellation cannot overtake an entered file write.
	result *mobiletor.DesktopTorCompareStatus
}

func newDesktopTorComparisonClient(a *app, launch *desktopNodeLaunch, target string) (*desktopTorComparisonClient, error) {
	if a == nil || launch == nil || launch.tor == nil || !mobiletor.DesktopTorCompareTarget(target) {
		return nil, errors.New("Tor comparison requires a captured native owner and approved target")
	}
	if _, err := a.readDesktopTorProof(launch); err != nil {
		return nil, err
	}
	requestID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	owner := launch.tor
	owner.mu.Lock()
	if owner.comparison != nil || owner.comparisonGeneration == ^uint64(0) {
		owner.mu.Unlock()
		return nil, errors.New("the captured Tor comparison has not drained")
	}
	owner.comparisonGeneration++
	life, cancel := context.WithCancel(context.Background())
	client := &desktopTorComparisonClient{app: a, launch: launch, life: life, cancel: cancel,
		base: mobiletor.DesktopTorCompareRequest{Schema: mobiletor.DesktopTorCompareSchema,
			SessionID: owner.expected.SessionID, SourceSHA256: owner.expected.SourceSHA256,
			ConfigSHA256: owner.expected.ConfigSHA256, Generation: owner.comparisonGeneration,
			RequestID: requestID, Target: target}}
	if owner.comparisonPrevious != nil {
		previous := *owner.comparisonPrevious
		client.previous = &previous
	}
	owner.comparison = client
	owner.mu.Unlock()
	if err := client.current(); err != nil {
		client.Cancel()
		return client, err
	}
	return client, nil
}

func (c *desktopTorComparisonClient) claimed() bool {
	if c == nil || c.launch == nil || c.launch.tor == nil {
		return false
	}
	owner := c.launch.tor
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.comparison == c && owner.comparisonGeneration == c.base.Generation
}

func (c *desktopTorComparisonClient) current() error {
	if !c.claimed() || c.life.Err() != nil {
		return errors.New("Tor comparison is cancelled or no longer owns its captured runtime")
	}
	_, err := c.app.readDesktopTorProof(c.launch)
	return err
}

func (c *desktopTorComparisonClient) Identity() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cancelled || !c.prepared {
		return ""
	}
	return c.identity
}

func (c *desktopTorComparisonClient) Prepare(ctx context.Context) error {
	_, err := c.perform(ctx, mobiletor.DesktopTorComparePrepare, c.base.Target)
	return err
}

func (c *desktopTorComparisonClient) Verify(ctx context.Context) error {
	_, err := c.perform(ctx, mobiletor.DesktopTorCompareVerify, c.base.Target)
	return err
}

func (c *desktopTorComparisonClient) ProbeLast(ctx context.Context) (time.Duration, error) {
	return c.perform(ctx, mobiletor.DesktopTorCompareLast, c.base.Target)
}

func (c *desktopTorComparisonClient) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	return c.perform(ctx, mobiletor.DesktopTorCompareExternal, target)
}

func (c *desktopTorComparisonClient) perform(parent context.Context, action, target string) (duration time.Duration, failure error) {
	if c == nil || parent == nil || target != c.base.Target {
		return 0, errors.New("Tor comparison cannot substitute its context or external endpoint")
	}
	if !c.operation.TryLock() {
		return 0, errors.New("another captured Tor comparison action is still running")
	}
	defer c.operation.Unlock()
	c.mu.Lock()
	ready := !c.closed && !c.cancelled && (action == mobiletor.DesktopTorComparePrepare && !c.prepared && c.last == nil || action != mobiletor.DesktopTorComparePrepare && c.prepared)
	c.mu.Unlock()
	if !ready {
		return 0, errors.New("Tor comparison action is not valid for this retained handle")
	}
	defer func() {
		if failure != nil {
			c.Cancel()
		}
	}()
	if err := c.current(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, (mobiletor.DesktopTorCompareRequest{Action: action}).Budget())
	stop := context.AfterFunc(c.life, cancel)
	defer func() { stop(); cancel() }()
	request, err := c.issue(ctx, action, false)
	if err != nil {
		return 0, err
	}
	result, err := c.await(ctx, request, false)
	if err != nil {
		return 0, err
	}
	if err := c.current(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if result.Failed || result.Cancelled || result.StopRequired || result.Drained {
		return 0, errors.New("captured Tor comparison action failed; its owner is retained for cleanup")
	}
	c.mu.Lock()
	if c.cancelled || c.closed || c.life.Err() != nil || ctx.Err() != nil {
		c.mu.Unlock()
		return 0, errors.New("Tor comparison completed after cancellation")
	}
	if action == mobiletor.DesktopTorComparePrepare {
		c.identity, c.prepared = result.IdentitySHA256, true
	}
	c.mu.Unlock()
	return time.Duration(result.ResponseNS), nil
}

func (c *desktopTorComparisonClient) issue(ctx context.Context, action string, cleanup bool) (*desktopTorComparisonAction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := c.base
	request.Action, request.Sequence = action, 1
	c.mu.Lock()
	if c.last != nil {
		if c.last.result == nil || !c.last.result.Complete || c.last.request.Sequence == ^uint64(0) {
			c.mu.Unlock()
			return nil, errors.New("previous Tor comparison action has not acknowledged completion")
		}
		request.Sequence = c.last.request.Sequence + 1
	}
	if c.closed || !cleanup && c.cancelled {
		c.mu.Unlock()
		return nil, errors.New("Tor comparison handle has been retired")
	}
	deadline := time.Now().Add(request.Budget())
	if bounded, ok := ctx.Deadline(); ok && bounded.Before(deadline) {
		deadline = bounded
	}
	request.ExpiresAt = deadline.UnixMilli()
	if err := request.Validate(time.Now()); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	issued := &desktopTorComparisonAction{request: request, issued: make(chan struct{})}
	c.last = issued
	c.mu.Unlock()
	defer close(issued.issued)
	raw, _ := json.Marshal(request)
	var err error
	if cleanup {
		err = c.writeCleanup(mobiletor.DesktopTorCompareRequestFile, request)
	} else {
		err = writeDesktopRuntimeFile(c.launch, mobiletor.DesktopTorCompareRequestFile, raw, true)
	}
	if err == nil {
		return issued, nil
	}
	// The native loop may consume the request before the final file read. An
	// exact echoed request acknowledges publication, never successful probing.
	if record, readErr := c.read(cleanup); readErr == nil && record.DesktopTorCompareRequest == request {
		return issued, nil
	}
	return issued, err
}

func desktopTorComparisonStatus(raw []byte) (mobiletor.DesktopTorCompareStatus, error) {
	var record mobiletor.DesktopTorCompareStatus
	bad := errors.New("invalid captured Tor comparison receipt")
	if len(raw) == 0 || len(raw) > mobiletor.DesktopTorCompareFileLimit || decodeRelayControlJSON(raw, &record) != nil {
		return record, bad
	}
	if record.IdentitySHA256 != "" {
		decoded, err := hex.DecodeString(record.IdentitySHA256)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != record.IdentitySHA256 {
			return record, bad
		}
	}
	failure := record.Failed || record.Cancelled || record.StopRequired
	measurement := record.Action == mobiletor.DesktopTorCompareLast || record.Action == mobiletor.DesktopTorCompareExternal
	if !record.Complete && (record.Drained || failure || record.ResponseNS != 0) ||
		record.Drained && (record.Action != mobiletor.DesktopTorCompareClose || record.StopRequired) ||
		record.StopRequired && !record.Failed && !record.Cancelled ||
		record.ResponseNS < 0 || record.ResponseNS > int64(record.Budget()) ||
		(!record.Complete || failure || !measurement) && record.ResponseNS != 0 ||
		record.Complete && !failure && measurement && record.ResponseNS <= 0 ||
		record.Complete && !failure && record.Action != mobiletor.DesktopTorCompareClose && record.IdentitySHA256 == "" ||
		record.Complete && !failure && record.Action == mobiletor.DesktopTorCompareClose && !record.Drained {
		return record, bad
	}
	return record, nil
}

func (c *desktopTorComparisonClient) read(cleanup bool) (mobiletor.DesktopTorCompareStatus, error) {
	var raw []byte
	var err error
	if cleanup {
		raw, err = c.readCleanup(mobiletor.DesktopTorCompareStatusFile)
	} else {
		raw, err = readDesktopRuntimeFile(c.launch, mobiletor.DesktopTorCompareStatusFile, mobiletor.DesktopTorCompareFileLimit)
	}
	if err != nil {
		return mobiletor.DesktopTorCompareStatus{}, err
	}
	return desktopTorComparisonStatus(raw)
}

func (c *desktopTorComparisonClient) await(ctx context.Context, action *desktopTorComparisonAction, cleanup bool) (mobiletor.DesktopTorCompareStatus, error) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return mobiletor.DesktopTorCompareStatus{}, err
		}
		if !c.claimed() {
			return mobiletor.DesktopTorCompareStatus{}, errors.New("Tor comparison claim was replaced")
		}
		if cleanup && c.nativeJoined() {
			return mobiletor.DesktopTorCompareStatus{}, errors.New("captured Tor runtime has joined; retire through its checked terminal receipt")
		}
		if !cleanup {
			if err := c.current(); err != nil {
				return mobiletor.DesktopTorCompareStatus{}, err
			}
			if time.Now().UnixMilli() >= action.request.ExpiresAt {
				return mobiletor.DesktopTorCompareStatus{}, context.DeadlineExceeded
			}
		}
		record, err := c.read(cleanup)
		if err == nil {
			if record.DesktopTorCompareRequest == action.request {
				c.mu.Lock()
				identity := c.identity
				c.mu.Unlock()
				if identity != "" && record.IdentitySHA256 != identity {
					return record, errors.New("Tor comparison native circuit identity changed")
				}
				if record.Complete {
					action.result = &record
					c.previous = &record
					return record, nil
				}
			} else if c.previous == nil || *c.previous != record {
				// Cancel may publish a terminal cancellation of the immediately
				// preceding action while Close is being consumed. This can only
				// advance cleanup; it never supplies a timing or a new identity.
				if !cleanup || c.previous == nil || record.DesktopTorCompareRequest != c.previous.DesktopTorCompareRequest ||
					!record.Complete || !record.Cancelled || record.Drained || record.ResponseNS != 0 || record.IdentitySHA256 != c.previous.IdentitySHA256 {
					return record, errors.New("Tor comparison result belongs to another request, source or generation")
				}
				c.previous = &record
			}
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDesktopRuntimeSnapshotChanged) {
			return record, err
		}
		select {
		case <-ctx.Done():
			return mobiletor.DesktopTorCompareStatus{}, ctx.Err()
		case <-tick.C:
		}
	}
}

// Cancel never blocks on file I/O or another action. Its retained worker waits
// for any entered publication, then addresses only that exact native request.
func (c *desktopTorComparisonClient) Cancel() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.cancelled || c.closed {
		c.mu.Unlock()
		return
	}
	c.cancelled = true
	c.cancel()
	last := c.last
	c.cancelDone = make(chan struct{})
	done := c.cancelDone
	c.mu.Unlock()
	if last == nil {
		close(done)
		return
	}
	go func() {
		defer close(done)
		<-last.issued
		_ = c.writeCleanup(mobiletor.DesktopTorCompareCancelFile, last.request)
	}()
}

// Close drains measurement resources only. The candidate separately owns its
// VPN/process stop. A failed wait retains this handle and its exact request for
// retry; an unknown native state is never inferred from cancellation or exit.
func (c *desktopTorComparisonClient) Close(parent context.Context) error {
	if c == nil {
		return nil
	}
	if parent == nil {
		return errors.New("Tor comparison cleanup requires a bounded context")
	}
	c.Cancel()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !c.operation.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	defer c.operation.Unlock()
	c.mu.Lock()
	closed, done, last := c.closed, c.cancelDone, c.last
	c.mu.Unlock()
	if closed {
		return nil
	}
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if !c.claimed() {
		return errors.New("Tor comparison cleanup lost its exact native claim")
	}
	if last == nil || c.nativeJoined() {
		return c.release(nil)
	}
	if last.result == nil {
		if last.request.Action != mobiletor.DesktopTorCompareClose {
			// Retry an unacknowledged cancel on the same captured input. A
			// completed local write is not a native cancellation receipt.
			_ = c.writeCleanup(mobiletor.DesktopTorCompareCancelFile, last.request)
		}
		if _, err := c.await(ctx, last, true); err != nil {
			if c.nativeJoined() {
				return c.release(nil)
			}
			return err
		}
	}
	if last.request.Action == mobiletor.DesktopTorCompareClose && last.result.Drained {
		return c.release(last.result)
	}
	request, err := c.issue(ctx, mobiletor.DesktopTorCompareClose, true)
	if err != nil {
		return err
	}
	result, err := c.await(ctx, request, true)
	if err != nil {
		if c.nativeJoined() {
			return c.release(nil)
		}
		return err
	}
	if !result.Drained || result.StopRequired {
		return errors.New("native Tor comparison cleanup is pending; captured owner retained")
	}
	return c.release(&result)
}

func (c *desktopTorComparisonClient) release(status *mobiletor.DesktopTorCompareStatus) error {
	owner := c.launch.tor
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.comparison != c || owner.comparisonGeneration != c.base.Generation {
		return errors.New("Tor comparison cleanup cannot release a replacement claim")
	}
	if status != nil {
		copy := *status
		owner.comparisonPrevious = &copy
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	owner.comparison = nil
	return nil
}

// Only a checked terminal native receipt AND the actual command Wait join
// can substitute for an unavailable comparison receipt during whole-path stop.
func (c *desktopTorComparisonClient) nativeJoined() bool {
	if !desktopNodeProcessExited(c.launch) {
		return false
	}
	owner := c.launch.tor
	owner.mu.Lock()
	acknowledged := owner.stopAcknowledged
	owner.mu.Unlock()
	if acknowledged {
		return true
	}
	raw, err := c.readCleanup("stopped.json")
	var record desktopExternalStop
	return err == nil && decodeRelayControlJSON(raw, &record) == nil && record.Schema == 1 && record.Closed &&
		record.SessionID == c.base.SessionID && record.SourceSHA256 == c.base.SourceSHA256
}

// Cleanup can follow the pinned old directory after a rename. It cannot adopt
// results, create a new comparison or address the replacement pathname.
func (c *desktopTorComparisonClient) readCleanup(name string) ([]byte, error) {
	if name != mobiletor.DesktopTorCompareStatusFile && name != "stopped.json" {
		return nil, errors.New("invalid Tor comparison cleanup record")
	}
	launch := c.launch
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return nil, errors.New("Tor comparison cleanup lost its captured directory")
	}
	info, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(info, launch.directoryInfo) {
		return nil, errors.New("Tor comparison cleanup directory owner changed")
	}
	return readDesktopRuntimeSnapshot(launch.directoryRoot, name, mobiletor.DesktopTorCompareFileLimit)
}

func (c *desktopTorComparisonClient) writeCleanup(name string, request mobiletor.DesktopTorCompareRequest) error {
	if name != mobiletor.DesktopTorCompareCancelFile && (name != mobiletor.DesktopTorCompareRequestFile || request.Action != mobiletor.DesktopTorCompareClose) ||
		request.Schema != c.base.Schema || request.SessionID != c.base.SessionID || request.SourceSHA256 != c.base.SourceSHA256 || request.ConfigSHA256 != c.base.ConfigSHA256 ||
		request.Generation != c.base.Generation || request.RequestID != c.base.RequestID || request.Target != c.base.Target || request.Sequence == 0 || !c.claimed() {
		return errors.New("Tor comparison cleanup cannot address another capture")
	}
	raw, _ := json.Marshal(request)
	launch := c.launch
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return errors.New("Tor comparison cleanup lost its captured directory")
	}
	root := launch.directoryRoot
	info, err := root.Stat(".")
	if err != nil || !os.SameFile(info, launch.directoryInfo) {
		return errors.New("Tor comparison cleanup directory owner changed")
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readDesktopRuntimeSnapshot(root, name, mobiletor.DesktopTorCompareFileLimit)
			if readErr == nil && bytes.Equal(existing, raw) {
				return nil
			}
		}
		return errors.New("Tor comparison cleanup input has another owner")
	}
	created, statErr := file.Stat()
	written, writeErr := file.Write(raw)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if statErr != nil || writeErr != nil || closeErr != nil || written != len(raw) {
		if written < len(raw) && created != nil {
			if current, err := root.Lstat(name); err == nil && os.SameFile(current, created) && current.Size() < int64(len(raw)) {
				_ = root.Remove(name)
			}
		}
		return errors.New("Tor comparison cleanup publication remains pending")
	}
	return nil
}
