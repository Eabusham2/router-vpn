package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"time"

	"router-vpn/internal/dnsmeasure"
)

type desktopDNSNativeRequest struct {
	Schema       int    `json:"schema"`
	Session      string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Generation   uint64 `json:"generation"`
	Request      string `json:"request_id"`
	Transport    string `json:"public_transport"`
}

type desktopDNSNativeRecord struct {
	desktopDNSNativeRequest
	Status dnsmeasure.Status `json:"status"`
}

func decodeDesktopDNSRecord(launch *desktopNodeLaunch, raw []byte) (desktopDNSNativeRecord, error) {
	var record desktopDNSNativeRecord
	bad := errors.New("native DNS result differs from the captured session, graph or request")
	owner, ownerErr := capturedDesktopDNSRuntime(launch)
	if ownerErr != nil || len(raw) == 0 || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &record) != nil {
		return record, bad
	}
	status := record.Status
	if record.Schema != 1 || record.Session != owner.session || record.SourceSHA256 != owner.source || record.ConfigSHA256 != owner.config || status.Schema != 1 || status.NodeID != owner.node || status.SessionID != owner.session || len(status.Results) > 13 || len(status.Failure) > 256 {
		return record, bad
	}
	if record.Generation == 0 {
		if record.Request != "" || record.Transport != "" || status.Request != "" || status.PublicTransport != "" || status.Stage != "idle" || !status.Complete || !status.Drained || len(status.Results) != 0 {
			return record, bad
		}
		return record, nil
	}
	if !desktopMTURequestPattern.MatchString(record.Request) || record.Transport != "tcp" && record.Transport != "tls" && record.Transport != "https" || status.Request != record.Request || status.PublicTransport != record.Transport || status.Drained && !status.Complete {
		return record, bad
	}
	switch status.Stage {
	case "starting", "measuring":
		if status.Complete || status.Drained || len(status.Results) != 0 || status.Failure != "" {
			return record, bad
		}
	case "complete":
		if !status.Complete || status.Failure != "" {
			return record, bad
		}
	case "cancelled", "invalidated", "failed", "draining":
		if !status.Complete || status.Failure == "" || len(status.Results) != 0 {
			return record, bad
		}
	default:
		return record, bad
	}
	return record, nil
}

func readDesktopDNSRecord(launch *desktopNodeLaunch) (desktopDNSNativeRecord, error) {
	raw, err := readDesktopRuntimeFile(launch, "dns-status.json", 64<<10)
	if err != nil {
		return desktopDNSNativeRecord{}, err
	}
	return decodeDesktopDNSRecord(launch, raw)
}

// Cleanup alone may follow the old captured directory handle after a rename.
// Result adoption always uses readDesktopDNSRecord's strict pathname check.
func readDesktopDNSDrainRecord(launch *desktopNodeLaunch) (desktopDNSNativeRecord, error) {
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return desktopDNSNativeRecord{}, errors.New("DNS cleanup lost its private directory owner")
	}
	current, err := launch.directoryRoot.Stat(".")
	if err != nil || !os.SameFile(current, launch.directoryInfo) {
		return desktopDNSNativeRecord{}, errors.New("DNS cleanup directory belongs to another owner")
	}
	raw, err := readDesktopRuntimeSnapshot(launch.directoryRoot, "dns-status.json", 64<<10)
	if err != nil {
		return desktopDNSNativeRecord{}, err
	}
	return decodeDesktopDNSRecord(launch, raw)
}

func writeDesktopDNSRequest(launch *desktopNodeLaunch, name string, request desktopDNSNativeRequest) error {
	if name != "dns-request.json" && name != "dns-cancel.json" {
		return errors.New("invalid native DNS command")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	writeErr := writeDesktopRuntimeFile(launch, name, raw, true)
	if writeErr == nil {
		return nil
	}
	// The native loop can retire a consumed input before the writer's final
	// file-identity read. Only this exact native receipt acknowledges that race.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		record, err := readDesktopDNSRecord(launch)
		if err == nil && record.desktopDNSNativeRequest == request && (name == "dns-request.json" || record.Status.Complete && record.Status.Drained && record.Status.Stage == "cancelled") {
			return nil
		}
		if desktopExternalDirectoryCurrent(launch) != nil {
			return writeErr
		}
		select {
		case <-deadline.C:
			return writeErr
		case <-tick.C:
		}
	}
}

// Cancellation is cleanup of an already captured generation. It may follow
// the original directory handle after a rename; it never resolves the old
// pathname again or writes Start, policy, or connection commands this way.
func writeDesktopDNSCleanupCancel(launch *desktopNodeLaunch, request desktopDNSNativeRequest) error {
	owner, ownerErr := capturedDesktopDNSRuntime(launch)
	if ownerErr != nil {
		return ownerErr
	}
	if request.Schema != 1 || request.Session != owner.session || request.SourceSHA256 != owner.source || request.ConfigSHA256 != owner.config || request.Generation == 0 || !desktopMTURequestPattern.MatchString(request.Request) {
		return errors.New("DNS cleanup command belongs to another owner")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	if launch.directoryRoot == nil || launch.directoryInfo == nil {
		return errors.New("DNS cleanup lost its original directory handle")
	}
	root := launch.directoryRoot
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(current, launch.directoryInfo) {
		return errors.New("DNS cleanup directory identity changed")
	}
	file, err := root.OpenFile("dns-cancel.json", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readDesktopRuntimeSnapshot(root, "dns-cancel.json", 2048)
			if readErr == nil && bytes.Equal(existing, raw) {
				return nil
			}
		}
		return errors.New("DNS cleanup input already has another owner")
	}
	info, err := file.Stat()
	written := 0
	if err == nil {
		written, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil || closed != nil {
		// Only our own incomplete, unparseable write may be removed for retry.
		// A complete control may already have been consumed by the native loop.
		if written < len(raw) && info != nil {
			if current, statErr := root.Lstat("dns-cancel.json"); statErr == nil && os.SameFile(current, info) && current.Size() < int64(len(raw)) {
				_ = root.Remove("dns-cancel.json")
			}
		}
		return errors.New("captured DNS cleanup publication is pending")
	}
	return nil // Only the later matching native receipt acknowledges drain.
}

func validateDesktopDNSResults(launch *desktopNodeLaunch, status dnsmeasure.Status) error {
	bad := errors.New("native DNS samples do not match the captured resolver policies")
	if !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 13 {
		return bad
	}
	selected, routeLabel, ipv6Mode, err := desktopDNSExpectedEndpoints(launch)
	if err != nil {
		return bad
	}
	endpoints := map[string]dnsmeasure.Endpoint{selected.ID: selected}
	for _, endpoint := range dnsmeasure.PublicEndpoints(status.PublicTransport, routeLabel) {
		endpoints[endpoint.ID] = endpoint
	}
	seen := map[string]bool{}
	for _, result := range status.Results {
		expected, ok := endpoints[result.ID]
		if !ok || seen[result.ID] || expected != result.Endpoint || result.Samples < 0 || result.Samples > dnsmeasure.Samples || result.Failed < 0 || result.Failed > dnsmeasure.Samples || result.Samples+result.Failed != dnsmeasure.Samples || len(result.Failure) > 256 {
			return bad
		}
		seen[result.ID] = true
		if result.Ready {
			if result.Samples != dnsmeasure.Samples || result.Failed != 0 || result.Median == nil || *result.Median <= 0 || math.IsNaN(*result.Median) || math.IsInf(*result.Median, 0) || result.Failure != "" {
				return bad
			}
			if result.Kind == "public" && ipv6Mode != "on" && ipv6Mode != "auto" {
				address, err := netip.ParseAddr(result.Address)
				if err != nil || address.Is6() {
					return bad
				}
			}
		} else if result.Median != nil || result.Failed == 0 || result.Failure == "" {
			return bad // A failed/cancelled probe has no score, including zero.
		}
	}
	return nil
}

// runDesktopDNSNative owns the command generation and MTU hold until actual
// worker drain. Cancellation never closes a replacement VPN or releases a
// still-active measurement. A stubborn native close stays visibly draining.
func (a *app) runDesktopDNSNative(ctx context.Context, operation *desktopDNSOperation) (result dnsmeasure.Status, failure error) {
	launch := operation.snapshot.launch
	owner, ownerErr := capturedDesktopDNSRuntime(launch)
	if ownerErr != nil {
		return result, ownerErr
	}
	if !owner.lock.TryLock() {
		return result, errors.New("another native DNS measurement is still draining")
	}
	defer owner.lock.Unlock()
	if *owner.failed {
		return result, errors.New("native DNS control was retired; reconnect before Retest")
	}
	initial, err := readDesktopDNSRecord(launch)
	if err != nil || !initial.Status.Complete || !initial.Status.Drained || initial.Generation != *owner.generation || *owner.generation == ^uint64(0) {
		return result, errors.New("native DNS mailbox is unavailable or has another owner")
	}
	if err := operation.snapshot.current(a); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	*owner.generation++
	request := desktopDNSNativeRequest{Schema: 1, Session: owner.session, SourceSHA256: owner.source, ConfigSHA256: owner.config, Generation: *owner.generation, Request: operation.request, Transport: operation.transport}
	drained := false
	defer func() {
		if drained {
			return
		}
		operation.draining()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			record, err := readDesktopDNSDrainRecord(launch)
			if err == nil && record.desktopDNSNativeRequest == request && record.Status.Complete && record.Status.Drained {
				return
			}
			if desktopDNSNativeClosed(launch) {
				*owner.failed = true
				return // The exact native close follows DNS worker/socket drain.
			}
			_ = writeDesktopDNSCleanupCancel(launch, request)
			<-tick.C
		}
	}()
	if err := writeDesktopDNSRequest(launch, "dns-request.json", request); err != nil {
		*owner.failed = true
		return result, err
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := operation.snapshot.current(a); err != nil {
			return result, err
		}
		record, err := readDesktopDNSRecord(launch)
		if err != nil {
			return result, err
		}
		if record.Generation == request.Generation {
			if record.desktopDNSNativeRequest != request {
				return result, errors.New("native DNS request was replaced")
			}
			operation.update(record.Status)
			if record.Status.Complete && record.Status.Drained {
				drained = true
				if err := validateDesktopDNSResults(launch, record.Status); err != nil {
					return result, err
				}
				return record.Status, operation.snapshot.current(a)
			}
		} else if record.Generation+1 != request.Generation {
			return result, errors.New("native DNS generation changed")
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-tick.C:
		}
	}
}
