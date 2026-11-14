package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// Native observers retain their ordinary process/protection/TUN checks, then
// dispatch only the additional proof record to its original concrete family.
func readDesktopNodeChainNativeReadyContext(ctx context.Context, launch *desktopNodeLaunch, transfer string, started time.Time, fresh bool, live desktopNodeMTURecord) error {
	if launch != nil && launch.chain != nil && launch.chain.execution != nil {
		_, err := launch.chain.execution.readReadyContext(ctx, launch, transfer, started, fresh, live)
		return err
	}
	_, err := readDesktopNodeChainReadyContext(ctx, launch, transfer, started, fresh, live)
	return err
}

// Call only inside the existing native process/protection guard. Adoption is
// pinned once; equal policy bytes from a different Box/network cannot replace
// that identity. The MTU service still identifies the preparation config,
// while the execution heartbeat identifies the actual adopted graph.
func (e *desktopNodeChainExecutionLaunch) readReadyContext(ctx context.Context, launch *desktopNodeLaunch, transfer string, started time.Time, fresh bool, live desktopNodeMTURecord) (mobilemultihop.DesktopNodeChainExecutionReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeChainExecutionReadyRecord
	if ctx == nil || ctx.Err() != nil || e.bound(launch) != nil {
		return empty, errors.New("execution readiness lost original caller or launch")
	}
	if err := desktopnetwork.LockContext(ctx, &e.mu); err != nil {
		return empty, err
	}
	defer e.mu.Unlock()
	if !e.started.IsZero() && e.started != started {
		return empty, errors.New("execution readiness replaced its original process start")
	}
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-execution-adoption.json", mobilemultihop.DesktopNodeChainExecutionAdoptionRecordLimit)
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	projection, identity := e.projection, e.identity
	if projection == nil {
		if !fresh || e.ready != nil || e.adoption != "" {
			return empty, errors.New("execution adoption preceded its original fresh native observation")
		}
		projection, identity, err = mobilemultihop.ParseDesktopNodeChainExecutionAdoptionRecord(raw, e.preparation, transfer)
		if err != nil {
			return empty, err
		}
	} else if string(raw) != e.adoption {
		return empty, errors.New("execution adoption replaced its original captured proposal")
	}
	physical, err := projection.DesktopPhysicalPolicy()
	if err != nil || physical != e.physical {
		return empty, errors.New("execution adoption replaced its retained preparation owner")
	}
	heartbeat, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-execution-ready.json", mobilemultihop.DesktopNodeChainExecutionReadyRecordLimit)
	if err != nil {
		return empty, err
	}
	defer clear(heartbeat)
	record, err := mobilemultihop.ParseDesktopNodeChainExecutionAdoptedReadyRecord(heartbeat, projection, identity, transfer)
	if err != nil {
		return empty, err
	}
	if err := validateDesktopNodeChainExecutionReady(record, live, started, time.Now(), e.ready, fresh, e.original.policy.Metadata().TargetOS); err != nil {
		return empty, err
	}
	if !desktopMTUPathPattern.MatchString(live.Path) || e.mtuPath != "" && e.mtuPath != live.Path {
		return empty, errors.New("execution readiness changed its original MTU path")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	// Detach nested comparison/proof slices before returning data to callers.
	var retained mobilemultihop.DesktopNodeChainExecutionReadyRecord
	if json.Unmarshal(heartbeat, &retained) != nil {
		return empty, errors.New("execution heartbeat could not be retained")
	}
	e.projection, e.identity, e.adoption, e.ready, e.mtuPath = projection, identity, string(raw), &retained, live.Path
	if e.started.IsZero() {
		e.started = started
	}
	return record, nil
}

func validateDesktopNodeChainExecutionReady(record mobilemultihop.DesktopNodeChainExecutionReadyRecord, live desktopNodeMTURecord, started, now time.Time, captured *mobilemultihop.DesktopNodeChainExecutionReadyRecord, fresh bool, target string) error {
	bad := errors.New("execution readiness lost original proof, selection epoch or native MTU reader")
	if !desktopExecutionReadyInterface(target, record.InterfaceName) || started.IsZero() || record.ObservedAt < started.UnixMilli() || record.ObservedAt > now.UnixMilli() || now.UnixMilli()-record.ObservedAt > 2000 ||
		live.Session != record.Identity.SessionID || live.Config != record.PreparationConfigSHA256 || live.Reader != record.Reader ||
		live.Interface != record.InterfaceName || live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU ||
		live.Failure != "" && !(live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored") {
		return bad
	}
	if captured == nil {
		if !fresh || record.Generation != 1 || record.Reader != 1 || record.SelectionEpoch == 0 || live.Active || live.Generation != 0 || live.Request != "" || live.Lease != "" || live.Restored || live.Expired || live.Failure != "" {
			return bad
		}
		return nil
	}
	if record.Identity != captured.Identity || record.SourceSHA256 != captured.SourceSHA256 || record.TransferSHA256 != captured.TransferSHA256 ||
		record.PreparationSourceSHA256 != captured.PreparationSourceSHA256 || record.PreparationConfigSHA256 != captured.PreparationConfigSHA256 ||
		record.DNSConfigSHA256 != captured.DNSConfigSHA256 || record.ObservedAt < captured.ObservedAt || record.Reader < captured.Reader ||
		record.Generation < captured.Generation || record.SelectionEpoch < captured.SelectionEpoch ||
		(record.InterfaceName != captured.InterfaceName && (target != "darwin" || record.Reader <= captured.Reader)) ||
		record.Progress.Execution != captured.Progress.Execution || record.Progress.Comparison.Target != captured.Progress.Comparison.Target ||
		record.Progress.Comparison.Winner == nil || captured.Progress.Comparison.Winner == nil || *record.Progress.Comparison.Winner != *captured.Progress.Comparison.Winner {
		return bad
	}
	if record.Reader == captured.Reader {
		if record.Generation != captured.Generation || record.SelectionEpoch != captured.SelectionEpoch || record.InterfaceIndex != captured.InterfaceIndex || record.MTU != captured.MTU {
			return bad
		}
	} else if fresh || record.Generation <= captured.Generation || record.Generation-captured.Generation != record.Reader-captured.Reader {
		return bad
	}
	return nil
}

// The native Darwin owner must separately prove the old utun is gone and the
// successor's exact index/MTU/up state before this source-bound record check.
func desktopExecutionReadyInterface(target, name string) bool {
	switch target {
	case "linux", "windows":
		return name == "router-vpn"
	case "darwin":
		unit, found := strings.CutPrefix(name, "utun")
		if !found || unit == "" {
			return false
		}
		for _, digit := range unit {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		return true
	default:
		return false
	}
}
