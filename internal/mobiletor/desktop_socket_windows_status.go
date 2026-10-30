//go:build windows

package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// DesktopWindowsProtectionSnapshot describes only the managed BFE objects.
// Active means a native owner or a durable baseline exists, not that a tunnel
// has passed its connection proofs. No PID, selected profile or state file is
// accepted as authority for this readback.
type DesktopWindowsProtectionSnapshot struct {
	Schema int    `json:"schema"`
	Active bool   `json:"active"`
	Policy string `json:"policy"`
	Phase  string `json:"phase"`
}

// A cancelled reader retains its one entered RPC and engine until they join.
// Repeated callers cannot accumulate unbounded native sessions while BFE is
// unavailable. Read operations never add or remove firewall objects.
var desktopWindowsProtectionReadGate = make(chan struct{}, 1)

func ReadDesktopWindowsProtection(ctx context.Context) (DesktopWindowsProtectionSnapshot, error) {
	return readDesktopWindowsProtection(ctx, nil)
}

func readDesktopWindowsProtection(ctx context.Context, fixtureScope []byte) (DesktopWindowsProtectionSnapshot, error) {
	return readDesktopWindowsProtectionRequest(ctx, fixtureScope, nil)
}

func readDesktopWindowsProtectionRequest(ctx context.Context, fixtureScope []byte, prepared *desktopWindowsPreparedCapture) (DesktopWindowsProtectionSnapshot, error) {
	var zero DesktopWindowsProtectionSnapshot
	if ctx == nil || ctx.Err() != nil {
		return zero, errors.New("Windows protection readback requires a live caller")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return zero, err
	}
	if len(fixtureScope) > 65536 || len(fixtureScope)%2 != 0 {
		return zero, errors.New("Windows protection readback has an invalid scope")
	}
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case desktopWindowsProtectionReadGate <- struct{}{}:
	}
	scope := append([]byte(nil), fixtureScope...)
	type result struct {
		snapshot DesktopWindowsProtectionSnapshot
		err      error
	}
	finished := make(chan result, 1)
	go func() {
		defer func() { <-desktopWindowsProtectionReadGate }()
		snapshot, err := desktopWindowsProtectionReadRequest(ctx, scope, prepared)
		finished <- result{snapshot, err}
	}()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case completed := <-finished:
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		return completed.snapshot, completed.err
	}
}

func desktopWindowsProtectionRead(ctx context.Context, scope []byte) (snapshot DesktopWindowsProtectionSnapshot, result error) {
	return desktopWindowsProtectionReadRequest(ctx, scope, nil)
}

func desktopWindowsProtectionReadRequest(ctx context.Context, scope []byte, prepared *desktopWindowsPreparedCapture) (snapshot DesktopWindowsProtectionSnapshot, result error) {
	engine, err := desktopWFPOpen(false)
	if engine != nil {
		defer func() { result = errors.Join(result, engine.Close()) }()
	}
	if err != nil {
		return snapshot, err
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	// FWPM_TXN_READ_ONLY takes one consistent BFE snapshot without acquiring
	// authority to mutate it. Close aborts that read transaction on every path.
	// https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
	status, _, _ := engine.api.begin.Call(uintptr(engine.handle), 1)
	if err := desktopWFPError("begin protection read transaction", status); err != nil {
		return snapshot, err
	}
	engine.transaction = true
	lockKey := desktopWindowsManagedKey("session-lock", scope)
	lock, err := engine.readSublayer(lockKey, false)
	if err != nil {
		return snapshot, err
	}
	var activeCapture DesktopSocketCapture
	if lock != nil {
		parts := strings.Split(string(lock.Metadata), "|")
		if len(parts) != 4 || parts[0] != "RouterVPN-WFP-session-lock/1" {
			return snapshot, errors.New("Windows protection session lock has an unknown owner")
		}
		activeCapture = DesktopSocketCapture{SessionID: parts[1], SourceSHA256: parts[2], NetworkID: parts[3]}
		if !activeCapture.valid() {
			return snapshot, errors.New("Windows protection session lock has an invalid captured identity")
		}
		if err := engine.AssertComplete(lockKey, nil); err != nil {
			return snapshot, err
		}
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	baseline, err := desktopWindowsReadBaseline(engine, desktopWindowsManagedKey("baseline", scope), scope)
	if err != nil {
		return snapshot, err
	}
	if prepared != nil {
		// A handoff may retire only its old protection while this exact new
		// native owner has a complete deny baseline and no active socket or
		// TUN permits. A retained, preparing, changed or unknown state is not
		// evidence of this barrier, even if ordinary status says Active.
		if lock == nil || baseline == nil || activeCapture != prepared.capture || baseline.capture != prepared.capture ||
			baseline.options.KillSwitchPolicy != prepared.policy {
			return snapshot, errors.New("Windows prepared protection differs from the captured handoff owner")
		}
		digest := sha256.Sum256(baseline.metadata)
		if hex.EncodeToString(digest[:]) != prepared.baselineSHA256 {
			return snapshot, errors.New("Windows prepared protection changed its complete captured baseline")
		}
		if err := engine.AssertComplete(baseline.sublayer, baseline.baseline); err != nil {
			return snapshot, err
		}
	}
	snapshot = DesktopWindowsProtectionSnapshot{Schema: 1, Policy: "off", Phase: "off"}
	if baseline == nil {
		if lock != nil {
			snapshot.Active, snapshot.Policy, snapshot.Phase = true, "", "preparing"
		}
		return snapshot, nil
	}
	snapshot.Active, snapshot.Policy = true, baseline.options.KillSwitchPolicy
	if lock == nil {
		if err := engine.AssertComplete(baseline.sublayer, baseline.baseline); err != nil {
			return DesktopWindowsProtectionSnapshot{}, err
		}
		snapshot.Phase = "retained"
	} else if activeCapture == baseline.capture {
		snapshot.Phase = "owned"
	} else {
		snapshot.Phase = "transition"
	}
	return snapshot, nil
}
