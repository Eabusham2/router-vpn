package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func (c *controller) rollbackComposePath() string {
	return c.statePath + ".rollback-compose"
}

func (c *controller) saveRollbackCompose(previous, from string) error {
	from = strings.TrimSpace(from)
	if !shaRE.MatchString(from) {
		return fmt.Errorf("previous Portainer stack does not resolve to one exact SHA: %q", from)
	}
	if len(previous) == 0 || len(previous) > maxCompose {
		return errors.New("previous Portainer compose is empty or oversized")
	}
	if actual := composeSHA(previous); actual != from {
		return fmt.Errorf("previous compose identity changed while snapshotting: got %s want %s", actual, from)
	}
	// A terminal prior update may have left a validated snapshot behind only
	// because cleanup failed after the terminal state was durably committed.
	// Clear it before publishing the new transaction's snapshot. Unsafe/broad/
	// symlink leftovers fail closed here, before any Portainer mutation begins.
	if err := c.clearRollbackCompose(); err != nil {
		return fmt.Errorf("clear stale rollback snapshot before new update: %w", err)
	}
	if err := atomicWriteUpdaterPrivate(c.rollbackComposePath(), []byte(previous)); err != nil {
		return fmt.Errorf("persist previous exact compose snapshot: %w", err)
	}
	return nil
}

func (c *controller) loadRollbackCompose(expected string) (string, error) {
	expected = strings.TrimSpace(expected)
	if !shaRE.MatchString(expected) {
		return "", fmt.Errorf("rollback requires an exact previous SHA, got %q", expected)
	}
	body, err := readUpdaterPrivate(c.rollbackComposePath(), maxCompose)
	if err != nil {
		return "", fmt.Errorf("read previous exact compose snapshot: %w", err)
	}
	previous := string(body)
	if len(previous) == 0 || len(previous) > maxCompose {
		return "", errors.New("previous exact compose snapshot is empty or oversized")
	}
	if actual := composeSHA(previous); actual != expected {
		return "", fmt.Errorf("rollback snapshot exact-SHA mismatch: got %s want %s", actual, expected)
	}
	return previous, nil
}

func (c *controller) clearRollbackCompose() error {
	path := c.rollbackComposePath()
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := validateUpdaterPrivateFile(path, maxCompose); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func (c *controller) persistRecoveryState(status, from, target, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persistStateLocked(status, from, target, message)
}

// restorePreviousStack is the only path that may declare rollback complete. It
// reloads the private exact compose snapshot, asks Portainer to restore it,
// waits for the full core health contract, and finally proves Portainer now
// reports the exact prior SHA again.
func (c *controller) restorePreviousStack(stack stackInfo, from string, timeout time.Duration) error {
	previous, err := c.loadRollbackCompose(from)
	if err != nil {
		return err
	}
	if err := c.putStack(stack, previous); err != nil {
		return fmt.Errorf("restore previous Portainer stack: %w", err)
	}
	if err := c.waitCoreHealthy(stack, timeout); err != nil {
		return fmt.Errorf("restored stack failed health verification: %w", err)
	}
	current, err := c.stackFile(stack)
	if err != nil {
		return fmt.Errorf("read restored Portainer stack identity: %w", err)
	}
	if actual := composeSHA(current); actual != from {
		return fmt.Errorf("rollback health passed but Portainer compose is %s, expected %s", actual, from)
	}
	return nil
}

// rollbackAfterDeploymentFailure is used after a Portainer mutation may have
// started. Terminal failed is written only after the exact prior stack is back,
// healthy, and identity-proved. If restoration fails, durable status remains
// rolling-back so a restarted controller retries recovery.
func (c *controller) rollbackAfterDeploymentFailure(stack stackInfo, from, target string, cause error) error {
	message := cause.Error()
	stateErr := c.persistRecoveryState("rolling-back", from, target, message)
	rollbackErr := c.restorePreviousStack(stack, from, 120*time.Second)
	if rollbackErr != nil {
		recoveryMessage := fmt.Sprintf("target failed (%v); rollback remains incomplete (%v)", cause, rollbackErr)
		if stateErr != nil {
			recoveryMessage += fmt.Sprintf("; rolling-back state persistence failed (%v)", stateErr)
		}
		if err := c.persistRecoveryState("rolling-back", from, target, recoveryMessage); err != nil {
			recoveryMessage += fmt.Sprintf("; recovery-state refresh failed (%v)", err)
		}
		return errors.New(recoveryMessage)
	}
	terminal := fmt.Errorf("target failed and prior exact stack %s was restored and health-verified: %w", from, cause)
	if stateErr != nil {
		terminal = fmt.Errorf("%v; initial rolling-back state persistence failed (%v)", terminal, stateErr)
	}
	if err := c.persistRecoveryState("failed", from, target, terminal.Error()); err != nil {
		return fmt.Errorf("%v; prior stack is restored but terminal failed state could not be persisted: %w", terminal, err)
	}
	if err := c.clearRollbackCompose(); err != nil {
		// A stale validated private snapshot is safe to retain. Do not turn a
		// proven rollback into a false failure merely because cleanup failed.
		return fmt.Errorf("%v; rollback snapshot cleanup deferred: %w", terminal, err)
	}
	return terminal
}

func (c *controller) completeRecoveredUpdate(state updateState, message string) error {
	if err := c.persistRecoveryState("complete", state.FromSHA, state.TargetSHA, message); err != nil {
		return err
	}
	if err := c.clearRollbackCompose(); err != nil {
		return fmt.Errorf("update is complete but rollback snapshot cleanup failed: %w", err)
	}
	return nil
}

// reconcileRecovery is intentionally conservative. Any interrupted applying
// state with a captured prior SHA is restored unconditionally; an interrupted
// finalizing state is accepted only when Portainer is already one exact target
// SHA and the full health contract succeeds. Otherwise it rolls back.
func (c *controller) reconcileRecovery() error {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	if state.Status == "idle" || state.Status == "complete" || state.Status == "failed" {
		return nil
	}

	if state.Status == "applying" && state.FromSHA == "" {
		// The first applying checkpoint is written before stack discovery or any
		// Portainer PUT. An empty from_sha therefore proves deployment had not
		// reached the mutation boundary, so Portainer configuration is not needed
		// to close this interrupted transaction truthfully.
		return c.persistRecoveryState("failed", "", state.TargetSHA, "update controller restarted before Portainer deployment began")
	}

	configured, reason := c.configured()
	if !configured {
		return fmt.Errorf("cannot reconcile %s update: %s", state.Status, reason)
	}
	if !shaRE.MatchString(state.FromSHA) || !shaRE.MatchString(state.TargetSHA) {
		return errors.New("interrupted update state lacks exact rollback/target identity")
	}
	stack, err := c.findStack()
	if err != nil {
		return err
	}

	if state.Status == "finalizing" {
		current, err := c.stackFile(stack)
		if err == nil && composeSHA(current) == state.TargetSHA {
			if healthErr := c.waitCoreHealthy(stack, 60*time.Second); healthErr == nil {
				return c.completeRecoveredUpdate(state, "exact-SHA update completed after update-controller restart")
			}
		}
		return c.rollbackAfterDeploymentFailure(stack, state.FromSHA, state.TargetSHA, errors.New("finalizing update could not prove one healthy exact target after restart"))
	}

	if state.Status == "applying" || state.Status == "rolling-back" {
		return c.rollbackAfterDeploymentFailure(stack, state.FromSHA, state.TargetSHA, fmt.Errorf("update controller restarted during %s", state.Status))
	}
	return fmt.Errorf("unsupported interrupted update status %q", state.Status)
}
