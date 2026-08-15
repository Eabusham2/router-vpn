package main

import (
	"os"
	"strings"
	"testing"
)

func envValueForTest(env []string, key string) (string, int) {
	prefix := key + "="
	value := ""
	count := 0
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			value = strings.TrimPrefix(item, prefix)
			count++
		}
	}
	return value, count
}

func TestEnvWithValueReplacesStaleKillSwitchHold(t *testing.T) {
	env := []string{"A=1", killSwitchHoldEnv + "=1", "B=2", killSwitchHoldEnv + "=stale"}
	manual := envWithValue(env, killSwitchHoldEnv, "0")
	if got, count := envValueForTest(manual, killSwitchHoldEnv); got != "0" || count != 1 {
		t.Fatalf("manual stop env = %q count=%d; want 0 exactly once", got, count)
	}
	held := envWithValue(manual, killSwitchHoldEnv, "1")
	if got, count := envValueForTest(held, killSwitchHoldEnv); got != "1" || count != 1 {
		t.Fatalf("transition stop env = %q count=%d; want 1 exactly once", got, count)
	}
}

func TestStopCommandEnvMakesManualAndTransitionIntentExplicit(t *testing.T) {
	old, had := os.LookupEnv(killSwitchHoldEnv)
	_ = os.Setenv(killSwitchHoldEnv, "stale")
	defer func() {
		if had {
			_ = os.Setenv(killSwitchHoldEnv, old)
		} else {
			_ = os.Unsetenv(killSwitchHoldEnv)
		}
	}()

	a := &app{}
	if got, count := envValueForTest(a.stopCommandEnv(false), killSwitchHoldEnv); got != "0" || count != 1 {
		t.Fatalf("manual stop inherited stale HOLD: value=%q count=%d", got, count)
	}
	if got, count := envValueForTest(a.stopCommandEnv(true), killSwitchHoldEnv); got != "1" || count != 1 {
		t.Fatalf("transition stop did not hold protection: value=%q count=%d", got, count)
	}
}
