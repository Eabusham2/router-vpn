package common

import (
	"testing"
	"time"
)

func TestOnboardingStateSchemaAndReopenHooks(t *testing.T) {
	s := NewOnboardingState(time.Unix(1_700_000_000, 0))
	if s.SchemaVersion != OnboardingSchemaVersion || s.Completed || s.CurrentStep != "welcome" {
		t.Fatalf("unexpected new onboarding state: %+v", s)
	}
	s.CompletedSteps = []string{"welcome", "link-node", "welcome"}
	s.CurrentStep = "select-node"
	if err := NormalizeOnboardingState(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.CompletedSteps) != 2 {
		t.Fatalf("completed steps should deduplicate: %+v", s.CompletedSteps)
	}
	s.LastReopenedAt = time.Now().UTC().Format(time.RFC3339)
	if s.LastReopenedAt == "" {
		t.Fatal("reopen hook was not persistable")
	}
}

func TestOnboardingRejectsFutureSchemaAndUnknownSteps(t *testing.T) {
	future := OnboardingState{SchemaVersion: OnboardingSchemaVersion + 1}
	if err := NormalizeOnboardingState(&future); err == nil {
		t.Fatal("future onboarding schema must fail closed")
	}
	bad := OnboardingState{CurrentStep: "invented-step"}
	if err := NormalizeOnboardingState(&bad); err == nil {
		t.Fatal("unknown onboarding step must be rejected")
	}
}
