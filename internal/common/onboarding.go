package common

import (
	"fmt"
	"strings"
	"time"
)

const OnboardingSchemaVersion = 1

// OnboardingState is the cross-platform persistence contract used by native
// clients and the local controller. UI implementation lives in later phases;
// this schema makes completion/re-run/progress semantics stable before that UI
// is built so upgrades do not invent incompatible per-platform state formats.
type OnboardingState struct {
	SchemaVersion  int      `json:"schema_version"`
	Completed      bool     `json:"completed"`
	CurrentStep    string   `json:"current_step,omitempty"`
	CompletedSteps []string `json:"completed_steps,omitempty"`
	StartedAt      string   `json:"started_at,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
	CompletedAt    string   `json:"completed_at,omitempty"`
	LastReopenedAt string   `json:"last_reopened_at,omitempty"`
}

var OnboardingStepOrder = []string{
	"welcome",
	"link-node",
	"select-node",
	"mode-and-base",
	"dns",
	"lan-access",
	"kill-switch",
	"multihop",
	"forwarding",
	"privacy-security",
	"native-permission",
	"first-connect",
	"public-exit-test",
	"connection-validation",
	"finish",
}

func NormalizeOnboardingState(s *OnboardingState) error {
	if s.SchemaVersion > OnboardingSchemaVersion {
		return fmt.Errorf("onboarding schema %d is newer than supported schema %d", s.SchemaVersion, OnboardingSchemaVersion)
	}
	s.SchemaVersion = OnboardingSchemaVersion
	valid := map[string]bool{}
	for _, step := range OnboardingStepOrder {
		valid[step] = true
	}
	s.CurrentStep = strings.TrimSpace(s.CurrentStep)
	if s.CurrentStep == "" && !s.Completed {
		s.CurrentStep = OnboardingStepOrder[0]
	}
	if s.CurrentStep != "" && !valid[s.CurrentStep] {
		return fmt.Errorf("unknown onboarding step %q", s.CurrentStep)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(s.CompletedSteps))
	for _, step := range s.CompletedSteps {
		step = strings.TrimSpace(step)
		if !valid[step] {
			return fmt.Errorf("unknown completed onboarding step %q", step)
		}
		if !seen[step] {
			seen[step] = true
			out = append(out, step)
		}
	}
	s.CompletedSteps = out
	return nil
}

func NewOnboardingState(now time.Time) OnboardingState {
	t := now.UTC().Format(time.RFC3339)
	return OnboardingState{
		SchemaVersion: OnboardingSchemaVersion,
		CurrentStep:   OnboardingStepOrder[0],
		StartedAt:     t,
		UpdatedAt:     t,
	}
}
