package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type externalSelectionKey struct{}

type externalSelectionEngine struct {
	*externalExecutionEngine
	selectOwned func(context.Context, string) error
	legacy      atomic.Int32
}

func (e *externalSelectionEngine) Select(string) error {
	e.legacy.Add(1)
	return errors.New("legacy selection must not admit an external mutation")
}
func (e *externalSelectionEngine) SelectContext(ctx context.Context, tag string) error {
	return e.selectOwned(ctx, tag)
}

// Hide only the mutation capability, retaining all existing proof and read
// capabilities. Refusal must not silently fall back to the legacy mutation.
type externalSelectionWithoutContext struct {
	Engine
	ExternalProofEngine
}

func (e *externalSelectionWithoutContext) Identity() string { return e.Engine.Identity() }
func (e *externalSelectionWithoutContext) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	return e.Engine.Dial(ctx, tag, address)
}
func (e *externalSelectionWithoutContext) IdentityContext(ctx context.Context) (string, error) {
	return externalObservedIdentity(ctx, e.Engine)
}
func (e *externalSelectionWithoutContext) SelectedContext(ctx context.Context) (string, error) {
	return externalObservedSelection(ctx, e.Engine)
}

func TestExternalSelectionKeepsOriginalTrialAndFinalCaller(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public"}
	defer func() { Targets = previous }()
	for _, phase := range []string{"current", "nil", "cancel-before", "trial-cancel", "trial-owner", "trial-late-success", "final-cancel", "final-owner", "final-late-success", "missing-context"} {
		t.Run(phase, func(t *testing.T) {
			request, native := externalExecutionRequest(t, "server", "")
			parent, cancel := context.WithTimeout(context.WithValue(context.Background(), externalSelectionKey{}, phase), 5*time.Second)
			defer cancel()
			engine := &externalSelectionEngine{externalExecutionEngine: native}
			var calls int
			engine.selectOwned = func(ctx context.Context, tag string) error {
				calls++
				deadline, ok := ctx.Deadline()
				original, _ := parent.Deadline()
				if ctx.Value(externalSelectionKey{}) != phase || !ok || deadline.After(original) || tag != ServerTag {
					return errors.New("selection discarded original values, deadline or candidate")
				}
				stage := "trial"
				if calls == 2 {
					stage = "final"
				}
				if strings.HasPrefix(phase, stage+"-") {
					if phase == stage+"-owner" {
						native.mu.Lock()
						native.identity = "replacement-native-owner"
						native.mu.Unlock()
					} else {
						cancel()
					}
					// A badly behaved native result cannot publish success after
					// its original caller/owner changed, even without an error.
					if strings.HasSuffix(phase, "late-success") || strings.HasSuffix(phase, "owner") {
						return nil
					}
				}
				return native.SelectContext(ctx, tag)
			}
			request.engine = engine
			if phase == "missing-context" {
				request.engine = &externalSelectionWithoutContext{Engine: engine, ExternalProofEngine: engine}
			}
			caller := context.Context(parent)
			if phase == "nil" {
				caller = nil
			}
			if phase == "cancel-before" {
				cancel()
			}
			raw, err := request.RunContext(caller, nil)
			if phase == "current" {
				if err != nil || raw == "" || calls != 2 || !request.Healthy() || request.Execution() != "server" {
					t.Fatal("original selection did not retain proved server result", calls, err)
				}
			} else {
				if err == nil || raw != "" || request.Healthy() || request.Execution() != "" {
					t.Fatal("cancelled or replaced selection published retained proof", calls, err)
				}
				var progress Progress
				if json.Unmarshal([]byte(request.execution.ProgressJSON()), &progress) != nil {
					t.Fatal("invalid progress")
				}
				if strings.HasPrefix(phase, "trial-") && len(progress.Measurements) != 0 {
					t.Fatal("cancelled trial manufactured a candidate score", progress)
				}
			}
			if engine.legacy.Load() != 0 {
				t.Fatal("external trial or final used legacy selection")
			}
		})
	}
}

func TestExternalSelectionCancellationJoinsEnteredCommit(t *testing.T) {
	request, native := externalExecutionRequest(t, "server", "")
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var committed atomic.Int32
	engine := &externalSelectionEngine{externalExecutionEngine: native}
	engine.selectOwned = func(ctx context.Context, tag string) error {
		close(entered)
		<-ctx.Done()
		<-release // Models an already-entered native persistence/Close commit.
		committed.Add(1)
		return nil
	}
	request.engine = engine
	ran := make(chan error, 1)
	go func() { _, err := request.RunContext(parent, nil); ran <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("selection did not enter original commit")
	}
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- request.Close() }()
	select {
	case <-ran:
		close(release)
		t.Fatal("proof detached entered selection commit")
	case <-closed:
		close(release)
		t.Fatal("close detached entered selection commit")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-ran:
		if err == nil {
			t.Fatal("late selection success defeated cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("proof did not join original commit")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not join original commit")
	}
	if committed.Load() != 1 || request.Healthy() || request.Execution() != "" || engine.legacy.Load() != 0 {
		t.Fatal("joined cancellation retained a selected proof or repeated its mutation")
	}
}
