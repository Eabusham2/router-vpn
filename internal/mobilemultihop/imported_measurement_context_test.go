package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type importedConstructorHop struct {
	observe func(context.Context) (string, error)
	reads   atomic.Int32
	legacy  atomic.Int32
}

func (e *importedConstructorHop) Identity() string {
	e.legacy.Add(1)
	return "detached-constructor"
}
func (e *importedConstructorHop) IdentityContext(ctx context.Context) (string, error) {
	e.reads.Add(1)
	return e.observe(ctx)
}
func (*importedConstructorHop) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("constructor does not own a traffic operation")
}

// Successful proof is an explicit model here. The real imported compiler,
// controller health checks, measurement constructor and caller lifetimes run.
func importedConstructorOwner(t *testing.T) (*Controller, *importedBoundedEngine) {
	t.Helper()
	config, capture, files, profile := importedEntryFixture(t, "", "")
	owner, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
	if err != nil {
		t.Fatal(err)
	}
	engine := &importedBoundedEngine{importedProofEngine: &importedProofEngine{id: "original-constructor", selected: LocalTag}}
	owner.engine, owner.engineID = engine, engine.id
	owner.progress = Progress{Complete: true, Stage: "selected", Execution: "local"}
	return owner, engine
}

func TestImportedHopLegacyConstructorKeepsOneObservationBudget(t *testing.T) {
	owner, native := importedConstructorOwner(t)
	var original context.Context
	input := &importedConstructorHop{observe: func(ctx context.Context) (string, error) {
		if original == nil {
			original = ctx
		}
		if ctx != original {
			return "", errors.New("imported constructor replaced its original observation context")
		}
		return native.id + ":" + LocalTag, ctx.Err()
	}}
	service, err := owner.NewImportedHopMeasurement(input)
	if err != nil || service == nil {
		t.Fatal("imported constructor restarted its original observation budget", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if input.reads.Load() != 3 || input.legacy.Load() != 0 {
		t.Fatal("constructor omitted its capture, recheck or service identity")
	}
}

var _ hopmeasure.ContextEngine = (*importedConstructorHop)(nil)

func TestImportedHopConstructorRetainsCallerAndOwner(t *testing.T) {
	for _, phase := range []string{"current", "nil", "cancel-before", "health", "capture", "recheck", "service", "hop-replaced", "controller-replaced"} {
		t.Run(phase, func(t *testing.T) {
			owner, native := importedConstructorOwner(t)
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), struct{}{}, phase))
			defer cancel()
			entered := make(chan struct{})
			var healthReads atomic.Int32
			native.observe = func(observed context.Context) (string, error) {
				healthReads.Add(1)
				if observed != ctx {
					return "", errors.New("health replaced the constructor caller")
				}
				if phase == "health" {
					close(entered)
					<-observed.Done()
				}
				return native.id, nil
			}
			input := &importedConstructorHop{}
			originalID := native.id + ":" + LocalTag
			input.observe = func(observed context.Context) (string, error) {
				if observed != ctx {
					return "", errors.New("identity replaced the constructor caller")
				}
				count := input.reads.Load()
				if phase == "capture" && count == 1 || phase == "recheck" && count == 2 || phase == "service" && count == 3 {
					close(entered)
					<-observed.Done()
				}
				if count == 3 {
					switch phase {
					case "hop-replaced":
						return "replacement:" + LocalTag, nil
					case "controller-replaced":
						native.id = "replacement"
					}
				}
				return originalID, nil // Late success must not defeat the original cancellation.
			}
			if phase == "cancel-before" {
				cancel()
			}
			type outcome struct {
				service *hopmeasure.Service
				err     error
			}
			done := make(chan outcome, 1)
			go func() {
				caller := context.Context(ctx)
				if phase == "nil" {
					caller = nil
				}
				service, err := owner.NewImportedHopMeasurementContext(caller, input)
				done <- outcome{service, err}
			}()
			blocked := phase == "health" || phase == "capture" || phase == "recheck" || phase == "service"
			if blocked {
				select {
				case <-entered:
					cancel()
				case actual := <-done:
					t.Fatal("constructor bypassed its retained observation", actual.err)
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("constructor did not enter its bounded original observation")
				}
			}
			var actual outcome
			select {
			case actual = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("constructor observation did not join its original caller")
			}
			if phase == "current" {
				if actual.err != nil || actual.service == nil || input.reads.Load() != 3 {
					t.Fatal("constructor did not retain every original read", actual.err)
				}
				cancel()
				// Service operations use their own new caller after construction.
				native.observe = nil
				input.observe = func(observed context.Context) (string, error) { return originalID, observed.Err() }
				request := strings.Repeat("a", 32)
				if err := actual.service.Start(request, 65536); err != nil {
					t.Fatal("constructor cancellation retired its returned measurement", err)
				}
				actual.service.Cancel(request)
				if err := actual.service.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if actual.service != nil {
					_ = actual.service.Close()
				}
				if actual.err == nil || actual.service != nil {
					t.Fatal("constructor retained a cancelled or replaced original owner")
				}
				if (blocked || phase == "cancel-before") && !errors.Is(actual.err, context.Canceled) {
					t.Fatal("constructor lost its original cancellation", actual.err)
				}
			}
			if (phase == "nil" || phase == "cancel-before") && (healthReads.Load() != 0 || input.reads.Load() != 0) {
				t.Fatal("expired constructor admitted an observation")
			}
			if owner.generation.Load() != 1 || input.legacy.Load() != 0 || native.legacy.Load() != 0 {
				t.Fatal("constructor cancellation touched legacy reads or retired replacement authority")
			}
		})
	}
}
