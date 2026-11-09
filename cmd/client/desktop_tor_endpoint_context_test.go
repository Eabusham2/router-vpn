package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopTorEndpointLookupRetainsNetworkAndFailureCause(t *testing.T) {
	for _, scenario := range []string{"live", "replacement", "empty-network", "before-error", "lookup-error", "after-error", "cancel-before", "cancel-lookup", "cancel-after"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("exact endpoint observation failed")
			address := netip.MustParseAddr("198.51.100.9")
			reads, lookups := 0, 0
			var lookupContext context.Context
			read := func(call context.Context) (string, error) {
				reads++
				if reads == 1 && call != ctx || reads == 2 && call != lookupContext {
					t.Fatal("network observer substituted its original caller or remaining lookup allowance")
				}
				if reads == 1 && scenario == "before-error" || reads == 2 && scenario == "after-error" {
					return "", cause
				}
				if reads == 1 && scenario == "cancel-before" || reads == 2 && scenario == "cancel-after" {
					cancel() // A late successful callback still cannot publish.
				}
				if reads == 1 && scenario == "empty-network" {
					return "", nil
				}
				if reads == 2 && scenario == "replacement" {
					return "replacement physical network", nil
				}
				return "original physical network", nil
			}
			lookup := func(call context.Context, network, host string) ([]netip.Addr, error) {
				lookups++
				lookupContext = call
				if network != "ip" || host != "entry.example.test" || reads != 1 {
					t.Fatal("resolver lost its captured endpoint or preceding physical observation")
				}
				if scenario == "lookup-error" {
					return nil, cause
				}
				if scenario == "cancel-lookup" {
					cancel()
				}
				return []netip.Addr{address}, nil
			}
			got, err := desktopTorEndpointLookupObserved(ctx, "entry.example.test", read, lookup)
			if scenario == "live" {
				if err != nil || len(got) != 1 || got[0] != address || reads != 2 || lookups != 1 {
					t.Fatal("valid endpoint did not retain its original network", got, err, reads, lookups)
				}
				return
			}
			if len(got) != 0 || err == nil {
				t.Fatal("failed, replaced or cancelled observation published an endpoint", got, err)
			}
			if strings.HasSuffix(scenario, "-error") && !errors.Is(err, cause) {
				t.Fatal("endpoint observation lost its real error cause", err)
			}
			if strings.HasPrefix(scenario, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("late endpoint completion hid original cancellation", err)
			}
			if (scenario == "before-error" || scenario == "cancel-before" || scenario == "empty-network") && lookups != 0 {
				t.Fatal("rejected initial network still performed endpoint bootstrap")
			}
			if (scenario == "lookup-error" || scenario == "cancel-lookup") && reads != 1 {
				t.Fatal("rejected resolver result began another network observation")
			}
		})
	}
}

func TestDesktopTorEndpointLookupCancellationJoinsEachObserver(t *testing.T) {
	for _, phase := range []string{"before-network", "resolver", "after-network"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered := make(chan struct{})
				done := make(chan error, 1)
				reads, lookups := 0, 0
				wait := func(call context.Context) error {
					close(entered)
					<-call.Done()
					return call.Err()
				}
				read := func(call context.Context) (string, error) {
					reads++
					if reads == 1 && phase == "before-network" || reads == 2 && phase == "after-network" {
						return "", wait(call)
					}
					return "original physical network", nil
				}
				lookup := func(call context.Context, _, _ string) ([]netip.Addr, error) {
					lookups++
					if phase == "resolver" {
						return nil, wait(call)
					}
					return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
				}
				go func() {
					addresses, err := desktopTorEndpointLookupObserved(ctx, "entry.example.test", read, lookup)
					if len(addresses) != 0 {
						err = errors.New("cancelled observer published addresses")
					}
					done <- err
				}()
				select {
				case <-entered:
				case err := <-done:
					t.Fatal("endpoint bootstrap did not enter its captured observer", err)
				}
				synctest.Wait() // Cancellation follows an observed blocked call.
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("entered observer outlived or lost its original cancellation", err)
				}
				if phase == "before-network" && (reads != 1 || lookups != 0) || phase == "resolver" && (reads != 1 || lookups != 1) || phase == "after-network" && (reads != 2 || lookups != 1) {
					t.Fatal("cancelled observer continued to another phase", reads, lookups)
				}
			})
		})
	}
}

func TestDesktopTorEndpointLookupFinalReadKeepsOriginalBudget(t *testing.T) {
	for _, originalBudget := range []time.Duration{5 * time.Second, 40 * time.Second} {
		t.Run(originalBudget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), originalBudget)
				defer cancel()
				reads := 0
				var lookupContext context.Context
				read := func(call context.Context) (string, error) {
					reads++
					if reads == 1 {
						if call != ctx {
							t.Fatal("initial network read replaced the original operation")
						}
						time.Sleep(time.Second)
						return "original physical network", nil
					}
					if call != lookupContext {
						t.Fatal("final network read renewed the resolver's remaining allowance")
					}
					<-call.Done()
					return "", call.Err()
				}
				lookup := func(call context.Context, _, _ string) ([]netip.Addr, error) {
					lookupContext = call
					time.Sleep(3 * time.Second)
					return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
				}
				addresses, err := desktopTorEndpointLookupObserved(ctx, "entry.example.test", read, lookup)
				want := min(originalBudget, 11*time.Second) // One second before the existing ten-second resolver budget.
				if len(addresses) != 0 || !errors.Is(err, context.DeadlineExceeded) || reads != 2 || time.Since(started) != want {
					t.Fatal("final observation renewed or lost the original bounded allowance", addresses, err, reads, time.Since(started), want)
				}
			})
		})
	}
}

func TestDesktopTorEndpointLookupShippingKeepsRealContextualObservers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if addresses, err := desktopTorEndpointLookup(ctx, "entry.example.test"); len(addresses) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("shipping bootstrap lost pre-existing caller cancellation", addresses, err)
	}
	source := sourceFunctionForTest(t, "desktop_tor_predecessor_external.go", "func desktopTorEndpointLookup(")
	if !strings.Contains(source, "desktopTorEndpointLookupObserved(ctx, host, physicalNetworkIdentityContext, net.DefaultResolver.LookupNetIP)") {
		t.Fatal("shipping endpoint bootstrap replaced its real contextual network or resolver observer")
	}
}
