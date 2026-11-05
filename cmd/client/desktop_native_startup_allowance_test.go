package main

import (
	"context"
	"testing"
	"time"
)

func TestDesktopNativeStartupUsesAcceptedHostAllowance(t *testing.T) {
	for _, kind := range []string{"external", "tor"} {
		t.Run(kind, func(t *testing.T) {
			launch := startupContextLaunch(kind)
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget := 180 * time.Second
			if kind == "tor" {
				budget = 150 * time.Second
			}
			before := time.Now()
			work, err := captureDesktopNativeStartup(operation, launch)
			after := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			defer launch.startup.Load().stop()
			deadline, ok := work.Deadline()
			if !ok || deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) {
				t.Fatal("accepted host changed its existing startup allowance", deadline)
			}
			borrowed, stop, err := desktopNativeStartupObservation(context.Background(), launch)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			observed, _ := borrowed.Deadline()
			if !observed.Equal(deadline) {
				t.Fatal("proof observation restarted host allowance")
			}
		})
	}
}
