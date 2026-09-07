package main

import (
	"errors"
	"sync"
)

// Current-path measurements must not own the VPN connection mutation lock:
// Disconnect must remain available while HTTP traffic is in flight. Give Speed
// Lab its own per-app owner so two callers cannot saturate the same path and
// misreport each other's throughput or loaded latency. The owner remains held
// through temporary-path cleanup and response delivery.
var speedLabRunOwners sync.Map // map[*app]*sync.Once

func beginSpeedLabRun(a *app) (func(), error) {
	if a == nil {
		return nil, errors.New("Speed Lab requires an app owner")
	}
	owner := new(sync.Once)
	if _, loaded := speedLabRunOwners.LoadOrStore(a, owner); loaded {
		return nil, errors.New("a Speed Lab test is already running; wait for it to finish or cancel it first")
	}
	return func() {
		owner.Do(func() { speedLabRunOwners.CompareAndDelete(a, owner) })
	}, nil
}
