//go:build linux

package main

import (
	"fmt"
	"testing"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
)

func TestLinuxStandardMTUCapacityPreservesWholeRetestAndRollback(t *testing.T) {
	if linuxStandardMTURetestCapacity != mobilemtu.MaxCandidates+2 || linuxStandardMTURetestCapacity > standardengine.OperationTransactions {
		t.Fatal("original optimizer and rollback do not fit native retained history")
	}
	for _, scenario := range []struct {
		name      string
		sequence  uint64
		seen      int
		exhausted bool
		remaining int
		admit     bool
	}{
		{"fresh", 0, 0, false, 32, true},
		{"whole-test", 25, 25, false, 7, true},
		{"rollback-reserve", 26, 26, false, 6, false},
		{"unsent-history", 1, 26, false, 6, false},
		{"exhausted", 2, 2, true, 0, false},
		{"full", 32, 32, false, 0, false},
		{"sequence-overflow", ^uint64(0), 0, false, 0, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			m := &linuxStandardServiceMTU{sequence: scenario.sequence, exhausted: scenario.exhausted, seen: make(map[string]struct{})}
			for i := 0; i < scenario.seen; i++ {
				m.seen[fmt.Sprintf("%032x", i)] = struct{}{}
			}
			remaining := m.remaining()
			if remaining != scenario.remaining || (validateLinuxStandardMTURetestCapacity(remaining) == nil) != scenario.admit {
				t.Fatal("Retest consumed the original rollback reserve", remaining)
			}
			if m.sequence != scenario.sequence || len(m.seen) != scenario.seen || m.exhausted != scenario.exhausted {
				t.Fatal("capacity observation changed retained history")
			}
		})
	}
	if validateLinuxStandardMTURetestCapacity(-1) == nil || validateLinuxStandardMTURetestCapacity(standardengine.OperationTransactions+1) == nil {
		t.Fatal("unbounded service capacity accepted")
	}
}
