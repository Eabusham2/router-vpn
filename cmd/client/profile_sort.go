package main

import (
	"sort"
	"strings"
	"time"

	"router-vpn/internal/common"
)

// sortPublicProfileStore returns a copy of the already-redacted public store in
// a deterministic order. It never mutates the private on-disk profile store.
// Supported orders are: current, last-used, most-used, latency, and name.
func sortPublicProfileStore(store common.RouterProfileStore, order string) common.RouterProfileStore {
	out := store
	out.Profiles = append([]common.RouterProfile(nil), store.Profiles...)
	order = strings.ToLower(strings.TrimSpace(order))
	if order == "" {
		order = "current"
	}
	nameLess := func(a, b common.RouterProfile) bool {
		an, bn := strings.ToLower(strings.TrimSpace(a.Name)), strings.ToLower(strings.TrimSpace(b.Name))
		if an == bn {
			return a.ID < b.ID
		}
		return an < bn
	}
	lastUsed := func(p common.RouterProfile) time.Time {
		if strings.TrimSpace(p.LastUsedAt) == "" {
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339Nano, p.LastUsedAt)
		if err != nil {
			return time.Time{}
		}
		return t
	}
	latencyMeasured := func(p common.RouterProfile) bool {
		return savedNodeLatencyEligible(p)
	}

	sort.SliceStable(out.Profiles, func(i, j int) bool {
		a, b := out.Profiles[i], out.Profiles[j]
		switch order {
		case "name":
			return nameLess(a, b)
		case "most-used", "most_used", "usage":
			ac, bc := max(0, a.UseCount), max(0, b.UseCount)
			if ac != bc {
				return ac > bc
			}
			at, bt := lastUsed(a), lastUsed(b)
			if !at.Equal(bt) {
				return at.After(bt)
			}
			return nameLess(a, b)
		case "last-used", "last_used", "recent":
			at, bt := lastUsed(a), lastUsed(b)
			if !at.Equal(bt) {
				return at.After(bt)
			}
			if a.UseCount != b.UseCount {
				return a.UseCount > b.UseCount
			}
			return nameLess(a, b)
		case "latency", "lowest-latency", "lowest_latency":
			am, bm := latencyMeasured(a), latencyMeasured(b)
			if am != bm {
				return am
			}
			if am && a.LatencyTrimmedMeanMs != b.LatencyTrimmedMeanMs {
				return a.LatencyTrimmedMeanMs < b.LatencyTrimmedMeanMs
			}
			if am {
				return a.ID < b.ID
			}
			return nameLess(a, b)
		default: // current
			ac, bc := a.ID == out.SelectedID, b.ID == out.SelectedID
			if ac != bc {
				return ac
			}
			at, bt := lastUsed(a), lastUsed(b)
			if !at.Equal(bt) {
				return at.After(bt)
			}
			return nameLess(a, b)
		}
	})
	return out
}

func lowestLatencyProfileID(store common.RouterProfileStore) string {
	sorted := sortPublicProfileStore(store, "latency")
	for _, p := range sorted.Profiles {
		if savedNodeLatencyEligible(p) {
			return p.ID
		}
	}
	return ""
}
