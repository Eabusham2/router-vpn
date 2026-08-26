package main

import (
	"fmt"
	"time"
)

// recordProfileUsageLocked updates non-authoritative ranking hints without ever
// leaving RAM ahead of disk. The caller already owns a.mu. A persistence failure
// deliberately does not change connection truth; it restores only the profile
// metadata mutation and reports the error for bounded logging.
func (a *app) recordProfileUsageLocked(profileID string, usedAt time.Time) error {
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != profileID {
			continue
		}
		previous := a.profiles.Profiles[i]
		a.profiles.Profiles[i].UseCount++
		a.profiles.Profiles[i].LastUsedAt = usedAt.UTC().Format(time.RFC3339)
		if err := a.persistProfilesLocked(); err != nil {
			a.profiles.Profiles[i] = previous
			return fmt.Errorf("persist profile usage metadata: %w", err)
		}
		return nil
	}
	return fmt.Errorf("profile %q disappeared before usage metadata persistence", profileID)
}
