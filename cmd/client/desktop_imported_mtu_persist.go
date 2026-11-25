package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
)

// The caller holds app.mu and retains the original operation or cleanup
// authority. Checking it again immediately before atomic rename prevents a
// temporary-file write from publishing after that same allowance expires.
// The private writer joins its file work and never returns a false failure
// after rename; callers can therefore retain the exact durable rollback token.
func persistDesktopImportedMTUProfilesContext(ctx context.Context, path string, profiles common.RouterProfileStore, loads ...*connectionProfileLoadTransaction) error {
	if ctx == nil {
		return errors.New("imported MTU persistence has no original caller")
	}
	if len(loads) > 1 {
		return errors.New("imported MTU persistence has multiple profile Load owners")
	}
	var load *connectionProfileLoadTransaction
	if len(loads) == 1 {
		load = loads[0]
	}
	encoded, err := marshalPrivateProfiles(profiles, load)
	if err != nil {
		return err
	}
	_, err = atomicWritePrivateChecked(path, append(encoded, '\n'), ctx.Err)
	return err
}
