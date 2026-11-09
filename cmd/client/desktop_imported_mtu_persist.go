package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/common"
)

// The caller holds app.mu and retains the original operation or cleanup
// authority. Checking it again immediately before atomic rename prevents a
// temporary-file write from publishing after that same allowance expires.
// The private writer joins its file work and never returns a false failure
// after rename; callers can therefore retain the exact durable rollback token.
func persistDesktopImportedMTUProfilesContext(ctx context.Context, path string, profiles common.RouterProfileStore) error {
	if ctx == nil {
		return errors.New("imported MTU persistence has no original caller")
	}
	encoded, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	_, err = atomicWritePrivateChecked(path, append(encoded, '\n'), ctx.Err)
	return err
}
