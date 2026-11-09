package main

import (
	"context"
	"encoding/json"
	"errors"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The imported constructor resolves the entry and final's constraints on their
// one system TUN. A saved final Auto choice cannot replace the proxy entry's
// Fixed or Jumbo choice. Replay only the original sealed private inputs; the
// derived protected launch config remains a separate live-owner check.
func readDesktopImportedMTUPolicyContext(ctx context.Context, selection multihopSelection) (string, mobilemtu.Profile, error) {
	var empty mobilemtu.Profile
	if ctx == nil || selection.Native == nil || !selection.Native.imported || selection.Control.ID != selection.Exit.ID {
		return "", empty, errors.New("imported MTU policy lost its original entry and paired final")
	}
	if err := ctx.Err(); err != nil {
		return "", empty, err
	}
	capture := selection.Native
	if err := capture.validate(selection); err != nil {
		return "", empty, err
	}
	original, err := mobilemultihop.ParseImportedLaunchInput(capture.importedInput)
	if err != nil {
		return "", empty, err
	}
	defer original.Close()
	graph, _, err := nativeMultihopProofConfig(original.Config(), selection.Entry)
	if err != nil || original.SourceSHA256() != capture.importedOriginalSource || graph != capture.configs[selection.ExitMode] {
		return "", empty, errors.Join(err, errors.New("imported MTU policy differs from its original sealed graph"))
	}
	raw := original.MTUProfile()
	policy, err := mobilemtu.ReadProfile(raw)
	if err != nil {
		return "", empty, err
	}
	final, err := json.Marshal(selection.Exit)
	if err != nil {
		return "", empty, err
	}
	defer clear(final)
	authority, err := mobilemtu.ReadProfile(string(final))
	if err != nil || policy.ID != authority.ID || policy.Proof != authority.Proof || policy.API != authority.API || policy.Token != authority.Token || policy.Sink != authority.Sink {
		return "", empty, errors.Join(err, errors.New("imported MTU policy changed the paired final probe authority"))
	}
	if err := ctx.Err(); err != nil {
		return "", empty, err
	}
	return raw, policy, nil
}
