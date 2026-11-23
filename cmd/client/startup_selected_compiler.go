package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/common"
)

// These presentation and measurement fields are serialized by the historical
// native compiler even though they confer no transport or routing authority.
// Recreate their exact original bytes only in the private compiler copy. The
// live catalog, original private files and actual current MTU retain ownership.
var startupCompilerHistoryFields = [...]string{
	"AutoConnect", "StartupMode", "UseCount", "LastUsedAt",
	"EffectiveMTU", "EffectiveMTUSource", "EffectiveMTUPathKey", "EffectiveUnderlayPMTU",
	"EffectiveMTUTestedAt", "EffectiveMTUNetworkFingerprint", "EffectiveMTUProfileFingerprint",
	"EffectiveMTUMbps", "EffectiveMTUMedianRTTMs", "EffectiveMTUSuccessRatio",
	"LatencySamples", "LatencyMinMs", "LatencyMedianMs", "LatencyTrimmedMeanMs", "LatencyAverageMs",
	"LatencyP90Ms", "LatencyMaxMs", "LatencyLastTest", "LatencyReceipt",
}

func startupCompilerHistory(original common.RouterProfile) (string, error) {
	fields := make(map[string]any)
	value := reflect.ValueOf(original)
	for _, name := range startupCompilerHistoryFields {
		field := value.FieldByName(name)
		if !field.IsZero() {
			fields[name] = field.Interface()
		}
	}
	encoded, err := json.Marshal(fields)
	return string(encoded), err
}

func withStartupCompilerHistory(profile common.RouterProfile, raw string) (common.RouterProfile, error) {
	fields, err := startupStrictObject([]byte(raw), startupCompilerHistoryFields[:]...)
	if err != nil {
		return common.RouterProfile{}, err
	}
	value := reflect.ValueOf(&profile).Elem()
	for _, name := range startupCompilerHistoryFields {
		field := value.FieldByName(name)
		field.SetZero()
		if encoded, ok := fields[name]; ok {
			if err := json.Unmarshal(encoded, field.Addr().Interface()); err != nil {
				return common.RouterProfile{}, err
			}
		}
	}
	canonical, err := startupCompilerHistory(profile)
	if err != nil || canonical != raw {
		return common.RouterProfile{}, errors.New("ordered Last lost canonical compiler history")
	}
	return profile, nil
}

type startupSelectedCompilerKey struct{}

func (c *startupNodeChainCapture) compilerContext(ctx context.Context) context.Context {
	if c == nil || c.selectedLast == "" {
		return ctx
	}
	return context.WithValue(ctx, startupSelectedCompilerKey{}, c)
}

func startupSelectedCompilerProfile(ctx context.Context, profile common.RouterProfile) (common.RouterProfile, error) {
	c, ok := ctx.Value(startupSelectedCompilerKey{}).(*startupNodeChainCapture)
	if !ok {
		return profile, nil
	}
	if c == nil || c.last == nil || c.last.NodeChain == nil || c.selectedLast != c.last.NodeChain.SelectedLast {
		return common.RouterProfile{}, errors.New("selected Last lost its original compiler capture")
	}
	for _, member := range c.last.NodeChain.Nodes {
		if member.ID == profile.ID && member.ProfileToken == startupExternalProfileToken(profile) {
			return withStartupCompilerHistory(profile, member.CompilerHistory)
		}
	}
	return common.RouterProfile{}, errors.New("selected Last lost its original member private source")
}
