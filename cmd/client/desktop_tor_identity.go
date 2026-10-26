package main

import "router-vpn/internal/common"

// Tor owns its actual interface through a native, per-operation readback.
// Persisting that derived measurement must not retire the same connection.
// Omit only EffectiveMTU from the existing credential/device/DNS/graph policy
// projection; its other measurement/display fields are already excluded.
// Requested ManualMTU, MTUPolicy and every existing protection field stay bound.
// This value copy never mutates the selected profile or weakens other runtimes'
// asyncMeasurementProfileToken checks.
func desktopTorSourceIdentityToken(profile common.RouterProfile) string {
	profile.EffectiveMTU = 0
	return asyncMeasurementProfileToken(profile)
}
