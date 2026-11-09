package main

import (
	"context"
	"errors"
	"math"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

// One historical suggestion per saved paired final, bounded by the existing
// profile store. Its full graph/path key and 24-hour age are checked on lookup;
// every accepted cache hit still runs the shared authenticated measurements.
type desktopImportedMTUCache struct {
	ui      *desktopImportedMTUUI
	before  common.RouterProfile
	written string // Accessed only by this synchronous run, under app.mu for CAS.
}

func (*desktopImportedMTUCache) Lookup(string) (int, bool) { return 0, false }
func (*desktopImportedMTUCache) Save(string, int, func() bool) error {
	return errors.New("imported MTU history requires its original caller")
}

func (c *desktopImportedMTUCache) LookupContext(ctx context.Context, key string) (int, bool, error) {
	u := c.ui
	if err := u.owner.current(ctx); err != nil {
		return 0, false, err
	}
	if err := mobilemtu.LockContext(ctx, &u.a.mu); err != nil {
		return 0, false, err
	}
	defer u.a.mu.Unlock()
	profile, ok := u.a.profileByIDLocked(u.identity.Profile)
	if !ok || mtuProfileSnapshotToken(profile) != mtuProfileSnapshotToken(u.runtime.selection.Control) {
		return 0, false, errors.New("imported MTU historical profile changed")
	}
	tested, err := time.Parse(time.RFC3339Nano, profile.EffectiveMTUTestedAt)
	now := time.Now()
	valid := err == nil && !tested.Before(now.Add(-24*time.Hour)) && !tested.After(now.Add(2*time.Second)) &&
		profile.EffectiveMTU >= 1280 && profile.EffectiveMTU <= 9000 && profile.EffectiveMTUPathKey == key &&
		profile.EffectiveMTUSource == "measured-private-system-tun" && profile.EffectiveMTUNetworkFingerprint == u.runtime.network &&
		profile.EffectiveMTUProfileFingerprint == mtuProfileSnapshotToken(profile)
	return profile.EffectiveMTU, valid, ctx.Err()
}

func (c *desktopImportedMTUCache) SaveContext(ctx context.Context, key string, mtu int, valid func(context.Context) error) error {
	if valid == nil || !desktopMTUPathPattern.MatchString(key) || mtu < 1280 || mtu > 9000 {
		return errors.New("imported MTU history lacks its fresh bounded result")
	}
	if err := valid(ctx); err != nil {
		return err
	}
	u := c.ui
	status, err := desktopImportedMTUStatusContext(ctx, u.controller)
	if err != nil {
		return err
	}
	var mbps, latency, ratio float64
	for _, candidate := range status.Candidates {
		if candidate.MTU == mtu && candidate.Working && candidate.Download != nil && candidate.Upload != nil &&
			candidate.PacketsSent == 6 && candidate.PacketsReceived == 6 && candidate.DatagramBytes > 0 {
			mbps, latency, ratio = math.Min(candidate.Download.Mbps, candidate.Upload.Mbps), candidate.MedianRTT, 1
		}
	}
	if mbps <= 0 || latency <= 0 || math.IsNaN(mbps) || math.IsInf(mbps, 0) || math.IsNaN(latency) || math.IsInf(latency, 0) || status.PathKey != key {
		return errors.New("imported MTU history omitted authenticated packet and bidirectional transfer evidence")
	}
	if err := mobilemtu.LockContext(ctx, &u.a.mu); err != nil {
		return err
	}
	defer u.a.mu.Unlock()
	_, temporary := speedLabTemporaryOwners.Load(u.a)
	if u.a.cmd != u.runtime.launch.command || u.a.profiles.SelectedID != u.identity.Profile || c.written != "" || temporary || speedLabTemporaryPersistenceSuppressed(u.a) {
		return errors.New("imported MTU cache lost its original synchronous writer")
	}
	for i := range u.a.profiles.Profiles {
		profile := &u.a.profiles.Profiles[i]
		if profile.ID != u.identity.Profile {
			continue
		}
		if mtuProfileSnapshotToken(*profile) != mtuProfileSnapshotToken(u.runtime.selection.Control) || !desktopImportedMTUAutomatic(profile.MTUPolicy, profile.JumboTUN) {
			return errors.New("imported MTU policy changed before historical persistence")
		}
		before := common.CloneRouterProfile(*profile)
		profile.EffectiveMTU, profile.EffectiveMTUSource, profile.EffectiveMTUPathKey = mtu, "measured-private-system-tun", key
		profile.EffectiveMTUNetworkFingerprint, profile.EffectiveMTUProfileFingerprint = u.runtime.network, mtuProfileSnapshotToken(before)
		profile.EffectiveMTUTestedAt = time.Now().UTC().Format(time.RFC3339Nano)
		profile.EffectiveMTUMbps, profile.EffectiveMTUMedianRTTMs, profile.EffectiveMTUSuccessRatio = mbps, latency, ratio
		profile.EffectiveUnderlayPMTU = 0 // Authenticated inner packets do not reveal outer underlay MTU.
		if err := ctx.Err(); err != nil {
			*profile = before
			return err
		}
		if err := persistDesktopImportedMTUProfilesContext(ctx, u.a.cfg.ProfilesFile, u.a.profiles); err != nil {
			*profile = before
			return err
		}
		c.before, c.written = before, mtuMeasurementFieldsDigest(*profile)
		return ctx.Err()
	}
	return errors.New("imported MTU paired final disappeared before persistence")
}

func (c *desktopImportedMTUCache) restore(ctx context.Context) error {
	u := c.ui
	cleanup, err := mobilemtu.OperationCleanupOnly(ctx)
	if err != nil || !cleanup || !mobilemtu.SameOperationContext(ctx, u.owner.operation) {
		return errors.Join(err, errors.New("imported MTU history rollback lost its original cleanup authority"))
	}
	if err := mobilemtu.LockContext(ctx, &u.a.mu); err != nil {
		return err
	}
	defer u.a.mu.Unlock()
	if c.written == "" {
		return nil
	}
	for i := range u.a.profiles.Profiles {
		profile := &u.a.profiles.Profiles[i]
		if profile.ID != u.identity.Profile {
			continue
		}
		if mtuProfileSnapshotToken(*profile) != mtuProfileSnapshotToken(c.before) || mtuMeasurementFieldsDigest(*profile) != c.written {
			return errors.New("newer imported MTU profile state retained during rollback")
		}
		before := common.CloneRouterProfile(*profile)
		copyMTUMeasurementFields(profile, c.before)
		if err := persistDesktopImportedMTUProfilesContext(ctx, u.a.cfg.ProfilesFile, u.a.profiles); err != nil {
			*profile = before
			return err
		}
		c.written = ""
		return ctx.Err()
	}
	return errors.New("original imported MTU historical writer disappeared")
}

func copyMTUMeasurementFields(to *common.RouterProfile, from common.RouterProfile) {
	to.EffectiveMTU, to.EffectiveMTUSource, to.EffectiveMTUPathKey = from.EffectiveMTU, from.EffectiveMTUSource, from.EffectiveMTUPathKey
	to.EffectiveUnderlayPMTU = from.EffectiveUnderlayPMTU
	to.EffectiveMTUNetworkFingerprint, to.EffectiveMTUProfileFingerprint, to.EffectiveMTUTestedAt = from.EffectiveMTUNetworkFingerprint, from.EffectiveMTUProfileFingerprint, from.EffectiveMTUTestedAt
	to.EffectiveMTUMbps, to.EffectiveMTUMedianRTTMs, to.EffectiveMTUSuccessRatio = from.EffectiveMTUMbps, from.EffectiveMTUMedianRTTMs, from.EffectiveMTUSuccessRatio
}
