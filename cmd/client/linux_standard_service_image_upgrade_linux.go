//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// The original service gate owns these fields. Source leases may yield only
// while ordinary dispatch and watchers are fenced and canonical helpers joined.
type linuxStandardImageAuthority struct {
	sourceIdentity *os.File
	sourcePath     string
	generation     *linuxStandardServiceGeneration
	source, owner  *os.File
	sourceInfo     os.FileInfo
}
type linuxStandardImageUpgrade struct {
	oldTransferFinished                          bool
	rootPin, runPin                              *os.File
	terminalPeersJoined                          bool
	abortPinResolved, abortReleased, abortClosed bool
	envelope                                     linuxStandardImageUpgradeEnvelope
	phase                                        string
	cleanupDeadline                              int64
	coordinator, successor, oldPeer              *linuxStandardServicePeer
	oldGeneration, newGeneration                 *linuxStandardServiceGeneration
	source                                       mobiletor.DesktopLinuxClosedTransferSnapshot
	destination                                  *mobiletor.DesktopLinuxClosedTransferSnapshot
	transfer                                     *mobiletor.DesktopLinuxStandardImageTransfer
	pin                                          *mobiletor.DesktopLinuxStandardImageSuccessorPin
	slot                                         *legacyExitProtectionSlot
	expectedCoordinator                          linuxprocess.Observation
	candidate                                    bool
	removed, ready, joined                       bool
}

func linuxStandardImageDigest(value any) string {
	b, _ := json.Marshal(value)
	return linuxStandardImageBytesDigest(b)
}
func linuxStandardImageBytesDigest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (t *linuxStandardImageUpgrade) view() *linuxStandardServiceImageUpgradeResponse {
	r := &linuxStandardServiceImageUpgradeResponse{Envelope: t.envelope, Phase: t.phase, CleanupDeadlineNS: t.cleanupDeadline, Source: &t.source, Destination: t.destination, SourceRemoved: t.removed, Ready: t.ready, OldJoined: t.joined}
	if t.coordinator != nil {
		v := t.coordinator.record
		r.CoordinatorPeer = &v
	}
	if t.oldPeer != nil {
		v := t.oldPeer.record
		r.OldPeer = &v
	}
	if t.successor != nil {
		v := t.successor.record
		r.NewPeer = &v
	}
	r.Frozen = t.phase == "frozen" || t.phase == "aborting"
	r.RollbackAllowed = t.phase == "aborting" && !t.removed
	r.ActivationAllowed = t.removed && t.phase != "settled"
	return r
}
func (t *linuxStandardImageUpgrade) context(ctx context.Context, cleanup bool, proposed int64) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("image operation omitted original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	stamp := t.envelope.DeadlineNS
	if cleanup {
		first := t.cleanupDeadline == 0
		if first && t.candidate {
			if proposed <= time.Now().UnixNano() || time.Unix(0, proposed).After(time.Now().Add(linuxStandardImageUpgradeCleanupLimit)) {
				return nil, nil, errors.New("candidate omitted original accepted cleanup clock")
			}
			t.cleanupDeadline = proposed
		}
		if first && !t.candidate {
			d := time.Now().Add(linuxStandardImageUpgradeCleanupLimit)
			if proposed > 0 && time.Unix(0, proposed).Before(d) {
				d = time.Unix(0, proposed)
			}
			if caller, ok := ctx.Deadline(); ok && caller.Before(d) {
				d = caller
			}
			t.cleanupDeadline = d.UnixNano()
		}
		if proposed > 0 && (!first && proposed != t.cleanupDeadline || first && proposed < t.cleanupDeadline) {
			return nil, nil, errors.New("image cleanup changed original accepted clock")
		}
		stamp = t.cleanupDeadline
	} else if t.cleanupDeadline != 0 {
		return nil, nil, errors.New("image work ended at original cleanup activation")
	}
	work, cancel := context.WithDeadline(ctx, time.Unix(0, stamp))
	if err := work.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	return work, cancel, nil
}
func (s *linuxStandardService) reserveImage(ctx context.Context, peer *linuxStandardServicePeer, q *linuxStandardServiceImageUpgradeRequest) (*linuxStandardImageUpgrade, error) {
	if q == nil || q.Generation == nil || q.Envelope != nil || q.Source != nil || q.Destination != nil || q.CleanupDeadlineNS != 0 || !linuxStandardImageSelectionValid(*q.Generation) || q.DeadlineNS <= time.Now().UnixNano() || time.Until(time.Unix(0, q.DeadlineNS)) > linuxStandardImageUpgradeWorkLimit {
		return nil, errors.New("image prepare changed fixed admission")
	}
	if s.imageUpgrade != nil && (s.imageUpgrade.coordinator == nil || s.imageUpgrade.candidate && s.imageUpgrade.phase != "settled" && s.imageUpgrade.phase != "aborted") {
		return nil, errors.New("candidate cannot replace its original pending admission")
	}
	if s.imageUpgrade != nil && (s.imageUpgrade.phase == "settled" || s.imageUpgrade.phase == "aborted") && s.imageUpgrade.coordinator.record != peer.record {
		if err := s.retireImageTerminal(ctx); err != nil {
			return nil, err
		}
	}
	if s.imageUpgrade != nil {
		t := s.imageUpgrade
		if t.coordinator.record != peer.record || t.envelope.NewGeneration != *q.Generation || t.envelope.DeadlineNS != q.DeadlineNS {
			return nil, errors.New("image prepare replaced original retained operation")
		}
		return t, s.resumeImageReservation(ctx, t)
	}
	a := s.imageAuthority
	if a == nil || a.generation == nil || a.source == nil || a.owner == nil || a.generation.selection == *q.Generation {
		return nil, errors.New("image prepare has no original immutable generation authority")
	}
	if s.quiescing || s.bootstrapPending() || s.transferPending() || s.reversePending() || s.legacyBoot != nil || s.protectionView != nil && s.protectionView.data.Pending || s.session != nil && (!s.session.joined || s.session.cleanupPending) {
		return nil, errors.New("image prepare requires joined engine and settled original policy")
	}
	if _, ok := legacyStandardExitOwners.Load(s.app); ok {
		return nil, errors.New("image prepare retains an original engine")
	}
	value, ok := legacyStandardProtectionOwners.Load(s.app)
	slot, valid := value.(*legacyExitProtectionSlot)
	if !ok || !valid || slot == nil || slot.policy != "always" || !slot.detached || slot.closed {
		return nil, errors.New("image prepare needs actual retained Always creator")
	}
	native, ok := slot.kernel.(*legacyExitNativeProtection)
	if !ok || native == nil {
		return nil, errors.New("image prepare requires actual native creator")
	}
	next, err := captureLinuxStandardServiceGenerationSelection(ctx, s.root, *q.Generation)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			_ = next.Close()
		}
	}()
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	if err = slot.current(ctx, lease); err != nil {
		return nil, err
	}
	if err = legacyExitTUNAbsent(); err != nil {
		return nil, err
	}
	if err = s.loadProfilesContext(ctx); err != nil {
		return nil, err
	}
	if err = desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
		return nil, err
	}
	profile, exists := s.app.profileByIDLocked(slot.profileID)
	s.app.mu.Unlock()
	revision, err := linuxStandardProfileDigest(profile)
	if err != nil || !exists || profile.KillSwitchPolicy != "always" || profile.HomeLANAccess != slot.homeLAN {
		return nil, errors.Join(err, errors.New("image original selected policy changed"))
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	e := linuxStandardImageUpgradeEnvelope{Schema: 1, ID: id, DeadlineNS: q.DeadlineNS, OldGeneration: a.generation.selection, NewGeneration: *q.Generation, ProfileID: slot.profileID, ProfileRevision: revision, HomeLAN: slot.homeLAN, DestinationSession: session}
	e.Root, err = desktopLinuxNodeObjectOf(lease.rootInfo)
	if err != nil {
		return nil, err
	}
	e.Run, err = desktopLinuxNodeObjectOf(lease.runInfo)
	if err != nil {
		return nil, err
	}
	e.MutationLock, err = desktopLinuxNodeObjectOf(lease.lockInfo)
	if err != nil {
		return nil, err
	}
	e.SavedState, err = desktopLinuxNodeObjectOf(slot.saved.info)
	if err != nil {
		return nil, err
	}
	e.SavedStateSHA256 = linuxStandardImageBytesDigest(slot.saved.body)
	activation, _, err := linuxStandardGenerationOpen(filepath.Join(s.root, linuxStandardGenerationActivation), false)
	if err != nil {
		return nil, err
	}
	raw, err := linuxStandardGenerationRead(ctx, activation, 4096)
	_ = activation.Close()
	if err != nil {
		return nil, err
	}
	var selected linuxStandardGenerationSelection
	if err = linuxStandardGenerationDecode(raw, &selected); err != nil || selected != e.OldGeneration {
		return nil, errors.Join(err, errors.New("image activation changed before reservation"))
	}
	e.ActivationSHA256 = linuxStandardImageBytesDigest(raw)
	t := &linuxStandardImageUpgrade{envelope: e, phase: "reserved", coordinator: peer, oldGeneration: a.generation, newGeneration: next, slot: slot}
	s.imageUpgrade = t
	retained = true
	if err = s.imageBoundary(ctx, t); err != nil {
		return t, err
	}
	_ = native
	return t, s.resumeImageReservation(ctx, t)

}
func (s *linuxStandardService) imageReleaseSource(ctx context.Context) error {
	a := s.imageAuthority
	if a == nil || a.generation == nil {
		return errors.New("image source has no original code lease")
	}
	if err := a.generation.Current(ctx); err != nil {
		return err
	}
	if a.source != nil {
		if err := a.source.Close(); err != nil {
			return err
		}
		a.source = nil
	}
	return ctx.Err()
}
func (s *linuxStandardService) imageAcquireSource(ctx context.Context, g *linuxStandardServiceGeneration) error {
	if s.imageAuthority.source == nil {
		f, err := ownedDesktopLock(s.imageAuthority.sourcePath, false)
		if err != nil {
			return err
		}
		info, statErr := f.Stat()
		named, nameErr := os.Lstat(s.imageAuthority.sourcePath)
		retained, identityErr := s.imageAuthority.sourceIdentity.Stat()
		if statErr != nil || nameErr != nil || identityErr != nil || !os.SameFile(info, retained) || s.imageAuthority.sourceInfo == nil || !os.SameFile(info, s.imageAuthority.sourceInfo) || !os.SameFile(info, named) {
			f.Close()
			return errors.Join(statErr, nameErr, errors.New("image source lock changed original inode"))
		}
		s.imageAuthority.source = f
	}
	return verifyLinuxStandardGenerationCode(ctx, s.root, g)
}
func (p *legacyExitProtectionSlot) finishImageTransfer(ctx context.Context) error {
	if p.closed {
		return nil
	}
	if err := p.kernel.Close(ctx); err != nil {
		return err
	}
	if err := p.saved.Close(); err != nil {
		return err
	}
	if !legacyStandardProtectionOwners.CompareAndDelete(p.app, p) {
		return errors.New("image transfer cannot discard replacement slot")
	}
	p.removed = true
	p.closed = true
	return ctx.Err()
}

var linuxStandardImageCodeTrees = map[string]bool{"client": true, "modes": true, "runtime": true}
var linuxStandardImageCodeFiles = map[string]bool{
	"modes.json": true, "logical-modes.json": true, "router-vpn-client": true, "router-vpn-dns": true, "router-vpn-start-layer-relay": true, "router-vpn-update": true, "router-vpn-app": true, "RouterVPN.ico": true, "router-vpn.png": true, "router-vpn.desktop": true, "MODES.md": true, "CLIENT.md": true, "SECURITY.md": true, "LICENSE": true, "DNS-PROXY-NOTICES.json": true, "ROUTER-VPN-SOURCE.json": true,
}

func verifyLinuxStandardGenerationCode(ctx context.Context, root string, g *linuxStandardServiceGeneration) error {
	if err := g.Current(ctx); err != nil {
		return err
	}
	raw, err := linuxStandardGenerationRead(ctx, g.manifest, 2<<20)
	if err != nil {
		return err
	}
	var manifest linuxStandardGenerationManifestData
	if err = linuxStandardGenerationDecode(raw, &manifest); err != nil {
		return err
	}
	declared := make(map[string]bool, len(manifest.Files))
	for _, entry := range manifest.Files {
		top, _, _ := strings.Cut(entry.Path, "/")
		if !linuxStandardImageCodeTrees[top] && !linuxStandardImageCodeFiles[entry.Path] {
			return errors.New("generation manifest escaped exact code-only promotion scope")
		}
		declared[entry.Path] = true
		f, info, e := linuxStandardGenerationOpen(filepath.Join(root, entry.Path), entry.SHA256 == "")
		if e != nil {
			return e
		}
		if uint32(info.Mode().Perm()) != entry.Mode {
			f.Close()
			return errors.New("promoted code mode differs from captured generation")
		}
		if entry.SHA256 != "" {
			digest, e := linuxStandardGenerationHash(ctx, f)
			if e != nil || digest != entry.SHA256 {
				f.Close()
				return errors.Join(e, errors.New("promoted code differs from captured immutable generation"))
			}
		}
		after, e := f.Stat()
		named, nameErr := os.Lstat(filepath.Join(root, entry.Path))
		f.Close()
		if e != nil || nameErr != nil || !linuxStandardGenerationEqual(info, after) || !linuxStandardGenerationEqual(info, named) {
			return errors.Join(e, nameErr, errors.New("promoted code changed during verification"))
		}
	}
	seen := map[string]bool{}
	visit := func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if !declared[name] || seen[name] || len(seen) >= 8192 {
			return errors.New("promoted code contains undeclared source")
		}
		seen[name] = true
		return nil
	}
	for name := range linuxStandardImageCodeTrees {
		path := filepath.Join(root, name)
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("promoted code tree changed type")
		}
		if e = filepath.WalkDir(path, visit); e != nil {
			return e
		}
	}
	for name := range linuxStandardImageCodeFiles {
		path := filepath.Join(root, name)
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("promoted code file changed type")
		}
		if e = visit(path, nil, nil); e != nil {
			return e
		}
	}
	if len(seen) != len(declared) {
		return errors.New("promoted code inventory is incomplete")
	}
	return ctx.Err()
}

func (s *linuxStandardService) resumeImageReservation(ctx context.Context, t *linuxStandardImageUpgrade) error {
	if t.transfer == nil {
		native, ok := t.slot.kernel.(*legacyExitNativeProtection)
		if !ok || native == nil {
			return errors.New("image reservation lost actual original creator")
		}
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err != nil {
			return err
		}
		defer lease.Close()
		if err = t.slot.current(ctx, lease); err != nil {
			return err
		}
		t.transfer, err = native.ReserveImageTransfer(ctx, t.envelope.ID, lease.lock)
		if err != nil {
			return err
		}
	}
	source, err := t.transfer.Snapshot(ctx)
	if err != nil {
		return err
	}
	if t.envelope.SourceSHA256 != "" && t.envelope.SourceSHA256 != linuxStandardImageDigest(source) {
		return errors.New("image reservation changed original source readback")
	}
	t.source = source
	t.envelope.Endpoints = append(t.envelope.Endpoints[:0], source.Endpoints...)
	t.envelope.SourceSHA256 = linuxStandardImageDigest(source)
	t.envelope.DestinationSHA256 = linuxStandardImageDigest(struct{ ID, Session, Source, Generation string }{t.envelope.ID, t.envelope.DestinationSession, t.envelope.SourceSHA256, t.envelope.NewGeneration.Generation})
	if err = t.envelope.validate(); err != nil {
		return err
	}
	return t.coordinator.Current(ctx)
}

func captureLinuxStandardImageAuthority(g *linuxStandardServiceGeneration, source, owner *os.File, path string) (*linuxStandardImageAuthority, error) {
	if source == nil || owner == nil {
		return nil, errors.New("image authority omitted retained source or lifetime lease")
	}
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, named) {
		return nil, errors.Join(err, errors.New("image authority source changed before capture"))
	}
	identity, err := os.Open("/proc/self/fd/" + strconv.FormatUint(uint64(source.Fd()), 10))
	if err != nil {
		return nil, err
	}
	actual, err := identity.Stat()
	if err != nil || !os.SameFile(actual, info) {
		identity.Close()
		return nil, errors.Join(err, errors.New("image authority failed to pin original source inode"))
	}
	return &linuxStandardImageAuthority{generation: g, source: source, owner: owner, sourceInfo: info, sourceIdentity: identity, sourcePath: path}, nil
}
func (s *linuxStandardService) retireImageTerminal(ctx context.Context) error {
	t := s.imageUpgrade
	if t == nil || t.phase != "settled" && t.phase != "aborted" {
		return errors.New("original image transfer is not terminal")
	}
	if !t.terminalPeersJoined {
		for _, peer := range []*linuxStandardServicePeer{t.coordinator, t.successor, t.oldPeer} {
			if peer == nil {
				continue
			}
			dead, err := peer.Retired()
			if err != nil || !dead {
				return errors.Join(err, errors.New("terminal image transfer retains an original live peer"))
			}
		}
		t.terminalPeersJoined = true
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return err
	}
	defer lease.Close()
	if t.slot == nil {
		return errors.New("terminal image transfer lost live selected slot")
	}
	if err = t.slot.current(ctx, lease); err != nil {
		return err
	}
	for _, peer := range []*linuxStandardServicePeer{t.coordinator, t.successor, t.oldPeer} {
		if peer != nil {
			if err = peer.Close(); err != nil {
				return err
			}
		}
	}
	for _, g := range []*linuxStandardServiceGeneration{t.oldGeneration, t.newGeneration} {
		if g != nil && g != s.imageAuthority.generation {
			if err = g.Close(); err != nil {
				return err
			}
		}
	}
	for _, file := range []*os.File{t.rootPin, t.runPin} {
		if file != nil {
			if err = file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				return err
			}
		}
	}
	s.imageUpgrade = nil
	return ctx.Err()
}

func (s *linuxStandardService) imageBoundary(ctx context.Context, t *linuxStandardImageUpgrade) error {
	for _, v := range []struct {
		path string
		pin  **os.File
		want linuxprotection.NativeObject
	}{{s.root, &t.rootPin, t.envelope.Root}, {filepath.Join(s.root, "run"), &t.runPin, t.envelope.Run}} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if *v.pin == nil {
			file, _, err := linuxStandardGenerationOpen(v.path, true)
			if err != nil {
				return err
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				return err
			}
			object, err := desktopLinuxNodeObjectOf(info)
			if err != nil || object != v.want {
				file.Close()
				return errors.Join(err, errors.New("image transfer original state boundary changed"))
			}
			*v.pin = file
		}
		actual, err := (*v.pin).Stat()
		named, nameErr := os.Lstat(v.path)
		if err != nil || nameErr != nil || !os.SameFile(actual, named) {
			return errors.Join(err, nameErr, errors.New("image transfer state boundary was replaced"))
		}
	}
	return ctx.Err()
}

func (s *linuxStandardService) imageCurrent(ctx context.Context, t *linuxStandardImageUpgrade) error {
	if err := s.imageBoundary(ctx, t); err != nil {
		return err
	}
	if t.candidate {
		if t.phase == "aborted" {
			return errors.New("candidate original guard retired")
		}
		if t.slot == nil || t.slot.kernel == nil {
			return errors.New("candidate native preparation remains incomplete")
		}
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err != nil {
			return err
		}
		defer lease.Close()
		if t.slot.persisted {
			if err = t.slot.current(ctx, lease); err != nil {
				return err
			}
			if t.pin == nil || t.destination == nil {
				return errors.New("candidate current proof lost original pin")
			}
			if err = t.pin.Resolve(ctx, t.source, true); err != nil {
				return err
			}
			return mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, *t.destination)
		}
		return t.slot.kernel.Current(ctx, lease.lock)
	}
	if t.phase == "aborted" {
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err != nil {
			return err
		}
		defer lease.Close()
		return t.slot.current(ctx, lease)
	}
	if t.oldTransferFinished {
		if t.destination == nil {
			return errors.New("settled source has no original successor")
		}
		return mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, *t.destination)
	}
	if t.transfer == nil {
		return errors.New("original source reservation remains incomplete")
	}
	removed, err := t.transfer.Result(ctx)
	if err != nil {
		return err
	}
	if removed {
		t.removed = true
		if t.phase != "settled" {
			t.phase = "source-removed"
		}
	}
	return nil
}
