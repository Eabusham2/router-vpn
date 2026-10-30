//go:build windows

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"syscall"
)

// The baseline itself is the durable record. BFE stores its bounded canonical
// provider data alongside the persistent sublayer; no user-selected path,
// registry value, process ID or environment string authorizes its replacement.
// A separate dynamic sublayer is the exclusive session lock. Its object key is
// unique in BFE, and its owning dynamic session also owns every traffic permit.
// On process death BFE removes both before a new owner can acquire the lock.
// https://learn.microsoft.com/windows/win32/fwp/object-management
type desktopWindowsBaselineRecord struct {
	Schema           int                  `json:"schema"`
	Kind             string               `json:"kind"`
	Capture          DesktopSocketCapture `json:"capture"`
	KillSwitchPolicy string               `json:"kill_switch_policy"`
	LANPrefixes      []netip.Prefix       `json:"lan_prefixes"`
	DHCP4Servers     []netip.Addr         `json:"dhcp4_servers"`
	FixtureSHA256    string               `json:"fixture_sha256,omitempty"`
	SublayerWeight   *uint16              `json:"sublayer_weight"`
}

func desktopWindowsManagedKey(kind string, fixtureScope []byte) syscall.GUID {
	digest := sha256.New()
	digest.Write([]byte("RouterVPN-owned-WFP/1\x00" + kind + "\x00"))
	digest.Write(fixtureScope)
	return desktopWFPGUID(hex.EncodeToString(digest.Sum(nil)[:16]))
}
func desktopWindowsFixtureHash(scope []byte) string {
	if len(scope) == 0 {
		return ""
	}
	digest := sha256.Sum256(scope)
	return hex.EncodeToString(digest[:])
}
func (p *DesktopWindowsSocketPolicy) baselineMetadata() ([]byte, error) {
	weight := p.baselineWeight
	return json.Marshal(desktopWindowsBaselineRecord{Schema: 2, Kind: "routervpn-owned-physical-baseline",
		Capture: p.capture, KillSwitchPolicy: p.options.KillSwitchPolicy,
		LANPrefixes: p.options.LANPrefixes, DHCP4Servers: p.options.DHCP4Servers,
		FixtureSHA256: desktopWindowsFixtureHash(p.fixtureScope), SublayerWeight: &weight})
}
func desktopWindowsParseBaseline(data []byte) (*desktopWindowsBaselineRecord, error) {
	if len(data) == 0 || len(data) > 16384 {
		return nil, errors.New("Windows baseline record exceeded its bound")
	}
	var record desktopWindowsBaselineRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, errors.New("Windows baseline record is not a known captured policy")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, data) || record.Schema != 2 || record.Kind != "routervpn-owned-physical-baseline" ||
		!record.Capture.valid() || record.KillSwitchPolicy != "always" && record.KillSwitchPolicy != "on-connect" || record.SublayerWeight == nil {
		return nil, errors.New("Windows baseline record lost its canonical identity")
	}
	if err := desktopWindowsValidateLAN(record.LANPrefixes); err != nil {
		return nil, err
	}
	if err := desktopWindowsValidateDHCP(record.DHCP4Servers); err != nil {
		return nil, err
	}
	return &record, nil
}
func desktopWindowsDecodeBaseline(data, fixtureScope []byte) (*DesktopWindowsSocketPolicy, error) {
	record, err := desktopWindowsParseBaseline(data)
	if err != nil {
		return nil, err
	}
	if record.FixtureSHA256 != desktopWindowsFixtureHash(fixtureScope) {
		return nil, errors.New("Windows baseline record lost its captured scope")
	}
	p := &DesktopWindowsSocketPolicy{capture: record.Capture, metadata: append([]byte(nil), data...),
		sublayer: desktopWindowsManagedKey("baseline", fixtureScope), fixtureScope: append([]byte(nil), fixtureScope...),
		baselineWeight: *record.SublayerWeight,
		options:        DesktopWindowsSocketOptions{KillSwitchPolicy: record.KillSwitchPolicy, LANPrefixes: record.LANPrefixes, DHCP4Servers: record.DHCP4Servers}}
	p.baseline = p.compileBaseline()
	return p, nil
}

func (p *DesktopWindowsSocketPolicy) acquireBaselineLock() error {
	var err error
	p.leaseEngine, err = desktopWFPOpen(true)
	if err != nil {
		return err
	}
	p.lockKey = desktopWindowsManagedKey("session-lock", p.fixtureScope)
	p.lockMetadata = []byte("RouterVPN-WFP-session-lock/1|" + p.capture.SessionID + "|" + p.capture.SourceSHA256 + "|" + p.capture.NetworkID)
	// A collision never grants authority to remove the existing lock. Closing
	// our own engine releases only objects this exact dynamic session created.
	if err := p.leaseEngine.addSublayer(p.lockKey, p.lockMetadata, false, 0); err != nil {
		return err
	}
	p.locked = true
	p.lockVerify = true
	snapshot, err := p.leaseEngine.readSublayer(p.lockKey, false)
	if err != nil || snapshot == nil || !bytes.Equal(snapshot.Metadata, p.lockMetadata) {
		return errors.Join(err, errors.New("Windows physical baseline session lock was not captured"))
	}
	p.lockWeight = snapshot.Weight
	return p.assertBaselineLock()
}
func (p *DesktopWindowsSocketPolicy) assertBaselineLock() error {
	if !p.locked || p.leaseEngine == nil || p.leaseEngine.handle == 0 {
		return errors.New("Windows physical baseline has no native session lock")
	}
	metadata, found, err := p.leaseEngine.ReadSublayer(p.lockKey, false, p.lockWeight)
	if err != nil || !found || !bytes.Equal(metadata, p.lockMetadata) {
		return errors.Join(err, errors.New("Windows physical baseline session lock changed"))
	}
	return p.leaseEngine.AssertComplete(p.lockKey, nil)
}

// Initial replacement/recovery reads have no trusted in-memory weight from the
// old process. Its canonical record must supply that exact value, and the full
// sublayer, ACL and rules are verified before any removal is authorized.
func desktopWindowsReadBaseline(engine *desktopWFPEngine, key syscall.GUID, scope []byte) (*DesktopWindowsSocketPolicy, error) {
	snapshot, err := engine.readSublayer(key, true)
	if err != nil || snapshot == nil {
		return nil, err
	}
	old, err := desktopWindowsDecodeBaseline(snapshot.Metadata, scope)
	if err != nil {
		return nil, err
	}
	if old.sublayer != key || snapshot.Weight != old.baselineWeight {
		return nil, errors.New("Windows baseline record differs from its captured kernel weight")
	}
	return old, nil
}

// Called only inside replaceBaseline's BFE write transaction, before any new
// filter exists. An empty initial add discovers BFE's assigned priority. A
// normalized result is recorded and re-added atomically with that exact weight;
// it is never inferred from an unrelated sublayer or accepted as later drift.
func (p *DesktopWindowsSocketPolicy) addCapturedBaseline() error {
	if err := p.baselineEngine.AddSublayer(p.sublayer, p.metadata); err != nil {
		return err
	}
	snapshot, err := p.baselineEngine.readSublayer(p.sublayer, true)
	if err != nil || snapshot == nil || !bytes.Equal(snapshot.Metadata, p.metadata) {
		return errors.Join(err, errors.New("Windows baseline assigned weight was not captured"))
	}
	if err := p.baselineEngine.AssertComplete(p.sublayer, nil); err != nil {
		return err
	}
	if snapshot.Weight != p.baselineWeight {
		if err := p.baselineEngine.DeleteSublayer(p.sublayer); err != nil {
			return err
		}
		p.baselineWeight = snapshot.Weight
		p.metadata, err = p.baselineMetadata()
		if err != nil {
			return err
		}
		if err := p.baselineEngine.AddSublayer(p.sublayer, p.metadata); err != nil {
			return err
		}
	}
	if err := p.baselineEngine.AssertSublayer(p.sublayer, p.metadata); err != nil {
		return err
	}
	if err := p.baselineEngine.AssertComplete(p.sublayer, nil); err != nil {
		return err
	}
	p.baseline = p.compileBaseline()
	return nil
}

func desktopWindowsDeleteBaseline(engine *desktopWFPEngine, old *DesktopWindowsSocketPolicy) error {
	if err := engine.AssertSublayer(old.sublayer, old.metadata); err != nil {
		return err
	}
	if err := engine.AssertComplete(old.sublayer, old.baseline); err != nil {
		return err
	}
	for _, rule := range old.baseline {
		if err := engine.Delete(rule.Key); err != nil {
			return err
		}
	}
	return engine.DeleteSublayer(old.sublayer)
}

func (p *DesktopWindowsSocketPolicy) replaceBaseline() error {
	if err := p.assertBaselineLock(); err != nil {
		return err
	}
	if err := p.baselineEngine.Begin(); err != nil {
		return err
	}
	// BFE's read/write transaction holds one lock across old-state readback,
	// exact removal and new installation: there is no open gap and no second
	// sublayer whose older drop rule can override this session's new permits.
	old, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, p.fixtureScope)
	if err == nil && p.predecessor != nil {
		err = p.predecessor.verify(old)
	}
	if err == nil && old != nil {
		if old.capture == p.capture {
			err = errors.New("Windows physical baseline cannot reuse a former native capture")
		}
		if err == nil {
			err = desktopWindowsDeleteBaseline(p.baselineEngine, old)
		}
	}
	if err == nil {
		err = p.addCapturedBaseline()
	}
	if err == nil {
		for index := range p.baseline {
			if err = p.baselineEngine.Add(&p.baseline[index]); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = p.completeSuccessorCommitBarrier(old)
	}
	if err == nil {
		err = p.baselineEngine.Commit()
	}
	if err != nil {
		return errors.Join(err, p.baselineEngine.Abort())
	}
	p.installed = true
	return p.assertBaseline()
}

// A failed or late commit is not treated as proof that no baseline was
// installed. Cleanup reads the kernel record after joining/aborting the exact
// operation. A different prior record belongs to the failed replacement's old
// state and is deliberately left intact.
func (p *DesktopWindowsSocketPolicy) resolveBaselineOwnership() error {
	if !p.locked || p.baselineEngine == nil || p.baselineEngine.handle == 0 {
		return nil
	}
	if err := p.assertBaselineLock(); err != nil {
		return err
	}
	if err := p.baselineEngine.Abort(); err != nil {
		return err
	}
	old, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, p.fixtureScope)
	if err != nil {
		return err
	}
	if old == nil {
		if p.installed && !p.baselineRemovalAttempted {
			return errors.New("Windows physical baseline disappeared before owned cleanup")
		}
		p.installed = false
		return nil
	}
	if old.capture != p.capture {
		if p.installed {
			return errors.New("Windows physical baseline was replaced before owned cleanup")
		}
		return p.baselineEngine.AssertComplete(old.sublayer, old.baseline)
	}
	if !bytes.Equal(p.metadata, old.metadata) || p.baselineWeight != old.baselineWeight {
		return errors.New("Windows physical baseline policy changed within its capture")
	}
	p.installed = true
	return p.assertBaseline()
}

func (p *DesktopWindowsSocketPolicy) finishBaseline(ctx context.Context) error {
	if p.baselineDone {
		return nil
	}
	if p.recoveryMode && !p.recoveryArmed.Load() {
		// A cancelled pre-handoff recovery owns only its session lock. It may
		// release that lock, but may not perform a late protection change.
		p.baselineDone = true
		return nil
	}
	if err := p.resolveBaselineOwnership(); err != nil {
		return err
	}
	if p.installed && p.options.KillSwitchPolicy != "always" && !p.options.RetainBaselineForHandoff {
		if err := p.baselineEngine.Begin(); err != nil {
			return err
		}
		err := p.completeRemovalCommitBarrier(ctx)
		if err == nil {
			p.baselineRemovalAttempted = true
			err = desktopWindowsDeleteBaseline(p.baselineEngine, p)
		}
		if err == nil {
			err = p.baselineEngine.Commit()
		}
		if err != nil {
			return errors.Join(err, p.baselineEngine.Abort())
		}
		p.installed = false
	}
	if p.baselineRemovalAttempted {
		for _, rule := range p.baseline {
			if err := p.baselineEngine.Absent(rule.Key); err != nil {
				return err
			}
		}
		if err := p.baselineEngine.SublayerAbsent(p.sublayer); err != nil {
			return err
		}
	}
	p.baselineDone = true
	return nil
}

// DesktopWindowsProtectionRecovery is an explicit, elevated removal request.
// It can remove only the complete known Router VPN baseline while no native
// socket session owns the lock. Close completes the exact removal/readback.
// A nonnil partial result must also be closed; failed/cancelled preparation
// releases its own lock without changing the existing protection.
type DesktopWindowsProtectionRecovery struct{ owner *DesktopWindowsSocketPolicy }

func NewDesktopWindowsProtectionRecovery(ctx context.Context) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionRecovery(ctx, nil)
}
func newDesktopWindowsProtectionRecovery(ctx context.Context, fixtureScope []byte) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransaction(ctx, fixtureScope, true)
}

// NewDesktopWindowsProtectionRelease retires a stale on-connect baseline after
// its native session has joined. Unlike explicit recovery, it preserves Always.
// The decision is read under the same native session lock as cleanup, so a
// selected-profile change or a replacement baseline cannot authorize removal.
func NewDesktopWindowsProtectionRelease(ctx context.Context) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransaction(ctx, nil, false)
}

func newDesktopWindowsProtectionTransaction(ctx context.Context, fixtureScope []byte, removeAlways bool) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransactionTarget(ctx, fixtureScope, removeAlways, nil)
}

func newDesktopWindowsProtectionTransactionTarget(ctx context.Context, fixtureScope []byte, removeAlways bool, target *DesktopWindowsProtectionTarget) (*DesktopWindowsProtectionRecovery, error) {
	return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, fixtureScope, removeAlways, target, nil)
}

func newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx context.Context, fixtureScope []byte, removeAlways bool, target *DesktopWindowsProtectionTarget, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsProtectionRecovery, error) {
	var expected *desktopWindowsProtectionExpected
	if target != nil {
		var err error
		expected, err = newDesktopWindowsProtectionExpected(target)
		if err != nil {
			return nil, err
		}
	}
	if ctx == nil || ctx.Err() != nil || len(fixtureScope) > 65536 || len(fixtureScope)%2 != 0 {
		return nil, errors.New("Windows protection recovery requires a live bounded owner")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	identity := sha256.Sum256([]byte("RouterVPN explicit Windows protection recovery/1"))
	capture := DesktopSocketCapture{SessionID: hex.EncodeToString(nonce[:16]), SourceSHA256: hex.EncodeToString(identity[:]), NetworkID: hex.EncodeToString(nonce[16:])}
	lifetime, cancel := context.WithCancel(ctx)
	p := &DesktopWindowsSocketPolicy{capture: capture, ctx: lifetime, cancel: cancel, gate: make(chan struct{}, 1),
		sublayer: desktopWindowsManagedKey("baseline", fixtureScope), fixtureScope: append([]byte(nil), fixtureScope...), recoveryMode: true}
	if barrier != nil {
		if expected == nil || expected.target == nil {
			cancel()
			return nil, errors.New("Windows durable retirement requires an exact expected target")
		}
		p.predecessor, p.commitBarrier, p.commitAction = expected, barrier, "release"
		if removeAlways {
			p.commitAction = "off"
		}
	}
	p.gate <- struct{}{}
	recovery := &DesktopWindowsProtectionRecovery{owner: p}
	_, err := desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) {
		if err := p.acquireBaselineLock(); err != nil {
			return struct{}{}, err
		}
		var err error
		p.baselineEngine, err = desktopWFPOpen(false)
		if err != nil {
			return struct{}{}, err
		}
		old, err := desktopWindowsReadBaseline(p.baselineEngine, p.sublayer, fixtureScope)
		if err != nil {
			return struct{}{}, err
		}
		if expected != nil {
			if err := expected.verify(old); err != nil {
				return struct{}{}, err
			}
		}
		if old == nil {
			p.baselineDone = true
			return struct{}{}, nil
		}
		if err := p.baselineEngine.AssertComplete(old.sublayer, old.baseline); err != nil {
			return struct{}{}, err
		}
		p.capture, p.metadata, p.baseline = old.capture, old.metadata, old.baseline
		p.baselineWeight = old.baselineWeight
		p.options = old.options
		if removeAlways {
			p.options.KillSwitchPolicy = "on-connect" // only explicit recovery authorizes removal of Always
		}
		p.installed = true
		return struct{}{}, nil
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		p.Cancel()
		return recovery, err
	}
	p.recoveryArmed.Store(true)
	return recovery, nil
}
func (r *DesktopWindowsProtectionRecovery) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	return r.owner.Close(ctx)
}

func (p *DesktopWindowsSocketPolicy) releaseBaselineLock() error {
	if p.leaseEngine == nil {
		return nil
	}
	if err := p.leaseEngine.Close(); err != nil {
		return err
	}
	p.locked = false
	if p.lockVerify {
		// A replacement may acquire the fixed key immediately after our
		// dynamic session closes. Read the captured metadata rather than
		// confusing a replacement lock with this session's failed cleanup.
		reader := p.baselineEngine
		if reader == nil || reader.handle == 0 {
			var err error
			p.baselineEngine, err = desktopWFPOpen(false)
			if err != nil {
				return err
			}
			reader = p.baselineEngine
		}
		snapshot, err := reader.readSublayer(p.lockKey, false)
		if err != nil || snapshot != nil && bytes.Equal(snapshot.Metadata, p.lockMetadata) {
			return errors.Join(err, errors.New("Windows native session lock retirement was not proved"))
		}
		p.lockVerify = false
	}
	return nil
}
