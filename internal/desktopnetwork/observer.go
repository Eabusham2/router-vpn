package desktopnetwork

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// These observations carry no mutation capability. A receipt can classify an
// owned TUN only after its caller has independently proved the original native
// process, source, session and current interface. Names and saved receipts alone
// are not sufficient admission at the controller boundary.
type Link struct {
	Index    uint32 `json:"index"`
	LUID     uint64 `json:"luid,omitempty"`
	Name     string `json:"name"`
	MTU      int    `json:"mtu"`
	Flags    uint32 `json:"flags"`
	Hardware string `json:"hardware,omitempty"`
	Policy   string `json:"policy,omitempty"`
	// Only the Darwin native reader can supply this private observation. It
	// retains an unused zero-MTU interface; it grants no routing ownership.
	darwinUnused *desktopDarwinUnusedInterface
}

type Address struct {
	Index  uint32 `json:"index"`
	LUID   uint64 `json:"luid,omitempty"`
	Prefix string `json:"prefix"`
}

type Snapshot struct {
	Links     []Link                 `json:"links"`
	Addresses []Address              `json:"addresses"`
	Objects   []DesktopNetworkObject `json:"objects"`
}

// Action is add, delete, or change. A change on a physical object invalidates
// immediately, even if the following snapshot has already returned to its old
// value. Windows notifications may carry only a key; Partial is never used to
// authorize a whole object unrelated to that exact key.
type Event struct {
	Kind, Action  string
	Index         uint32
	LUID          uint64
	Name, Address string
	Object        DesktopNetworkObject
	Partial       bool
}

type nativeObserver interface {
	Snapshot(context.Context) (Snapshot, error)
	Barrier(context.Context) error
	Close() error
}

type Tracker struct {
	mu                                        sync.Mutex
	closeMu                                   sync.Mutex
	ctx                                       context.Context
	native                                    nativeObserver
	initializing, transition, closing, closed bool
	startedWithoutOwnedReceipt                bool
	failure                                   atomic.Pointer[networkObservationFailure]
	baseline                                  string
	identity                                  string
	physical                                  Snapshot
	current                                   *DesktopNetworkReceipt
	old                                       *DesktopNetworkReceipt
	recorded                                  []DesktopNetworkReceipt
	events                                    []Event
}

// The first genuine native failure is independent of observation lock acquisition.
// This lets an expired reader retain an identity failure without waiting beyond
// its caller deadline merely to publish or report that failure.
type networkObservationFailure struct {
	err      error
	reported atomic.Bool
}

func (t *Tracker) failureError() error {
	if failure := t.failure.Load(); failure != nil {
		return failure.err
	}
	return nil
}

func Open(ctx context.Context, original *DesktopNetworkReceipt) (*Tracker, error) {
	return OpenWithLifetime(ctx, ctx, original)
}

// OpenWithLifetime installs and drains the original observer within the
// initialization caller's deadline, while retaining a separate owned lifetime.
// It never refreshes an existing tracker or its physical baseline.
func OpenWithLifetime(initialization, lifetime context.Context, original *DesktopNetworkReceipt) (*Tracker, error) {
	if initialization == nil || initialization.Err() != nil || lifetime == nil || lifetime.Err() != nil {
		return nil, errors.New("network observation requires a live bounded caller")
	}
	if original != nil && (original.Validate() != nil || original.TargetOS != runtime.GOOS) {
		return nil, errors.New("network observation has no exact original native receipt")
	}
	t := &Tracker{ctx: lifetime, initializing: true, current: cloneReceipt(original)}
	n, err := openNativeObserver(t.observe)
	t.native = n
	if err == nil {
		err = t.initialize(initialization)
	}
	if err != nil {
		t.mu.Lock()
		t.failLocked(err)
		t.mu.Unlock()
		if cleanup := t.Close(); cleanup != nil {
			return t, errors.Join(err, cleanup)
		}
		return nil, err
	}
	return t, nil
}

func cloneReceipt(r *DesktopNetworkReceipt) *DesktopNetworkReceipt {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Addresses = append([]string(nil), r.Addresses...)
	copy.Objects = append([]DesktopNetworkObject(nil), r.Objects...)
	return &copy
}

func receiptKey(r *DesktopNetworkReceipt) string {
	if r == nil {
		return ""
	}
	raw, _ := CanonicalDesktopNetworkReceipt(*r)
	return raw
}

func (t *Tracker) initialize(ctx context.Context) error {
	if t.native == nil {
		return errors.New("native network observer was not installed")
	}
	snapshot, err := t.native.Snapshot(ctx)
	if err == nil {
		err = t.native.Barrier(ctx)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		return err
	}
	if ctx.Err() != nil || t.ctx.Err() != nil {
		return errors.New("network initialization lost its original caller or retained lifetime")
	}
	if t.failureError() != nil || len(t.events) != 0 {
		return errors.Join(errors.New("network changed while the observer was being installed"), t.failureError())
	}
	physical, key, err := project(snapshot, t.current)
	if err != nil {
		return err
	}
	t.physical, t.baseline = physical, key
	t.startedWithoutOwnedReceipt = t.current == nil
	sum := sha256.Sum256([]byte(key))
	t.identity = hex.EncodeToString(sum[:])
	t.initializing = false
	return nil
}

func (t *Tracker) failLocked(err error) error {
	if err != nil {
		t.failure.CompareAndSwap(nil, &networkObservationFailure{err: err})
	}
	return t.failureError()
}

func (t *Tracker) observe(event Event, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.failureError() != nil {
		return
	}
	if err != nil {
		t.failLocked(fmt.Errorf("native network observation lost continuity: %w", err))
		return
	}
	if event.Kind == "" || event.Action == "" {
		t.failLocked(errors.New("native network event is incomplete"))
		return
	}
	if runtime.GOOS == "darwin" && event.Kind == "route" && event.Object.Flags&0x20000 != 0 {
		parents := append([]DesktopNetworkObject(nil), t.physical.Objects...)
		if t.current != nil {
			parents = append(parents, t.current.Objects...)
		}
		proved, derivedErr := DesktopDarwinDerivedRoute(event.Object, parents)
		if proved && derivedErr == nil {
			return
		}
		// A newly created native parent may not have reached proof yet. Keep
		// the full event until that exact owner's receipt is supplied.
		if !t.transition && !t.initializing {
			t.failLocked(fmt.Errorf("Darwin route cache event has no captured parent: %w", derivedErr))
			return
		}
		if len(t.events) >= 8192 {
			t.failLocked(errors.New("native network event queue exceeded its bounded transition"))
			return
		}
		t.events = append(t.events, event)
		return
	}
	if !t.initializing && !t.transition {
		t.failLocked(errors.New("network changed outside the exact native transition"))
		return
	}
	// Baseline physical interfaces and routes are never temporary owners. Latch
	// their first notification before a later read can hide an away-and-back.
	for _, link := range t.physical.Links {
		if event.Index != 0 && event.Index == link.Index && (event.LUID == 0 || event.LUID == link.LUID) {
			t.failLocked(errors.New("physical interface, address or route changed during comparison"))
			return
		}
	}
	for _, object := range t.physical.Objects {
		if event.Kind == object.Kind && eventMatchesObject(event, object) {
			t.failLocked(errors.New("physical routing policy changed during comparison"))
			return
		}
	}
	if len(t.events) >= 8192 {
		t.failLocked(errors.New("native network event queue exceeded its bounded transition"))
		return
	}
	t.events = append(t.events, event)
}

func (t *Tracker) reportFailure(result *error) {
	if t == nil || result == nil || *result == nil {
		return
	}
	if failure := t.failure.Load(); failure != nil && errors.Is(*result, failure.err) {
		failure.reported.Store(true)
	}
}

// A joined native error must not become harmless just because it also contains
// cancellation. Only a tree containing exclusively context errors is pure expiry.
func observationExpired(err error) bool {
	if err == nil {
		return false
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !observationExpired(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return observationExpired(one.Unwrap())
	}
	return err == context.Canceled || err == context.DeadlineExceeded
}

func (t *Tracker) Identity() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.identity
}

// Current never calls the application or its selection lock. This permits the
// final durable selection guard to use it while holding the captured app state.
func (t *Tracker) Current() (result error) {
	if t == nil {
		return errors.New("network observer is missing")
	}
	return t.CurrentContext(t.ctx)
}

// CurrentContext drains the same retained event stream using this operation's
// budget. Cancellation/read failure cannot produce a current observation.
func (t *Tracker) CurrentContext(ctx context.Context) (result error) {
	defer t.reportFailure(&result)
	if t == nil || ctx == nil {
		return errors.New("network observer is missing")
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return errors.Join(err, t.failureError())
	}
	if t.closed || t.closing || t.initializing || t.transition || t.failureError() != nil || t.ctx.Err() != nil {
		err := t.failureError()
		if err == nil {
			err = errors.New("network observer is closed, cancelled or inside a native transition")
		}
		t.mu.Unlock()
		return err
	}
	native, current, baseline := t.native, cloneReceipt(t.current), t.baseline
	t.mu.Unlock()
	snapshot, err := native.Snapshot(ctx)
	if err == nil {
		// A complete snapshot may prove a real identity failure even when the
		// following barrier exhausts the caller's remaining budget.
		_, key, projection := project(snapshot, current)
		if projection != nil {
			t.failLocked(projection)
		} else if key != baseline {
			t.failLocked(errors.New("network snapshot changed its frozen physical cohort"))
		}
		if ctx.Err() == nil {
			err = native.Barrier(ctx)
		} else {
			err = ctx.Err()
		}
	}
	if err != nil && !observationExpired(err) {
		t.failLocked(err)
	}
	if failure := t.failureError(); failure != nil {
		return errors.Join(failure, err, ctx.Err())
	}
	if err != nil {
		return err
	}
	if err := LockContext(ctx, &t.mu); err != nil {
		return errors.Join(err, t.failureError())
	}
	defer t.mu.Unlock()
	if t.closed || t.closing || t.transition || t.ctx.Err() != nil || receiptKey(t.current) != receiptKey(current) {
		return t.failLocked(errors.New("network snapshot changed its frozen physical cohort"))
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, t.failureError())
	}
	return t.failureError()
}

func (t *Tracker) Begin(ctx context.Context, original *DesktopNetworkReceipt) (result error) {
	defer t.reportFailure(&result)
	if ctx == nil || ctx.Err() != nil {
		return errors.New("network transition lost its caller")
	}
	if err := t.CurrentContext(ctx); err != nil {
		return t.failLocked(err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ctx.Err() != nil || t.closed || t.closing || t.transition || t.failureError() != nil || receiptKey(original) != receiptKey(t.current) {
		return t.failLocked(errors.New("network transition does not own its original native receipt"))
	}
	t.old, t.recorded, t.events = cloneReceipt(original), nil, nil
	t.transition = true
	return nil
}

func (t *Tracker) Record(receipt DesktopNetworkReceipt) (result error) {
	defer t.reportFailure(&result)
	if t == nil || receipt.Validate() != nil || receipt.TargetOS != runtime.GOOS {
		return errors.New("transient network receipt is malformed or for another platform")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.closing || !t.transition || t.failureError() != nil || t.ctx.Err() != nil {
		return errors.New("transient network receipt has no current transition owner")
	}
	if len(t.recorded) >= 64 {
		return t.failLocked(errors.New("native comparison created too many transient interfaces"))
	}
	for _, old := range t.recorded {
		if old.Incarnation == receipt.Incarnation {
			if receiptKey(&old) != receiptKey(&receipt) {
				return t.failLocked(errors.New("native routing receipt changed within one incarnation"))
			}
			return nil
		}
	}
	t.recorded = append(t.recorded, *cloneReceipt(&receipt))
	return nil
}

func eventMatchesObject(event Event, object DesktopNetworkObject) bool {
	if !event.Partial {
		return event.Object == object
	}
	// Windows route callbacks identify these keys, not a complete live row.
	// Only that exact captured native row may satisfy an incomplete callback.
	a, b := event.Object, object
	return a.Kind == b.Kind && a.Family == b.Family && a.Index == b.Index && a.LUID == b.LUID && a.Destination == b.Destination && a.Gateway == b.Gateway
}

func eventOwnedBy(event Event, receipt *DesktopNetworkReceipt) bool {
	if receipt == nil {
		return false
	}
	switch event.Kind {
	case "link":
		return event.Index == receipt.Index && (event.LUID == 0 || event.LUID == receipt.LUID) && (event.Name == "" || event.Name == receipt.Name)
	case "address":
		if event.Index != receipt.Index || event.LUID != receipt.LUID {
			return false
		}
		for _, address := range receipt.Addresses {
			if event.Address == address || event.Partial && strings.Split(address, "/")[0] == event.Address {
				return true
			}
		}
	case "route", "rule":
		for _, object := range receipt.Objects {
			if eventMatchesObject(event, object) {
				return true
			}
			if runtime.GOOS == "linux" && event.Kind == "rule" && !event.Partial {
				for _, target := range receipt.Objects {
					if DesktopLinuxRuleResolvedBy(event.Object, object, target) {
						return true
					}
				}
			}
			// Linux reports the same exact owned route with RTNH_F_LINKDOWN
			// while its interface is being brought up or retired. This is only
			// a transition classification, never snapshot/physical identity.
			// Keep every other native byte and require this original index.
			if runtime.GOOS == "linux" && event.Kind == "route" && !event.Partial &&
				object.Index == receipt.Index && event.Object.Index == receipt.Index &&
				event.Object.Flags^object.Flags == 16 {
				raw, err := base64.StdEncoding.DecodeString(event.Object.Native)
				if err == nil && len(raw) >= 12 {
					binary.LittleEndian.PutUint32(raw[8:12], object.Flags)
					adjusted, err := ParseDesktopLinuxNetworkObject("route", raw)
					if err == nil && adjusted == object {
						return true
					}
				}
			}
		}
	}
	return false
}

func (t *Tracker) End(ctx context.Context, current *DesktopNetworkReceipt) (result error) {
	defer t.reportFailure(&result)
	if t == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native transition completion lost its caller")
	}
	if current != nil && (current.Validate() != nil || current.TargetOS != runtime.GOOS) {
		return errors.New("native transition completion has no exact current receipt")
	}
	snapshot, err := t.native.Snapshot(ctx)
	if err == nil {
		err = t.native.Barrier(ctx)
	}
	_, key, projection := project(snapshot, current)
	t.mu.Lock()
	defer t.mu.Unlock()
	if ctx.Err() != nil || t.closed || t.closing || !t.transition || t.ctx.Err() != nil {
		return t.failLocked(errors.New("native transition completion has no current observer"))
	}
	if err != nil {
		return t.failLocked(err)
	}
	if projection != nil {
		return t.failLocked(projection)
	}
	if t.failureError() != nil {
		return t.failureError()
	}
	for _, event := range t.events {
		if runtime.GOOS == "darwin" && event.Kind == "route" && event.Object.Flags&0x20000 != 0 {
			parents := append([]DesktopNetworkObject(nil), t.physical.Objects...)
			if t.old != nil {
				parents = append(parents, t.old.Objects...)
			}
			if current != nil {
				parents = append(parents, current.Objects...)
			}
			for _, receipt := range t.recorded {
				parents = append(parents, receipt.Objects...)
			}
			// Identical parent entries in separate captured incarnations still
			// describe one routing key, not two ambiguous route policies.
			seen := map[string]bool{}
			unique := parents[:0]
			for _, parent := range parents {
				if !seen[parent.Key()] {
					seen[parent.Key()] = true
					unique = append(unique, parent)
				}
			}
			proved, derivedErr := DesktopDarwinDerivedRoute(event.Object, unique)
			if proved && derivedErr == nil {
				continue
			}
			return t.failLocked(fmt.Errorf("Darwin transition route cache has no exact captured parent: %w", derivedErr))
		}
		owned := event.Action != "add" && eventOwnedBy(event, t.old) || event.Action != "delete" && eventOwnedBy(event, current)
		// NEWLINK is also the kernel update notification while an old TUN is
		// brought down. Only its exact original index/name can classify it.
		if event.Kind == "link" && eventOwnedBy(event, t.old) {
			owned = true
		}
		for i := range t.recorded {
			owned = owned || eventOwnedBy(event, &t.recorded[i])
		}
		if !owned {
			return t.failLocked(errors.New("native transition contained an unclaimed routing, address or interface event"))
		}
	}
	if key != t.baseline {
		return t.failLocked(errors.New("native transition changed or left effects in its frozen physical cohort"))
	}
	t.current, t.old = cloneReceipt(current), nil
	t.recorded, t.events, t.transition = nil, nil, false
	return nil
}

// Close leaves the original observer attached when native unregister/join
// fails. Its caller must retain this capability and may retry this same Close.
func (t *Tracker) Close() error {
	if t == nil {
		return nil
	}
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	native := t.native
	t.closing = true
	t.mu.Unlock()
	if native != nil {
		if err := native.Close(); err != nil {
			return err
		}
	}
	t.mu.Lock()
	t.closed = true
	failure := t.failure.Load()
	late := failure != nil && !failure.reported.Swap(true)
	t.mu.Unlock()
	if late {
		return fmt.Errorf("late native network event invalidated comparison before joined close: %w", failure.err)
	}
	return nil
}

func project(snapshot Snapshot, receipt *DesktopNetworkReceipt) (Snapshot, string, error) {
	if len(snapshot.Links) > 4096 || len(snapshot.Addresses) > 16384 || len(snapshot.Objects) > 32768 {
		return Snapshot{}, "", errors.New("network snapshot exceeds its bounded inventory")
	}
	result := Snapshot{}
	links := make(map[uint32]Link)
	found := receipt == nil
	for _, link := range snapshot.Links {
		unused := desktopDarwinUnusedInterfaceMatches(link)
		if link.Index == 0 || link.Name == "" || link.MTU <= 0 && !unused || link.darwinUnused != nil && !unused {
			return Snapshot{}, "", fmt.Errorf("network snapshot contains an incomplete interface (index=%d luid=%d name_present=%t mtu=%d flags=%d)", link.Index, link.LUID, link.Name != "", link.MTU, link.Flags)
		}
		if _, exists := links[link.Index]; exists {
			return Snapshot{}, "", errors.New("network snapshot repeats an interface identity")
		}
		links[link.Index] = link
		if receipt != nil && link.Index == receipt.Index {
			if unused || found || link.Name != receipt.Name || link.LUID != receipt.LUID || link.MTU != receipt.MTU {
				return Snapshot{}, "", errors.New("native receipt differs from the observed original TUN")
			}
			found = true
			continue
		}
		result.Links = append(result.Links, link)
	}
	if !found {
		return Snapshot{}, "", errors.New("native receipt has no original interface in the kernel")
	}
	seenAddresses, seenObjects := map[string]bool{}, map[string]int{}
	for _, address := range snapshot.Addresses {
		link, exists := links[address.Index]
		if !exists || address.Prefix == "" || link.LUID != address.LUID || link.MTU <= 0 {
			return Snapshot{}, "", errors.New("network address has no complete interface identity")
		}
		key := fmt.Sprintf("%d/%d/%s", address.Index, address.LUID, address.Prefix)
		if seenAddresses[key] {
			return Snapshot{}, "", errors.New("network snapshot repeats an address")
		}
		seenAddresses[key] = true
		if receipt != nil && address.Index == receipt.Index {
			matched := false
			for _, owned := range receipt.Addresses {
				matched = matched || address.Prefix == owned
			}
			if !matched {
				return Snapshot{}, "", errors.New("native TUN gained an address absent from its receipt")
			}
			continue
		}
		result.Addresses = append(result.Addresses, address)
	}
	if receipt != nil {
		for _, address := range receipt.Addresses {
			if !seenAddresses[fmt.Sprintf("%d/%d/%s", receipt.Index, receipt.LUID, address)] {
				return Snapshot{}, "", errors.New("native TUN lost a captured address")
			}
		}
	}
	for _, object := range snapshot.Objects {
		// Check every captured object before classifying a Darwin derived
		// route. An unused link can never become an active or owned path.
		if link, exists := links[object.Index]; exists && link.MTU <= 0 {
			return Snapshot{}, "", errors.New("unused interface acquired a routing object")
		}
		if runtime.GOOS == "darwin" {
			derived, err := DesktopDarwinDerivedRoute(object, snapshot.Objects)
			if err != nil {
				return Snapshot{}, "", err
			}
			if derived {
				continue
			}
		}
		if object.Validate(runtime.GOOS) != nil {
			return Snapshot{}, "", errors.New("network snapshot contains an incomplete routing object")
		}
		seenObjects[object.Key()]++
		owned := false
		if receipt != nil {
			for _, expected := range receipt.Objects {
				owned = owned || object == expected
			}
		}
		if !owned {
			result.Objects = append(result.Objects, object)
		}
	}
	if receipt != nil {
		for _, object := range receipt.Objects {
			if seenObjects[object.Key()] != 1 {
				return Snapshot{}, "", errors.New("native routing receipt has no unique matching installed object")
			}
		}
	}
	sort.Slice(result.Links, func(i, j int) bool { return result.Links[i].Index < result.Links[j].Index })
	sort.Slice(result.Addresses, func(i, j int) bool {
		a, _ := json.Marshal(result.Addresses[i])
		b, _ := json.Marshal(result.Addresses[j])
		return string(a) < string(b)
	})
	SortDesktopNetworkObjects(result.Objects)
	raw, err := json.Marshal(result)
	return result, string(raw), err
}
