package windowscontroller

import (
	"errors"
	"strings"
	"testing"
)

// These records are observations supplied by the Windows fixture's actual
// GetTokenInformation calls. They are never a launcher or token authority.
type fixtureFreshUACIdentity struct {
	SID                       string
	AuthenticationID, TokenID uint64
	Session                   uint32
	ElevationType, Integrity  uint32
	ImpersonationLevel        uint32
	Primary, Elevated, Admin  bool
	DebugPresent              bool
}

// A linked handle can be SecurityIdentification even though its matching
// logon can later own a real primary process through ordinary Windows runas.
// These comparisons preserve the observed carrier; they never turn a linked
// identity into launch authority.
func fixtureFreshUACAuthorityMatches(a, b fixtureFreshUACIdentity) bool {
	a.TokenID, b.TokenID = 0, 0
	a.Primary, b.Primary = false, false
	a.ImpersonationLevel, b.ImpersonationLevel = 0, 0
	return a == b
}

func fixtureFreshUACObservedCarrier(a fixtureFreshUACIdentity) bool {
	return a.TokenID != 0 && ((a.Primary && a.ImpersonationLevel == 0) || (!a.Primary && a.ImpersonationLevel == 1))
}

func fixtureFreshUACPrimaryMatches(actual, observed fixtureFreshUACIdentity) bool {
	return actual.Primary && actual.ImpersonationLevel == 0 && fixtureFreshUACObservedCarrier(actual) &&
		fixtureFreshUACObservedCarrier(observed) && fixtureFreshUACAuthorityMatches(actual, observed)
}

// ReadPair already proves the native reciprocal links. Only the independently
// running Full side is primary here; its Limited link may be identification.
func fixtureFreshUACFullWorkerMatches(limited, full, expectedLimited, expectedFull fixtureFreshUACIdentity) bool {
	return fixtureFreshUACObservedCarrier(limited) && fixtureFreshUACObservedCarrier(expectedLimited) &&
		fixtureFreshUACAuthorityMatches(limited, expectedLimited) && fixtureFreshUACPrimaryMatches(full, expectedFull)
}

type fixtureFreshUACParentObservation struct {
	PID     uint32
	Created int64
	Token   fixtureFreshUACIdentity
	Live    bool
}

// Native callers hold the parent capability's mutex around this state. The
// portable test executes the same retirement/lease rules without OS handles.
type fixtureFreshUACParentLease struct {
	operation      uint64
	active, closed bool
}

func (lease *fixtureFreshUACParentLease) begin() (uint64, error) {
	if lease.closed || lease.active || lease.operation == ^uint64(0) {
		return 0, errors.New("fresh Limited source cannot create another owned access lease")
	}
	lease.operation++
	lease.active = true
	return lease.operation, nil
}

func (lease *fixtureFreshUACParentLease) current(operation uint64) bool {
	return operation != 0 && !lease.closed && lease.active && operation == lease.operation
}

func (lease *fixtureFreshUACParentLease) release(operation uint64) {
	if operation == lease.operation {
		lease.active = false
	}
}

func (lease *fixtureFreshUACParentLease) retire() error {
	if lease.active {
		return errors.New("fresh Limited primary source cannot close before its exact thread access joins")
	}
	lease.closed = true
	return nil
}

// This compares the same retained process and primary token object. Linked
// observations may have another carrier/TokenID; neither same-object primary
// recheck is allowed to use that deliberately broader comparison.
func fixtureFreshUACParentMatches(captured, current fixtureFreshUACParentObservation, held, expected, linked fixtureFreshUACIdentity) bool {
	return captured.Live && current.Live && captured.PID != 0 && captured.PID == current.PID &&
		captured.Created > 0 && captured.Created == current.Created && captured.Token == current.Token && held == captured.Token &&
		fixtureFreshUACPrimaryMatches(held, expected) && held.AuthenticationID != 0 &&
		held.ElevationType == 3 && held.Integrity == 8192 && !held.Elevated && !held.Admin && !held.DebugPresent &&
		fixtureFreshUACObservedCarrier(linked) && fixtureFreshUACAuthorityMatches(held, linked)
}

// The native attempt includes its locked-thread reversion; its caller joins
// that thread before releasing the retained source. A failed operation must
// still keep the final ownership failure visible to its caller.
func fixtureFreshUACCheckedAccess(current func() error, attempt func() error) error {
	if current == nil || attempt == nil {
		return errors.New("fresh Limited access has no exact ownership checkpoint or native attempt")
	}
	if err := current(); err != nil {
		return err
	}
	return errors.Join(attempt(), current())
}

func TestFixtureFreshUACFullWorkerPreservesObservedCarrier(t *testing.T) {
	sid := "S-1-5-21-100-200-300-1007"
	limited := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 41, TokenID: 101, Session: 2, ElevationType: 3, Integrity: 8192, Primary: true}
	observedFull := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 42, TokenID: 102, Session: 2, ElevationType: 2, Integrity: 12288, ImpersonationLevel: 1, Elevated: true, Admin: true, DebugPresent: true}
	actualFull := observedFull
	actualFull.Primary, actualFull.ImpersonationLevel, actualFull.TokenID = true, 0, 103
	for _, carrier := range []string{"primary-link", "identification-link"} {
		t.Run(carrier, func(t *testing.T) {
			linked := limited
			if carrier == "identification-link" {
				linked.Primary, linked.ImpersonationLevel, linked.TokenID = false, 1, 104
			}
			if err := fixtureFreshUACObservedPairValid(sid, actualFull, linked, actualFull, limited, observedFull); err != nil ||
				!fixtureFreshUACFullWorkerMatches(linked, actualFull, limited, observedFull) {
				t.Fatal("real Full primary lost its reciprocal observational Limited carrier", err)
			}
			if carrier == "identification-link" && fixtureFreshUACPrimaryMatches(linked, limited) {
				t.Fatal("linked Limited observation was relabeled as a primary process")
			}
		})
	}
	for _, fault := range []string{"identification-full", "empty-full-object", "empty-link-object", "limited-logon", "full-logon", "limited-session", "full-session", "wrong-user", "limited-integrity", "limited-admin", "limited-debug", "invalid-link-carrier"} {
		t.Run(fault, func(t *testing.T) {
			linked, full := limited, actualFull
			linked.Primary, linked.ImpersonationLevel = false, 1
			switch fault {
			case "identification-full":
				full.Primary, full.ImpersonationLevel = false, 1
			case "empty-full-object":
				full.TokenID = 0
			case "empty-link-object":
				linked.TokenID = 0
			case "limited-logon":
				linked.AuthenticationID++
			case "full-logon":
				full.AuthenticationID++
			case "limited-session":
				linked.Session++
			case "full-session":
				full.Session++
			case "wrong-user":
				linked.SID += "1"
			case "limited-integrity":
				linked.Integrity = 12288
			case "limited-admin":
				linked.Admin = true
			case "limited-debug":
				linked.DebugPresent = true
			case "invalid-link-carrier":
				linked.ImpersonationLevel = 2
			}
			if fixtureFreshUACFullWorkerMatches(linked, full, limited, observedFull) {
				t.Fatal("Full worker accepted a changed logon or identification-only process", fault)
			}
		})
	}
}

func TestFixtureFreshUACRetainedParentRequiresActualPrimary(t *testing.T) {
	expected := fixtureFreshUACIdentity{SID: "S-1-5-21-100-200-300-1007", AuthenticationID: 41, TokenID: 101, Session: 2, ElevationType: 3, Integrity: 8192, Primary: true}
	held := expected
	held.TokenID = 103 // The actual process may own a duplicate of its logon token.
	linked := expected
	linked.TokenID, linked.Primary, linked.ImpersonationLevel = 104, false, 1
	captured := fixtureFreshUACParentObservation{PID: 711, Created: 123456789, Token: held, Live: true}
	for _, fault := range []string{"owned", "identification-source", "current-identification", "held-identification", "wrong-parent", "reused-pid", "exited-parent", "revoked-original", "held-token-replaced", "process-token-replaced", "empty-token", "empty-process", "empty-incarnation", "empty-logon", "wrong-logon", "wrong-session", "wrong-user", "elevated-source", "debug-source", "admin-source", "high-integrity", "default-token", "wrong-link-logon", "invalid-link-carrier"} {
		t.Run(fault, func(t *testing.T) {
			original, current, token, observed := captured, captured, held, linked
			switch fault {
			case "identification-source":
				original.Token.Primary, original.Token.ImpersonationLevel = false, 1
				current.Token, token = original.Token, original.Token
			case "current-identification":
				current.Token.Primary, current.Token.ImpersonationLevel = false, 1
			case "held-identification":
				token.Primary, token.ImpersonationLevel = false, 1
			case "wrong-parent":
				current.PID++
			case "reused-pid":
				current.Created++
			case "exited-parent":
				current.Live = false
			case "revoked-original":
				original.Live = false
			case "held-token-replaced":
				token.TokenID++
			case "process-token-replaced":
				current.Token.TokenID++
			case "empty-token":
				original.Token.TokenID, current.Token.TokenID, token.TokenID = 0, 0, 0
			case "empty-process":
				original.PID, current.PID = 0, 0
			case "empty-incarnation":
				original.Created, current.Created = 0, 0
			case "empty-logon":
				original.Token.AuthenticationID, current.Token.AuthenticationID, token.AuthenticationID = 0, 0, 0
			case "wrong-logon":
				current.Token.AuthenticationID++
			case "wrong-session":
				current.Token.Session++
			case "wrong-user":
				current.Token.SID += "1"
			case "elevated-source":
				current.Token.Elevated = true
			case "debug-source":
				current.Token.DebugPresent = true
			case "admin-source":
				current.Token.Admin = true
			case "high-integrity":
				current.Token.Integrity = 12288
			case "default-token":
				current.Token.ElevationType = 1
			case "wrong-link-logon":
				observed.AuthenticationID++
			case "invalid-link-carrier":
				observed.ImpersonationLevel = 2
			}
			if fixtureFreshUACParentMatches(original, current, token, expected, observed) != (fault == "owned") {
				t.Fatal("retained Limited source accepted a different process/token or lost genuine primary authority", fault)
			}
		})
	}
}

func TestFixtureFreshUACAccessRetainsCleanupAndOwnershipFailure(t *testing.T) {
	for _, phase := range []string{"owned", "revoked-before", "revoked-after", "native-denied", "reversion-failed", "native-and-owner-failed"} {
		t.Run(phase, func(t *testing.T) {
			ownerFailure, nativeFailure := errors.New("captured parent retired"), errors.New("native access or reversion failed")
			checks, attempts := 0, 0
			current := func() error {
				checks++
				if phase == "revoked-before" || checks == 2 && (phase == "revoked-after" || phase == "native-and-owner-failed") {
					return ownerFailure
				}
				return nil
			}
			err := fixtureFreshUACCheckedAccess(current, func() error {
				attempts++
				if phase == "native-denied" || phase == "reversion-failed" || phase == "native-and-owner-failed" {
					return nativeFailure
				}
				return nil
			})
			wantAttempts, wantChecks := 1, 2
			if phase == "revoked-before" {
				wantAttempts, wantChecks = 0, 1
			}
			wantOwner := phase == "revoked-before" || phase == "revoked-after" || phase == "native-and-owner-failed"
			wantNative := phase == "native-denied" || phase == "reversion-failed" || phase == "native-and-owner-failed"
			if attempts != wantAttempts || checks != wantChecks || errors.Is(err, ownerFailure) != wantOwner || errors.Is(err, nativeFailure) != wantNative || (err == nil) != (phase == "owned") {
				t.Fatal("native attempt escaped its before/after owner or lost cleanup failure", checks, attempts, err)
			}
		})
	}
	if fixtureFreshUACCheckedAccess(nil, func() error { t.Fatal("unowned attempt executed"); return nil }) == nil || fixtureFreshUACCheckedAccess(func() error { return nil }, nil) == nil {
		t.Fatal("missing source or native attempt was accepted")
	}
}

func TestFixtureFreshUACParentLeaseJoinsBeforeRetirement(t *testing.T) {
	var lease fixtureFreshUACParentLease
	first, err := lease.begin()
	if err != nil || !lease.current(first) || lease.current(0) {
		t.Fatal("original access lease was not captured", err)
	}
	if _, err := lease.begin(); err == nil {
		t.Fatal("a concurrent access borrowed the held primary token")
	}
	if lease.retire() == nil || !lease.current(first) {
		t.Fatal("retained primary closed before its exact access joined")
	}
	lease.release(first + 1)
	if !lease.current(first) {
		t.Fatal("a foreign release retired the captured access")
	}
	lease.release(first)
	second, err := lease.begin()
	if err != nil || first == second {
		t.Fatal("joined access did not permit a separately captured next lease", err)
	}
	lease.release(first)
	if lease.current(first) || !lease.current(second) {
		t.Fatal("an older release changed its replacement access owner")
	}
	lease.release(second)
	if lease.retire() != nil || lease.current(second) {
		t.Fatal("joined source could not retire")
	}
	if _, err := lease.begin(); err == nil {
		t.Fatal("closed primary source acquired another access")
	}
	lease = fixtureFreshUACParentLease{operation: ^uint64(0)}
	if _, err := lease.begin(); err == nil || lease.active {
		t.Fatal("access generation wrapped to a stale lease")
	}
}

func fixtureFreshUACObservedPairValid(sid string, root, limited, full, backLimited, backFull fixtureFreshUACIdentity) error {
	if !root.Primary || root.ImpersonationLevel != 0 ||
		!strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "-500") || limited.SID != sid || full.SID != sid ||
		!fixtureFreshUACObservedCarrier(root) || !fixtureFreshUACObservedCarrier(limited) || !fixtureFreshUACObservedCarrier(full) ||
		!fixtureFreshUACObservedCarrier(backLimited) || !fixtureFreshUACObservedCarrier(backFull) ||
		limited.AuthenticationID == 0 || full.AuthenticationID == 0 || limited.Session != full.Session ||
		limited.ElevationType != 3 || full.ElevationType != 2 || limited.Integrity != 8192 || full.Integrity != 12288 ||
		limited.Elevated || limited.Admin || limited.DebugPresent || !full.Elevated || !full.Admin ||
		!fixtureFreshUACAuthorityMatches(limited, backLimited) || !fixtureFreshUACAuthorityMatches(full, backFull) ||
		(root.ElevationType == 3 && !fixtureFreshUACSameIdentity(root, limited)) ||
		(root.ElevationType == 2 && !fixtureFreshUACSameIdentity(root, full)) || (root.ElevationType != 2 && root.ElevationType != 3) {
		return errors.New("fresh UAC observations lost their original primary root or reciprocal logon identities")
	}
	return nil
}

func fixtureFreshUACSameIdentity(a, b fixtureFreshUACIdentity) bool {
	// Creating a primary process can duplicate the Full token object. Its
	// TokenID may differ from the reciprocal link; its logon, session, and
	// effective authority must not. Both native TokenIDs are still recorded.
	a.TokenID, b.TokenID = 0, 0
	return a == b
}

func fixtureFreshUACPairValid(sid string, limited, full, backLimited, backFull fixtureFreshUACIdentity) error {
	if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "-500") ||
		limited.SID != sid || full.SID != sid || !limited.Primary || !full.Primary ||
		limited.ImpersonationLevel != 0 || full.ImpersonationLevel != 0 ||
		limited.AuthenticationID == 0 || full.AuthenticationID == 0 ||
		limited.TokenID == 0 || full.TokenID == 0 || backLimited.TokenID == 0 || backFull.TokenID == 0 ||
		limited.Session != full.Session || limited.ElevationType != 3 || full.ElevationType != 2 ||
		limited.Integrity != 8192 || full.Integrity != 12288 || limited.Elevated || limited.Admin || limited.DebugPresent ||
		!full.Elevated || !full.Admin || !fixtureFreshUACSameIdentity(limited, backLimited) || !fixtureFreshUACSameIdentity(full, backFull) {
		return errors.New("fresh interactive logon did not return a reciprocal native Limited/Full pair")
	}
	// Windows may retain distinct authentication LUIDs for the two logons.
	// Capture and compare each side independently; do not assert equality.
	return nil
}

func TestFixtureFreshUACLinkedObservationIsNotLaunchAuthority(t *testing.T) {
	sid := "S-1-5-21-100-200-300-1007"
	limited := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 41, TokenID: 101, Session: 2, ElevationType: 3, Integrity: 8192, Primary: true}
	observedFull := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 42, TokenID: 102, Session: 2, ElevationType: 2, Integrity: 12288, ImpersonationLevel: 1, Elevated: true, Admin: true, DebugPresent: true}
	if err := fixtureFreshUACObservedPairValid(sid, limited, limited, observedFull, limited, observedFull); err != nil {
		t.Fatal("native identification link lost its bounded observational role", err)
	}
	if fixtureFreshUACPairValid(sid, limited, observedFull, limited, observedFull) == nil || fixtureFreshUACPrimaryMatches(observedFull, observedFull) {
		t.Fatal("identification-only linked handle acquired primary launch authority")
	}
	actualFull := observedFull
	actualFull.Primary, actualFull.ImpersonationLevel, actualFull.TokenID = true, 0, 103
	if !fixtureFreshUACPrimaryMatches(actualFull, observedFull) {
		t.Fatal("independently observed primary process could not match its captured Full logon")
	}
	for _, name := range []string{"identification-root", "identification-root-and-pair", "anonymous-link", "impersonating-link", "delegating-link", "no-link-object", "wrong-link-user", "wrong-link-session", "wrong-limited-logon", "wrong-full-logon", "wrong-limited-integrity", "default-full", "elevated-limited", "limited-debug", "limited-admin", "unlinked-back", "root-replaced", "built-in-administrator"} {
		t.Run("observation/"+name, func(t *testing.T) {
			owner, root, l, f, backL, backF := sid, limited, limited, observedFull, limited, observedFull
			switch name {
			case "identification-root":
				root.Primary, root.ImpersonationLevel = false, 1
			case "identification-root-and-pair":
				root.Primary, l.Primary, backL.Primary = false, false, false
				root.ImpersonationLevel, l.ImpersonationLevel, backL.ImpersonationLevel = 1, 1, 1
			case "anonymous-link":
				f.ImpersonationLevel = 0
			case "impersonating-link":
				f.ImpersonationLevel = 2
			case "delegating-link":
				f.ImpersonationLevel = 3
			case "no-link-object":
				backF.TokenID = 0
			case "wrong-link-user":
				f.SID += "1"
			case "wrong-link-session":
				f.Session++
			case "wrong-limited-logon":
				backL.AuthenticationID++
			case "wrong-full-logon":
				backF.AuthenticationID++
			case "wrong-limited-integrity":
				l.Integrity = 12288
			case "default-full":
				f.ElevationType = 1
			case "elevated-limited":
				l.Elevated = true
			case "limited-debug":
				l.DebugPresent = true
			case "limited-admin":
				l.Admin = true
			case "unlinked-back":
				backL.SID += "1"
			case "root-replaced":
				root.AuthenticationID++
			case "built-in-administrator":
				owner = "S-1-5-21-100-200-300-500"
				root.SID, l.SID, f.SID, backL.SID, backF.SID = owner, owner, owner, owner, owner
			}
			if fixtureFreshUACObservedPairValid(owner, root, l, f, backL, backF) == nil {
				t.Fatal("invalid native reciprocal observation passed", name)
			}
		})
	}
	for _, name := range []string{"identification-process", "wrong-user", "wrong-logon", "wrong-session", "wrong-integrity", "default-token", "not-elevated", "not-admin", "changed-debug", "missing-object", "invalid-observation"} {
		t.Run("process/"+name, func(t *testing.T) {
			actual, observed := actualFull, observedFull
			switch name {
			case "identification-process":
				actual.Primary, actual.ImpersonationLevel = false, 1
			case "wrong-user":
				actual.SID += "1"
			case "wrong-logon":
				actual.AuthenticationID++
			case "wrong-session":
				actual.Session++
			case "wrong-integrity":
				actual.Integrity = 8192
			case "default-token":
				actual.ElevationType = 1
			case "not-elevated":
				actual.Elevated = false
			case "not-admin":
				actual.Admin = false
			case "changed-debug":
				actual.DebugPresent = false
			case "missing-object":
				actual.TokenID = 0
			case "invalid-observation":
				observed.ImpersonationLevel = 3
			}
			if fixtureFreshUACPrimaryMatches(actual, observed) {
				t.Fatal("unproved process acquired the observed Full authority", name)
			}
		})
	}
}

func TestFixtureFreshUACRequiresReciprocalNativeAuthority(t *testing.T) {
	sid := "S-1-5-21-100-200-300-1007"
	limited := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 41, TokenID: 101, Session: 2, ElevationType: 3, Integrity: 8192, Primary: true}
	full := fixtureFreshUACIdentity{SID: sid, AuthenticationID: 42, TokenID: 102, Session: 2, ElevationType: 2, Integrity: 12288, Primary: true, Elevated: true, Admin: true, DebugPresent: true}
	if err := fixtureFreshUACPairValid(sid, limited, full, limited, full); err != nil {
		t.Fatal("genuine pair shape with separately captured logons was refused", err)
	}
	duplicate := full
	duplicate.TokenID++
	if err := fixtureFreshUACPairValid(sid, limited, duplicate, limited, full); err != nil {
		t.Fatal("a duplicated Full process token changed no captured logon authority", err)
	}
	for _, name := range []string{"natural-administrator", "constructed-medium", "wrong-user", "built-in-administrator", "wrong-session", "limited-logon", "full-logon", "unlinked-limited", "unlinked-full", "limited-debug", "limited-admin", "limited-elevated", "wrong-integrity", "impersonation", "missing-object"} {
		t.Run(name, func(t *testing.T) {
			owner, l, f, backL, backF := sid, limited, full, limited, full
			switch name {
			case "natural-administrator":
				f.ElevationType, backF.ElevationType = 1, 1
			case "constructed-medium":
				l.ElevationType, backL.ElevationType = 1, 1
			case "wrong-user":
				l.SID += "1"
			case "built-in-administrator":
				owner = "S-1-5-21-100-200-300-500"
				l.SID, f.SID, backL.SID, backF.SID = owner, owner, owner, owner
			case "wrong-session":
				l.Session++
			case "limited-logon":
				backL.AuthenticationID++
			case "full-logon":
				backF.AuthenticationID++
			case "unlinked-limited":
				backL.SID += "1"
			case "unlinked-full":
				backF.Session++
			case "limited-debug":
				l.DebugPresent, backL.DebugPresent = true, true
			case "limited-admin":
				l.Admin, backL.Admin = true, true
			case "limited-elevated":
				l.Elevated, backL.Elevated = true, true
			case "wrong-integrity":
				l.Integrity, backL.Integrity = 12288, 12288
			case "impersonation":
				f.Primary, backF.Primary = false, false
			case "missing-object":
				backF.TokenID = 0
			}
			if fixtureFreshUACPairValid(owner, l, f, backL, backF) == nil {
				t.Fatal("nonreciprocal or manufactured authority was accepted", name)
			}
		})
	}
}
