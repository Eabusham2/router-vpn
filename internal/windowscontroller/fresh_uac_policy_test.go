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
