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
	Primary, Elevated, Admin  bool
	DebugPresent              bool
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
