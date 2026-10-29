package mobiletor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestDesktopDarwinGuardianUIDAbsenceWait(t *testing.T) {
	const uid = 0x40000001
	for _, name := range []string{"immediate", "delayed", "never", "lookup-error", "cancelled", "parent-deadline", "late-absence"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if name == "cancelled" {
					cancel()
				}
				if name == "parent-deadline" {
					var deadlineCancel context.CancelFunc
					ctx, deadlineCancel = context.WithTimeout(ctx, 30*time.Millisecond)
					defer deadlineCancel()
				}
				lookupFailure := errors.New("independent native lookup failed")
				calls := 0
				err := desktopDarwinWaitForUIDAbsence(ctx, uid, func(actual uint32) (bool, error) {
					calls++
					if actual != uid {
						t.Fatal("native UID absence probe borrowed another capture")
					}
					switch name {
					case "immediate":
						return true, nil
					case "delayed":
						return calls >= 3, nil
					case "lookup-error":
						return false, lookupFailure
					case "late-absence":
						time.Sleep(3 * time.Second)
						return true, nil
					default:
						return false, nil
					}
				})
				elapsed := time.Since(start)
				switch name {
				case "immediate":
					if err != nil || calls != 1 || elapsed != 0 {
						t.Fatal("already absent native UID did not finish its exact readback", calls, elapsed, err)
					}
				case "delayed":
					if err != nil || calls != 3 || elapsed != 40*time.Millisecond {
						t.Fatal("cached occupied UID was discarded before independent absent readback", calls, elapsed, err)
					}
				case "never":
					if !errors.Is(err, context.DeadlineExceeded) || calls < 2 || elapsed != 2*time.Second {
						t.Fatal("occupied native UID escaped its bounded quarantine", calls, elapsed, err)
					}
				case "lookup-error":
					if !errors.Is(err, lookupFailure) || calls != 1 || elapsed != 0 {
						t.Fatal("failed native UID lookup was treated as absent or retried away", calls, elapsed, err)
					}
				case "cancelled":
					if !errors.Is(err, context.Canceled) || calls != 0 || elapsed != 0 {
						t.Fatal("cancelled UID retirement acquired a new native readback", calls, elapsed, err)
					}
				case "parent-deadline":
					if !errors.Is(err, context.DeadlineExceeded) || calls != 2 || elapsed != 30*time.Millisecond {
						t.Fatal("native UID retirement extended its captured caller deadline", calls, elapsed, err)
					}
				case "late-absence":
					if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
						t.Fatal("late native UID absence installed a retired proof", calls, elapsed, err)
					}
				}
			})
		})
	}
	for _, invalid := range []uint32{0, 0x3fffffff, 0x80000000} {
		if err := desktopDarwinWaitForUIDAbsence(context.Background(), invalid, func(uint32) (bool, error) {
			t.Fatal("invalid UID acquired native lookup authority")
			return true, nil
		}); err == nil {
			t.Fatal("invalid UID acquired retirement authority")
		}
	}
	if desktopDarwinWaitForUIDAbsence(nil, uid, func(uint32) (bool, error) { return true, nil }) == nil ||
		desktopDarwinWaitForUIDAbsence(context.Background(), uid, nil) == nil {
		t.Fatal("missing retirement context or native observer was accepted")
	}
}

func TestDesktopDarwinGuardianUIDObserverProtocol(t *testing.T) {
	request := desktopDarwinUIDRequest{Operation: "observe-uid", Sequence: 1, Capture: desktopSocketFixtureCapture(), UID: 0x40000001}
	if err := request.validate(); err != nil {
		t.Fatal("captured read-only observer request was rejected", err)
	}
	ack := request.acknowledgment()
	if ack.Operation != "observed-uid-ack" || ack.Sequence != 2 || ack.Capture != request.Capture || ack.UID != request.UID || ack.validate() == nil {
		t.Fatal("observer acknowledgment changed authority or became a reusable lookup request")
	}
	for _, change := range []struct {
		name string
		edit func(*desktopDarwinUIDRequest)
	}{
		{"operation", func(r *desktopDarwinUIDRequest) { r.Operation = "prepare" }},
		{"empty-operation", func(r *desktopDarwinUIDRequest) { r.Operation = "" }},
		{"sequence", func(r *desktopDarwinUIDRequest) { r.Sequence++ }},
		{"zero-sequence", func(r *desktopDarwinUIDRequest) { r.Sequence = 0 }},
		{"capture", func(r *desktopDarwinUIDRequest) { r.Capture.SessionID = "" }},
		{"root-uid", func(r *desktopDarwinUIDRequest) { r.UID = 0 }},
		{"below-managed-uid", func(r *desktopDarwinUIDRequest) { r.UID = 0x3fffffff }},
		{"above-managed-uid", func(r *desktopDarwinUIDRequest) { r.UID = 0x80000000 }},
	} {
		t.Run("request/"+change.name, func(t *testing.T) {
			changed := request
			change.edit(&changed)
			if changed.validate() == nil {
				t.Fatal("invalid observer request acquired a native lookup")
			}
			if absent, err := (desktopDarwinUIDReply{Sequence: changed.Sequence, Capture: changed.Capture, UID: changed.UID, State: "absent"}).absent(changed); err == nil || absent {
				t.Fatal("invalid observer request acquired an absent receipt")
			}
		})
	}
	reply := desktopDarwinUIDReply{Sequence: request.Sequence, Capture: request.Capture, UID: request.UID, State: "absent"}
	for _, state := range []string{"absent", "occupied"} {
		observed := reply
		observed.State = state
		if absent, err := observed.absent(request); err != nil || absent != (state == "absent") {
			t.Fatal("explicit native observation lost its state", state, absent, err)
		}
	}
	for _, change := range []struct {
		name string
		edit func(*desktopDarwinUIDReply)
	}{
		{"sequence", func(r *desktopDarwinUIDReply) { r.Sequence++ }},
		{"session", func(r *desktopDarwinUIDReply) { r.Capture.SessionID = strings.Repeat("9", 32) }},
		{"source", func(r *desktopDarwinUIDReply) { r.Capture.SourceSHA256 = strings.Repeat("9", 64) }},
		{"network", func(r *desktopDarwinUIDReply) { r.Capture.NetworkID = strings.Repeat("9", 32) }},
		{"uid", func(r *desktopDarwinUIDReply) { r.UID++ }},
		{"unknown", func(r *desktopDarwinUIDReply) { r.State = "unknown" }},
		{"empty", func(r *desktopDarwinUIDReply) { r.State = "" }},
		{"error", func(r *desktopDarwinUIDReply) { r.State = "lookup-error" }},
		{"masked", func(r *desktopDarwinUIDReply) { r.State = " absent" }},
	} {
		t.Run("reply/"+change.name, func(t *testing.T) {
			changed := reply
			change.edit(&changed)
			if absent, err := changed.absent(request); err == nil || absent {
				t.Fatal("unknown or mismatched native receipt released an identity")
			}
		})
	}
}

func TestDesktopDarwinUIDSearchRequiresOneExactLocalAndNativeIdentity(t *testing.T) {
	account := "_rvpnt_" + strings.Repeat("1", 20)
	const uid = 0x40000001
	raw := account + "\t\tUniqueID = (\n    1073741825\n)\n"
	for _, value := range []string{raw, account + "\t\tUniqueID = (1073741825)\n"} {
		if err := desktopDarwinUIDSearchProof([]byte(value), account, uid, true); err != nil {
			t.Fatal("actual dscl search description lost its single captured UID", err)
		}
	}
	for _, change := range []struct{ name, value string }{
		{"list-format", account + " 1073741825\n"},
		{"missing", ""},
		{"duplicate-record", raw + raw},
		{"foreign-record", raw + strings.Replace(raw, account, "_rvpnt_"+strings.Repeat("2", 20), 1)},
		{"foreign-name", strings.Replace(raw, account, "_rvpnt_"+strings.Repeat("2", 20), 1)},
		{"other-uid", strings.Replace(raw, "1073741825", "1073741826", 1)},
		{"uid-prefix", strings.Replace(raw, "1073741825", "01073741825", 1)},
		{"two-values", strings.Replace(raw, "1073741825", "1073741825, 1073741825", 1)},
		{"other-attribute", strings.Replace(raw, "UniqueID", "PrimaryGroupID", 1)},
		{"native-alias", strings.Replace(raw, "UniqueID", "dsAttrTypeNative:UniqueID", 1)},
		{"unrequested-raw-prefix", strings.Replace(raw, "UniqueID", "dsAttrTypeStandard:UniqueID", 1)},
		{"missing-assignment", strings.Replace(raw, "=", "", 1)},
		{"missing-array", strings.NewReplacer("(", "", ")", "").Replace(raw)},
		{"nested-array", strings.Replace(raw, "(", "((", 1)},
		{"quoted-value", strings.Replace(raw, "1073741825", "\"1073741825\"", 1)},
		{"trailing-output", raw + "another-field: credential-value\n"},
		{"control", raw + "\x00"},
		{"unicode-space", strings.Replace(raw, " = ", "\u00a0=\u00a0", 1)},
		{"unbounded", raw + strings.Repeat("x", 4096)},
	} {
		t.Run(change.name, func(t *testing.T) {
			if err := desktopDarwinUIDSearchProof([]byte(change.value), account, uid, true); err == nil {
				t.Fatal("ambiguous or foreign local UID search acquired exclusive identity")
			}
		})
	}
	if err := desktopDarwinUIDSearchProof([]byte(raw), account, uid, false); err == nil {
		t.Fatal("local UID search replaced independent system directory ownership")
	}
	for _, capture := range []struct {
		account string
		uid     uint32
	}{{"foreign", uid}, {account, 0}, {account, 0x80000000}} {
		if err := desktopDarwinUIDSearchProof([]byte(raw), capture.account, capture.uid, true); err == nil {
			t.Fatal("invalid caller capture acquired UID authority")
		}
	}
}

func TestDesktopDarwinUIDSearchDiagnosticsDoNotDiscloseDirectoryValues(t *testing.T) {
	account := "_rvpnt_" + strings.Repeat("1", 20)
	raw := account + "\t\tUniqueID = (\n    private-directory-value\n)\n"
	err := desktopDarwinUIDSearchProof([]byte(raw), account, 0x40000001, false)
	if err == nil {
		t.Fatal("foreign UID text unexpectedly passed")
	}
	message := err.Error()
	if len(message) > 256 || strings.ContainsAny(message, "\r\n\t") || strings.Contains(message, account) || strings.Contains(message, "private-directory-value") || strings.Contains(message, "1073741825") {
		t.Fatal("UID proof diagnostics disclosed directory values or lost their bound")
	}
	for _, part := range []string{"fields=6", "shape=true", "name_match=true", "key_match=true", "value_match=false", "native_match=false"} {
		if !strings.Contains(message, part) {
			t.Fatal("UID proof diagnostics lost the failed boundary", part, message)
		}
	}
}

func TestDesktopDarwinAccountDiagnosticsRemainBoundedAndDoNotDiscloseValues(t *testing.T) {
	account := "_rvpnt_" + strings.Repeat("1", 20)
	values := map[string]string{
		"RecordName": account, "UniqueID": "1073741825", "PrimaryGroupID": "65534",
		"NFSHomeDirectory": "/var/empty", "UserShell": "/usr/bin/false", "Password": "*",
		"AuthenticationAuthority": ";DisabledUser;", desktopDarwinHiddenAttribute: "1", "GeneratedUID": strings.Repeat("a", 36),
	}
	baseline := desktopDarwinAccountAttributeFailure(values, account, 0x40000001).Error()
	if strings.Count(baseline, "equal=true") != 8 || !strings.Contains(baseline, "fields=9;") {
		t.Fatal("the diagnostic lost the exact requested account comparison", baseline)
	}
	// The fixture is deliberately unlike a disabled account. No alternate
	// spelling or plausible masking changes the caller's rejection predicate.
	delete(values, desktopDarwinHiddenAttribute)
	values["IsHidden"] = "1"
	secret := "private-value\n\t\r\"" + strings.Repeat("s", 16384)
	values["Password"] = secret
	values["AuthenticationAuthority"] = secret
	values["NFSHomeDirectory"] = secret
	values[secret] = secret
	actual := desktopDarwinAccountAttributeFailure(values, account, 0x40000001).Error()
	if len(actual) > 1024 || strings.ContainsAny(actual, "\r\n\t") || strings.Contains(actual, "private-value") ||
		strings.Contains(actual, strings.Repeat("s", 32)) || strings.Contains(actual, account) {
		t.Fatal("account diagnostics disclosed directory values or lost their bound")
	}
	if !strings.Contains(actual, "IsHidden(present=false equal=false bytes=0 native=false standard=false)") ||
		!strings.Contains(actual, "Password(present=true equal=false") || strings.Count(actual, "equal=true") != 4 {
		t.Fatal("account diagnostics hid the differing native attribute shape", actual)
	}
	values["dsAttrTypeStandard:IsHidden"] = "1"
	if value := desktopDarwinAccountAttributeFailure(values, account, 0x40000001).Error(); !strings.Contains(value, "IsHidden(present=false equal=false bytes=0 native=false standard=true)") {
		t.Fatal("ambiguous aliases were not distinguished", value)
	}
}

func TestDesktopDarwinAccountReadbackPreservesExactDisabledNativeIdentity(t *testing.T) {
	account := "_rvpnt_" + strings.Repeat("1", 20)
	raw := "RecordName: " + account + "\nUniqueID: 1073741825\nPrimaryGroupID: 65534\n" +
		"NFSHomeDirectory: /var/empty\nUserShell: /usr/bin/false\nPassword: *\n" +
		"AuthenticationAuthority: ;DisabledUser;\ndsAttrTypeNative:IsHidden: 1\n" +
		"GeneratedUID: 12345678-1234-1234-1234-123456789ABC\n"
	values, err := desktopDarwinParseAccountRecord([]byte(raw), account, 0x40000001)
	if err != nil || len(values) != 9 || values[desktopDarwinHiddenAttribute] != "1" || values["GeneratedUID"] != "12345678-1234-1234-1234-123456789ABC" {
		t.Fatal("actual dscl native attribute readback lost its disabled account", err)
	}
	for _, change := range []struct{ name, before, after string }{
		{"unqualified-hidden", "dsAttrTypeNative:IsHidden", "IsHidden"},
		{"standard-hidden", "dsAttrTypeNative:IsHidden", "dsAttrTypeStandard:IsHidden"},
		{"visible-account", "IsHidden: 1", "IsHidden: 0"},
		{"different-account", "RecordName: " + account, "RecordName: _rvpnt_" + strings.Repeat("2", 20)},
		{"different-uid", "UniqueID: 1073741825", "UniqueID: 1073741826"},
		{"different-group", "PrimaryGroupID: 65534", "PrimaryGroupID: 0"},
		{"home", "NFSHomeDirectory: /var/empty", "NFSHomeDirectory: /tmp"},
		{"shell", "UserShell: /usr/bin/false", "UserShell: /bin/sh"},
		{"password", "Password: *", "Password: credential-value"},
		{"authentication", "AuthenticationAuthority: ;DisabledUser;", "AuthenticationAuthority: ;ShadowHash;"},
		{"uuid", "12345678-1234-1234-1234-123456789ABC", "12345678-1234-1234-1234-123456789ABZ"},
		{"extra-alias", "dsAttrTypeNative:IsHidden: 1", "dsAttrTypeNative:IsHidden: 1\nIsHidden: 1"},
		{"extra-standard-alias", "dsAttrTypeNative:IsHidden: 1", "dsAttrTypeNative:IsHidden: 1\ndsAttrTypeStandard:IsHidden: 1"},
		{"duplicate", "Password: *", "Password: *\nPassword: *"},
		{"empty-duplicate", "Password: *", "Password: \nPassword: *"},
		{"whitespace", "Password: *", "Password: *\t"},
		{"missing", "Password: *\n", ""},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := strings.Replace(raw, change.before, change.after, 1)
			if changed == raw {
				t.Fatal("invalid-account negative did not change its native record")
			}
			if value, err := desktopDarwinParseAccountRecord([]byte(changed), account, 0x40000001); err == nil || value != nil {
				t.Fatal("invalid account or namespace acquired disabled identity")
			}
		})
	}
	if value, err := desktopDarwinParseAccountRecord([]byte(raw+strings.Repeat("x", 4096)), account, 0x40000001); err == nil || value != nil {
		t.Fatal("unbounded directory record acquired disabled identity")
	}
}
