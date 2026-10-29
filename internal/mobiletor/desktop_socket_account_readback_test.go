package mobiletor

import (
	"strings"
	"testing"
)

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
