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
		"AuthenticationAuthority": ";DisabledUser;", "IsHidden": "1", "GeneratedUID": strings.Repeat("a", 36),
	}
	baseline := desktopDarwinAccountAttributeFailure(values, account, 0x40000001).Error()
	if strings.Count(baseline, "equal=true") != 8 || !strings.Contains(baseline, "fields=9;") {
		t.Fatal("the diagnostic lost the exact requested account comparison", baseline)
	}
	// The fixture is deliberately unlike a disabled account. No alternate
	// spelling or plausible masking changes the caller's rejection predicate.
	delete(values, "IsHidden")
	values["dsAttrTypeNative:IsHidden"] = "1"
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
	if !strings.Contains(actual, "IsHidden(present=false equal=false bytes=0 native=true standard=false)") ||
		!strings.Contains(actual, "Password(present=true equal=false") || strings.Count(actual, "equal=true") != 4 {
		t.Fatal("account diagnostics hid the differing native attribute shape", actual)
	}
	values["dsAttrTypeStandard:IsHidden"] = "1"
	if value := desktopDarwinAccountAttributeFailure(values, account, 0x40000001).Error(); !strings.Contains(value, "IsHidden(present=false equal=false bytes=0 native=true standard=true)") {
		t.Fatal("ambiguous aliases were not distinguished", value)
	}
}
