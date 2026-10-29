package mobiletor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IsHidden is a native Directory Services attribute. dscl preserves that
// namespace on readback; it strips the standard prefix from the other fields.
// Request and create the exact native key rather than treating aliases as
// interchangeable account authority.
const desktopDarwinHiddenAttribute = "dsAttrTypeNative:IsHidden"

var desktopDarwinAccountAttributes = []string{"RecordName", "UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell", "Password", "AuthenticationAuthority", desktopDarwinHiddenAttribute, "GeneratedUID"}

func desktopDarwinParseAccountRecord(raw []byte, account string, uid uint32) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 4096 || !strings.HasPrefix(account, "_rvpnt_") || !desktopSocketHex(strings.TrimPrefix(account, "_rvpnt_"), 20) || uid < 0x40000000 || uid >= 0x80000000 {
		return nil, errors.New("Darwin physical account identity is invalid")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, ": ")
		_, duplicate := values[key]
		if !ok || duplicate || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
			return nil, errors.New("Darwin physical account has an ambiguous attribute")
		}
		values[key] = value
	}
	if len(values) != len(desktopDarwinAccountAttributes) || values["RecordName"] != account || values["UniqueID"] != strconv.FormatUint(uint64(uid), 10) ||
		values["PrimaryGroupID"] != "65534" || values["NFSHomeDirectory"] != "/var/empty" || values["UserShell"] != "/usr/bin/false" ||
		values["Password"] != "*" || values["AuthenticationAuthority"] != ";DisabledUser;" || values[desktopDarwinHiddenAttribute] != "1" {
		return nil, desktopDarwinAccountAttributeFailure(values, account, uid)
	}
	compact := strings.ReplaceAll(strings.ToLower(values["GeneratedUID"]), "-", "")
	if !desktopSocketHex(compact, 32) || len(values["GeneratedUID"]) != 36 {
		return nil, errors.New("Darwin physical account lost its generated identity")
	}
	return values, nil
}

// Directory values can contain credentials or arbitrary text. Report only
// presence, equality and length for fixed expected keys; never their values.
func desktopDarwinAccountAttributeFailure(values map[string]string, account string, uid uint32) error {
	expected := [][2]string{
		{"RecordName", account}, {"UniqueID", strconv.FormatUint(uint64(uid), 10)},
		{"PrimaryGroupID", "65534"}, {"NFSHomeDirectory", "/var/empty"},
		{"UserShell", "/usr/bin/false"}, {"Password", "*"},
		{"AuthenticationAuthority", ";DisabledUser;"}, {desktopDarwinHiddenAttribute, "1"},
	}
	parts := make([]string, 0, len(expected))
	for _, pair := range expected {
		value, present := values[pair[0]]
		label := strings.TrimPrefix(pair[0], "dsAttrTypeNative:")
		_, native := values["dsAttrTypeNative:"+label]
		_, standard := values["dsAttrTypeStandard:"+label]
		parts = append(parts, fmt.Sprintf("%s(present=%t equal=%t bytes=%d native=%t standard=%t)",
			label, present, present && value == pair[1], len(value), native, standard))
	}
	return fmt.Errorf("Darwin physical account lost its exclusive disabled identity: fields=%d; %s", len(values), strings.Join(parts, "; "))
}
