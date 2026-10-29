package mobiletor

import (
	"fmt"
	"strconv"
	"strings"
)

// Keep the account rejection unchanged while identifying the exact native
// attribute boundary. Directory values can contain credentials or arbitrary
// text: report only presence, equality and length for the requested fixed keys.
// Native/standard aliases are observations, never accepted substitutes.
func desktopDarwinAccountAttributeFailure(values map[string]string, account string, uid uint32) error {
	expected := [][2]string{
		{"RecordName", account}, {"UniqueID", strconv.FormatUint(uint64(uid), 10)},
		{"PrimaryGroupID", "65534"}, {"NFSHomeDirectory", "/var/empty"},
		{"UserShell", "/usr/bin/false"}, {"Password", "*"},
		{"AuthenticationAuthority", ";DisabledUser;"}, {"IsHidden", "1"},
	}
	parts := make([]string, 0, len(expected))
	for _, pair := range expected {
		value, present := values[pair[0]]
		_, native := values["dsAttrTypeNative:"+pair[0]]
		_, standard := values["dsAttrTypeStandard:"+pair[0]]
		parts = append(parts, fmt.Sprintf("%s(present=%t equal=%t bytes=%d native=%t standard=%t)",
			pair[0], present, present && value == pair[1], len(value), native, standard))
	}
	return fmt.Errorf("Darwin physical account lost its exclusive disabled identity: fields=%d; %s", len(values), strings.Join(parts, "; "))
}
