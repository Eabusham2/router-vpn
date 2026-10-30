package mobiletor

import "fmt"

const desktopPFABIUpstream = "apple-oss-distributions/xnu@43a90889846e00bfb5cf1d255cdc0a701a1e05a4"

// This is a bounded qualification target, not a claim of stable/private PF ABI
// compatibility. The actual scoped rule/readback/commit/rollback/retirement
// fixtures must pass on both architectures before the native loader is used.
// An OS update requires renewed source review and actual native evidence.
func desktopPFValidateABI(release, build, architecture string) error {
	if release != "24.6.0" || build != "24G830" || (architecture != "amd64" && architecture != "arm64") {
		return fmt.Errorf("Darwin private PF ABI has no qualified source/kernel boundary for release=%q build=%q architecture=%q", release, build, architecture)
	}
	return nil
}
