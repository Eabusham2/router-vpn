package windowsapp

import (
	"errors"
	"strings"

	"router-vpn/internal/updatepolicy"
)

func updateSourceSHA(raw []byte, portable bool, architecture string) (string, error) {
	provenance, err := updatepolicy.ParsePackageProvenance(raw)
	if err != nil {
		return "", err
	}
	if architecture != "amd64" && architecture != "arm64" {
		return "", errors.New("Windows updater has no supported captured architecture")
	}
	family := "windows-"
	if portable {
		family = "windows-portable-"
	}
	if provenance.ArtifactFamily != family+architecture {
		return "", errors.New("Windows updater provenance differs from its captured package layout")
	}
	return provenance.SourceSHA, nil
}

// An old cache can contain only files produced by the staged Windows updater.
// Even an allowed name still needs independent regular-file, single-link and
// original-user security checks. No existing object is repaired or removed.
func updateCacheFilename(name string) bool {
	if name == "app-update-state.json" {
		return true
	}
	for _, prefix := range []string{".router-vpn-update-state-", ".router-vpn-update-"} {
		if suffix, ok := strings.CutPrefix(name, prefix); ok {
			if len(suffix) == 0 || len(suffix) > 20 {
				return false
			}
			for _, digit := range suffix {
				if digit < '0' || digit > '9' {
					return false
				}
			}
			return true
		}
	}
	if len(name) < 18 || name[16] != '-' {
		return false
	}
	for _, value := range name[:16] {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	switch name[17:] {
	case "RouterVPN-Windows-amd64.zip", "RouterVPN-Windows-arm64.zip",
		"RouterVPN-Portable-Windows-amd64.zip", "RouterVPN-Portable-Windows-arm64.zip":
		return true
	default:
		return false
	}
}
