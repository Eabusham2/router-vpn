//go:build windows

package windowsapp

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"router-vpn/internal/updatepolicy"
	"router-vpn/internal/windowscontroller"
)

// StartUpdateCheck keeps the original-user update helper inside this session's
// retained Job ownership. It can stage an exact-SHA package but never adopts
// the separate controller token or receives its bearer token/private channel.
// A desktop that was already elevated keeps its own original token.
// Normal app startup can report an update-check error and continue; any partial
// native owner stays retained here for checked Close.
func (s *Session) StartUpdateCheck() error {
	if s == nil {
		return errors.New("the Windows update check has no captured app session")
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.ctx == nil || s.ctx.Err() != nil || !s.authenticated || s.updaterImage != nil || s.updater != nil || s.updateCache != nil {
		return errors.New("the Windows update check has no new live session operation")
	}
	var err error
	s.updaterImage, err = windowscontroller.PinImage(filepath.Join(s.packageRoot, "router-vpn-update.exe"))
	if err != nil {
		return err
	}
	// The installed and Portable packagers place provenance beside the actual
	// launcher, not necessarily beside the updater under App/RouterVPN. Hold
	// that exact file against replacement and pass its explicit validated SHA.
	provenance, err := windowscontroller.PinFile(filepath.Join(filepath.Dir(s.selfImage.Path()), "ROUTER-VPN-SOURCE.json"))
	if err != nil {
		return err
	}
	s.files = append(s.files, provenance)
	sha, err := readUpdateSource(provenance, s.desktop.SID, s.portable)
	if err != nil {
		return err
	}
	profile, err := s.self.UserDirectories()
	if err != nil {
		return err
	}
	base, components := profile.LocalAppData, []string{"RouterVPN", "updates"}
	if s.portable {
		base, components = s.dataRoot, []string{"updates"}
	}
	s.updateCache, err = captureUpdateCache(s.ctx, base, components, s.desktop.SID)
	if err != nil {
		return err
	}
	identity, err := s.self.Identity()
	if err != nil || identity != s.desktop {
		return errors.Join(err, errors.New("the Windows updater lost its original desktop identity"))
	}
	if err := s.self.VerifyImage(s.selfImage); err != nil {
		return err
	}
	if err := s.updateCache.Verify(); err != nil {
		return err
	}
	arguments := []string{"--download", "--json", "--current-sha", sha, "--cache", s.updateCache.Path()}
	launch := "windows-installed"
	if s.portable {
		arguments = append(arguments, "--portable")
		launch = "windows-portable"
	}
	environment := append(append([]string(nil), s.environment...), "ROUTER_VPN_UPDATE_LAUNCH="+launch)
	s.updater, err = windowscontroller.LaunchGUIChild(s.ctx, s.updaterImage,
		func(uint64) ([]string, error) { return arguments, nil }, environment, s.dataRoot)
	return err
}

func readUpdateSource(provenance *windowscontroller.CodeFile, desktop string, portable bool) (_ string, failure error) {
	if provenance == nil || provenance.Path() == "" {
		return "", errors.New("the Windows updater has no pinned provenance")
	}
	file, err := os.Open(provenance.Path())
	if err != nil {
		return "", err
	}
	defer func() { failure = errors.Join(failure, file.Close()) }()
	api, err := portableNative()
	if err != nil {
		return "", err
	}
	security, err := portableInspectSecurity(api, file)
	if err != nil {
		return "", err
	}
	defer func() { failure = errors.Join(failure, security.close()) }()
	owner, _, grants, err := security.inspect()
	if err != nil {
		return "", err
	}
	if err := validatePortablePackageGrants(owner, desktop, grants); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(file, updatepolicy.MaxPackageProvenanceBytes+1))
	if err != nil {
		return "", err
	}
	return updateSourceSHA(raw, portable, runtime.GOARCH)
}
