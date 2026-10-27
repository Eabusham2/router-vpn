package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Delayed startup owns the selection made at scheduling time. In particular,
// importing, relinking or selecting a different node during the delay cannot
// redirect the scheduled connection to newly supplied credentials.
type startupPolicyCapture struct {
	profile      common.RouterProfile
	entry        common.RouterProfile
	profileToken string
	entryToken   string
	sourceToken  string
	entryMode    string
}

// Durable Last state contains references and digests only. Private imported
// settings and Router-entry assets stay in their original node stores.
type startupExternalSelection struct {
	Protocol    string `json:"protocol"`
	Direct      bool   `json:"direct"`
	EntryID     string `json:"entry_id,omitempty"`
	EntryToken  string `json:"entry_token,omitempty"`
	EntryMode   string `json:"entry_mode,omitempty"`
	SourceToken string `json:"source_token"`
	Execution   string `json:"execution"`
}

func (a *app) captureStartupPolicy() (*startupPolicyCapture, error) {
	a.mu.Lock()
	p, ok := a.profileByIDLocked(a.profiles.SelectedID)
	p = cloneRouterProfile(p)
	entry, _ := a.profileByIDLocked(p.MultihopEntryID)
	entry = cloneRouterProfile(entry)
	a.mu.Unlock()
	mode := strings.ToLower(strings.TrimSpace(p.StartupMode))
	if !ok || !p.AutoConnect || mode == "" || mode == "manual" {
		return nil, nil
	}
	capture := &startupPolicyCapture{profile: p, profileToken: startupProfileToken(p)}
	if p.NodeKind != "external" && p.External == nil {
		return capture, nil
	}
	if p.NodeKind != "external" || p.External == nil {
		return nil, errors.New("startup external node has no captured private protocol")
	}
	if p.MultihopEnabled {
		if p.MultihopExitID != p.ID || !validProfileID(p.MultihopEntryID) || entry.ID != p.MultihopEntryID || entry.ID == p.ID {
			return nil, errors.New("startup external path has invalid or missing entry/exit references")
		}
		capture.entry, capture.entryToken = entry, startupProfileToken(entry)
		if desktopTorProtocol(p.External.Protocol) {
			var err error
			capture.entryMode, err = desktopTorEntryMode(p, entry, "", "")
			if err != nil {
				return nil, err
			}
		} else if entry.NodeKind != "external" && entry.External == nil {
			var err error
			capture.entryMode, err = desktopExternalEntryMode(p, entry, "", "")
			if err != nil {
				return nil, err
			}
		}
	}
	var err error
	capture.sourceToken, err = startupExternalSourceToken(a, capture.entry, capture.entryMode)
	if err != nil {
		return nil, err
	}
	return capture, nil
}

// currentLocked checks settings and source references, not measurements or use
// counters that the current connection may update independently.
func (capture *startupPolicyCapture) currentLocked(a *app) error {
	if capture == nil || a.closing || a.profiles.SelectedID != capture.profile.ID {
		return errors.New("scheduled startup selection was retired")
	}
	p, ok := a.profileByIDLocked(capture.profile.ID)
	if !ok || !p.AutoConnect || startupProfileToken(p) != capture.profileToken {
		return errors.New("scheduled startup profile or policy changed")
	}
	if capture.entry.ID != "" {
		entry, ok := a.profileByIDLocked(capture.entry.ID)
		if !ok || startupProfileToken(entry) != capture.entryToken {
			return errors.New("scheduled startup entry or credentials changed")
		}
	}
	return nil
}

func (capture *startupPolicyCapture) current(a *app) error {
	a.mu.Lock()
	err := capture.currentLocked(a)
	a.mu.Unlock()
	if err != nil || capture.sourceToken == "" {
		return err
	}
	token, err := startupExternalSourceToken(a, capture.entry, capture.entryMode)
	if err != nil || token != capture.sourceToken {
		return errors.New("scheduled startup private entry source changed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return capture.currentLocked(a)
}

// Hash the original private Router-entry source as well as its profile. A
// relink can replace a mode asset while preserving the public profile fields.
// Direct and ordinary external entries keep their source in the profile token.
func startupExternalSourceToken(a *app, entry common.RouterProfile, mode string) (string, error) {
	var files, start map[string][]byte
	if entry.ID != "" && entry.NodeKind != "external" && entry.External == nil {
		var err error
		files, err = readDesktopNodeAssets(clientRoot(a), entry.ID, mode)
		if err != nil {
			return "", err
		}
		defer func() {
			for _, data := range files {
				clear(data)
			}
		}()
		if entry.StartLayer != "" && entry.StartLayer != "off" && !mobilemultihop.MAXMode(mode) && mode != "shadowsocks" {
			start, err = readDesktopNodeAssets(clientRoot(a), entry.ID, "shadowsocks")
			if err != nil {
				return "", err
			}
			defer func() {
				for _, data := range start {
					clear(data)
				}
			}()
		}
	}
	return desktopNodeAssetsIdentity(mode, files, start)
}

func startupExternalProfileToken(profile common.RouterProfile) string {
	profile = cloneRouterProfile(profile)
	// Choosing Last must not invalidate the path it is meant to restore. A
	// historical measured MTU is also remeasured by the new native session.
	profile.StartupMode, profile.AutoConnect, profile.EffectiveMTU = "", false, 0
	return startupProfileToken(profile)
}

func (a *app) retainedExternalStartupExecution(capture *startupPolicyCapture) string {
	selection, err := a.loadStartupSelection()
	p := capture.profile
	if err != nil || selection.External == nil || p.External == nil || selection.RouterID != p.ID ||
		selection.RuntimeMode != "external-"+p.External.Protocol || selection.ProfileToken != startupExternalProfileToken(p) {
		return ""
	}
	last := selection.External
	if last.Protocol != p.External.Protocol || last.Direct != !p.MultihopEnabled || last.EntryID != capture.entry.ID ||
		last.EntryMode != capture.entryMode || last.SourceToken != capture.sourceToken ||
		last.Execution != "local" && last.Execution != "server" {
		return ""
	}
	if capture.entry.ID != "" && last.EntryToken != startupExternalProfileToken(capture.entry) {
		return ""
	}
	if p.MultihopExecution == "server" && last.Execution != "server" {
		return ""
	}
	// Direct/ordinary Local has no relay proposal to restore. Its fresh proof
	// still uses the saved protocol, and there is no Compare to rerun.
	if !p.MultihopEnabled || p.MultihopExecution == "" || p.MultihopExecution == "local" {
		return ""
	}
	return last.Execution
}

func (a *app) startExternalStartupOwned(capture *startupPolicyCapture, native externalConnectRuntime) error {
	mode := strings.ToLower(strings.TrimSpace(capture.profile.StartupMode))
	if mode != "auto" && mode != "smart-auto" && mode != "last" {
		return fmt.Errorf("unsupported external startup mode %q", mode)
	}
	retained := ""
	if mode == "last" {
		retained = a.retainedExternalStartupExecution(capture)
	}
	// The owned helper is exactly the interactive external-node launch path.
	// This writer only adapts its existing response contract in process; no
	// local HTTP request, extra transaction, or fabricated connection is used.
	result := &startupConnectResponse{header: make(http.Header)}
	a.externalProfileConnectOwned(result, externalProfileConnectRequest{ProfileID: capture.profile.ID}, retained, capture, native)
	if err := result.err(); err != nil {
		return err
	}
	return nil
}

func (a *app) saveExternalStartupSelection(native *desktopNodeLaunch, sourceToken, execution string) {
	if native == nil || native.external == nil || execution != "local" && execution != "server" || !validStartupProfileToken(sourceToken) {
		return
	}
	if _, err := a.readDesktopExternalProof(native); err != nil {
		return
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(native.policyProfileID)
	entry, entryOK := a.profileByIDLocked(native.external.entry.ID)
	profile, entry = cloneRouterProfile(profile), cloneRouterProfile(entry)
	st := a.state
	owned := a.cmd == native.command && st.Connected && st.Phase == "connected" && st.RouterID == profile.ID
	a.mu.Unlock()
	if !owned || !ok || profile.External == nil || !native.external.direct && !entryOK {
		return
	}
	currentSource, err := startupExternalSourceToken(a, entry, profile.MultihopEntryMode)
	if err != nil || currentSource != sourceToken {
		return
	}
	last := &startupExternalSelection{Protocol: profile.External.Protocol, Direct: native.external.direct, SourceToken: sourceToken, Execution: execution, EntryMode: profile.MultihopEntryMode}
	if !last.Direct {
		last.EntryID, last.EntryToken = entry.ID, startupExternalProfileToken(entry)
	}
	selection := startupSelection{RouterID: profile.ID, RuntimeMode: st.RuntimeMode, LogicalMode: st.LogicalMode, Base: st.Base,
		ProfileToken: startupExternalProfileToken(profile), UpdatedAt: time.Now().UTC(), External: last}
	if err := a.saveStartupSelection(selection); err != nil {
		log.Printf("Router VPN could not persist the proved external startup selection: %v", err)
	}
}

type startupConnectResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *startupConnectResponse) Header() http.Header { return r.header }
func (r *startupConnectResponse) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *startupConnectResponse) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.body.Len()+len(data) > 16<<10 {
		return 0, errors.New("startup connection response exceeded its bound")
	}
	return r.body.Write(data)
}
func (r *startupConnectResponse) err() error {
	if r.status < 200 || r.status >= 300 {
		return fmt.Errorf("external startup failed (%d): %s", r.status, strings.TrimSpace(r.body.String()))
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(r.body.Bytes(), &result) != nil || !result.OK {
		return errors.New("external startup returned no proved connection result")
	}
	return nil
}
