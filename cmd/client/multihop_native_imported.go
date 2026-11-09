package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopImportedEntryProtocol(protocol string) bool {
	switch protocol {
	case "socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn":
		return true
	}
	return false
}

func desktopImportedFinalMode(mode string) bool {
	switch mode {
	case "shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong", "reality-vision", "reality-pq-vision", "reality-xhttp":
		return true
	}
	return false
}

func resolveDesktopImportedSelection(control, entry, exit common.RouterProfile, q multihopConnectRequest) (multihopSelection, error) {
	bad := errors.New("imported entry requires its original supported external profile, the selected paired Router VPN final, and Local execution")
	if entry.NodeKind != "external" || entry.External == nil || !desktopImportedEntryProtocol(entry.External.Protocol) ||
		exit.External != nil || exit.NodeKind != "" && exit.NodeKind != "router-vpn" || control.ID != exit.ID ||
		q.Execution != "" && q.Execution != "local" || q.Execution == "" && control.MultihopExecution != "" && control.MultihopExecution != "local" ||
		q.Base != "" && q.Base != "auto" && q.Base != "wg" && q.Base != "awg" {
		return multihopSelection{}, bad
	}
	if entry.External.Protocol == "openvpn" {
		if _, err := desktopImportedOpenVPNProfile(entry); err != nil {
			return multihopSelection{}, err
		}
	}
	mode := q.EntryMode
	if mode == "" {
		mode = control.MultihopEntryMode
	}
	if mode != "" && mode != entry.External.Protocol {
		return multihopSelection{}, errors.New("imported entry transport differs from its original profile")
	}
	final := q.ExitMode
	if final == "" {
		final = "shadowsocks"
	}
	if !desktopImportedFinalMode(final) {
		return multihopSelection{}, errors.New("imported entry requires an explicit compatible paired final transport")
	}
	return multihopSelection{Control: control, Entry: entry, Exit: exit, Base: "native", EntryMode: entry.External.Protocol, ExitMode: final}, nil
}

// The standalone entry DNS is irrelevant to this path. Build a private rescue
// seed, then restore the complete original entry into the compiler capture.
// NewImportedEntry validates that original and owns the final's selected DNS.
func desktopImportedEntrySource(ctx context.Context, entry common.RouterProfile, lookup applexray.Lookup) (string, string, string, error) {
	exit, err := standardExitFromExternalProfile(entry)
	if err != nil {
		return "", "", "", err
	}
	projection := cloneRouterProfile(entry)
	projection.DNSMode, projection.DNSProtocol, projection.DNSHost, projection.DNSPort = "rescue", "", "", 0
	projection.DNSServerName, projection.DNSPath = "", ""
	launch, err := compileDesktopExternalCaptured(ctx, projection, common.RouterProfile{}, exit, true, "", nil, nil, lookup)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		clear(launch.config)
		clear(launch.metadata)
		clear(launch.external.source)
		clear(launch.external.capture)
	}()
	original := cloneRouterProfile(entry)
	if launch.endpoint != entry.Endpoint {
		original, err = freezeDesktopExternalProfile(original, launch.endpoint)
		if err != nil {
			return "", "", "", err
		}
	}
	capture, err := json.Marshal(map[string]any{"schema": 1, "exit_id": original.ID, "protocol": original.External.Protocol,
		"expected_public_ip": original.External.ExpectedPublicIP, "profile": original})
	if err != nil {
		return "", "", "", err
	}
	return string(launch.external.source), string(capture), launch.endpoint, nil
}

func captureDesktopImportedMultihop(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup) (multihopSelection, error) {
	return captureDesktopImportedMultihopWithHost(ctx, root, sel, modes, lookup, nil)
}

func captureDesktopImportedMultihopWithHost(ctx context.Context, root string, sel multihopSelection, modes []string, lookup applexray.Lookup, host *desktopNodeConnectionOwner) (multihopSelection, error) {
	if ctx == nil || ctx.Err() != nil || sel.Base != "native" || len(modes) != 1 || modes[0] != sel.ExitMode ||
		sel.Entry.External == nil || sel.EntryMode != sel.Entry.External.Protocol || !desktopImportedEntryProtocol(sel.EntryMode) || !desktopImportedFinalMode(sel.ExitMode) ||
		sel.Control.ID != sel.Exit.ID {
		return sel, errors.New("desktop imported path requires one explicit Local captured entry and paired final")
	}
	root, err := canonicalBundleRoot(root)
	if err != nil {
		return sel, err
	}
	sel.Control, sel.Entry, sel.Exit = cloneRouterProfile(sel.Control), cloneRouterProfile(sel.Entry), cloneRouterProfile(sel.Exit)
	c := &nativeMultihopCapture{root: root, entryID: sel.Entry.ID, exitID: sel.Exit.ID, base: sel.Base, entryMode: sel.EntryMode, entrySelection: sel.EntryMode,
		controlToken: liveMeasurementProfileToken(sel.Control), entryToken: liveMeasurementProfileToken(sel.Entry), exitToken: liveMeasurementProfileToken(sel.Exit),
		configs: map[string]string{}, localPacketPublic: map[string]string{}, localPQIdentity: map[string]string{}, failures: map[string]error{}, imported: true, importedHost: host}
	if host != nil && (host.capture.dataRoot != root || host.currentContext(ctx) != nil) {
		return sel, errors.New("protected imported capture changed its original Windows controller")
	}
	if sel.EntryMode == "openvpn" {
		c.openVPN, err = desktopImportedOpenVPNProfile(sel.Entry)
		if err != nil {
			return sel, err
		}
	}
	owned := map[string]map[string][]byte{}
	defer func() {
		for _, files := range owned {
			clearViaEntryAssets(files)
		}
	}()
	read := func(mode string) (map[string][]byte, error) {
		if files, ok := owned[mode]; ok {
			return files, nil
		}
		files, err := readDesktopNodeAssets(root, sel.Exit.ID, mode)
		if err == nil {
			owned[mode] = files
			c.assets = append(c.assets, viaEntryAsset{sel.Exit.ID, mode, viaEntryAssetDigest(files)})
		}
		return files, err
	}
	identity, err := read("wg")
	if err != nil {
		return sel, err
	}
	base, err := mobilemultihop.NativeBaseSourceForEndpoint("wg", identity, sel.Exit.Endpoint)
	proofID, proofErr := nodeProofIDFromWGConfig(base)
	if err != nil || proofErr != nil || proofID != sel.Exit.NodeProofID {
		return sel, errors.New("imported path final identity differs from its independently saved paired WireGuard peer")
	}
	files, err := read(sel.ExitMode)
	if err != nil {
		return sel, err
	}
	var start map[string][]byte
	if sel.Exit.StartLayer != "" && sel.Exit.StartLayer != "off" && sel.ExitMode != "shadowsocks" {
		start, err = read("shadowsocks")
		if err != nil {
			return sel, err
		}
	}
	_, address, err := compileDesktopNode(ctx, sel.Exit, sel.ExitMode, files, start, lookup)
	if err != nil {
		return sel, err
	}
	final := cloneRouterProfile(sel.Exit)
	// The public resolver admitted an explicit Local request. Keep both saved
	// originals unchanged; only this candidate's compiler projection selects
	// Local. The original policy tokens remain part of the capture/restore seal.
	final.MultihopExecution = "local"
	if address != final.Endpoint {
		files, err = freezeDesktopNodeAssets(files, final.Endpoint, address)
		if err != nil {
			return sel, err
		}
		defer clearViaEntryAssets(files)
		start, err = freezeDesktopNodeAssets(start, final.Endpoint, address)
		if err != nil {
			return sel, err
		}
		defer clearViaEntryAssets(start)
		final.Endpoint = address
	}
	bootstrap, err := desktopNodeDNSBootstrap(final)
	if err != nil {
		return sel, err
	}
	rawFinal, err := json.Marshal(final)
	if err != nil {
		return sel, err
	}
	defer clear(rawFinal)
	startJSON := ""
	if len(start) != 0 {
		startJSON = encodeDesktopNodeAssets(start)
	}
	source, capture, endpoint, err := desktopImportedEntrySource(ctx, sel.Entry, lookup)
	if err != nil {
		return sel, err
	}
	compiled, err := mobilemultihop.NewImportedEntry(source, capture, sel.ExitMode, encodeDesktopNodeAssets(files), string(rawFinal), startJSON, bootstrap)
	if err != nil {
		return sel, err
	}
	defer compiled.Close()
	c.importedInput, err = compiled.ImportedLaunchInput()
	if err != nil {
		return sel, err
	}
	c.importedOriginalSource = compiled.SourceSHA256()
	if c.openVPN != nil {
		if err := capturedDesktopImportedOpenVPN(compiled.Config(), c.openVPN); err != nil {
			return sel, err
		}
	}
	if host != nil {
		// The typed native SOCKS owner admits a negotiated UDP relay later.
		// This parent capture retains only the constructor's static sockets;
		// it never turns a control endpoint into a wildcard datagram permit.
		physical, captureErr := compiled.ImportedDesktopCapture()
		if captureErr != nil {
			return sel, captureErr
		}
		for _, root := range physical.PhysicalRoots {
			c.entryPhysical = append(c.entryPhysical, root.Destinations...)
		}
	} else {
		c.entryPhysical, err = compiled.ImportedPhysicalEgress()
		if err != nil {
			return sel, err
		}
	}
	if _, err := netip.ParseAddr(endpoint); err != nil || len(c.entryPhysical) == 0 {
		return sel, errors.New("imported entry lost its captured physical socket identity")
	}
	c.endpoint = endpoint
	config, _, err := nativeMultihopProofConfig(compiled.Config(), sel.Entry)
	if err != nil {
		return sel, err
	}
	c.configs[sel.ExitMode] = config
	c.source = c.importedCaptureDigest()
	sel.Native = c
	return sel, errors.Join(ctx.Err(), c.validate(sel))
}

// Bind the replay envelope to the original graph and both independently saved
// node sources. A launch must not swap its constructor after preflight merely
// because a public profile ID or compiled metadata stayed the same.
func (c *nativeMultihopCapture) importedCaptureDigest() string {
	if c == nil || !c.imported || c.importedInput == "" || len(c.importedInput) > mobilemultihop.ImportedLaunchInputLimit {
		return ""
	}
	assetIDs := make([][]string, 0, len(c.assets))
	for _, asset := range c.assets {
		assetIDs = append(assetIDs, []string{asset.id, asset.mode, asset.digest})
	}
	inputHash := sha256.Sum256([]byte(c.importedInput))
	sealed, _ := json.Marshal([]any{"desktop-imported-entry-v2", c.importedHost != nil, c.importedOriginalSource, hex.EncodeToString(inputHash[:]), c.entryMode, c.entryPhysical, c.endpoint,
		c.controlToken, c.entryToken, c.exitToken, assetIDs, c.configs})
	sum := sha256.Sum256(sealed)
	clear(sealed)
	return hex.EncodeToString(sum[:])
}

func proveNativeMultihopLaneContext(ctx context.Context, profile common.RouterProfile, proxy string) error {
	if profile.NodeKind != "external" {
		return proveMultihopLaneNodeContext(ctx, profile, proxy)
	}
	if profile.External == nil || !desktopImportedEntryProtocol(profile.External.Protocol) || proxy != multihopEntryProofProxy {
		return errors.New("imported entry proof has no exact original entry lane")
	}
	client, closeIdle, err := newMultihopLaneHTTPClient(proxy, 2500*time.Millisecond)
	if err != nil {
		return err
	}
	defer closeIdle()
	return proveExpectedPublicExit(ctx, client, publicExitProofProviders, profile.External.ExpectedPublicIP, "imported entry", 3*time.Second)
}
