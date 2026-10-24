package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func desktopExternalEntryMode(control, entry common.RouterProfile, requested, base string) (string, error) {
	mode := requested
	if mode == "" {
		mode = control.MultihopEntryMode
	}
	if mode == "" {
		mode = "wg"
		if resolveMultihopEntryBase(control, entry, base) == "awg" {
			mode = "awg2-fast"
		}
	}
	if !mobilemultihop.NodeProfileMode(mode) {
		return "", errors.New("external Router entry requires an exact supported native mode")
	}
	return mode, nil
}

func desktopExternalEntryBase(mode string) string {
	if mode == "wg" {
		return "wg"
	}
	if mode == "awg2-fast" || mode == "awg2-strong" {
		return "awg"
	}
	return "native"
}

// Only an outer transport address changes. TLS identity, DNS, remote public
// proof, protocol options, provider keys and saved profiles remain captured.
func freezeDesktopExternalProfile(profile common.RouterProfile, address string) (common.RouterProfile, error) {
	copy := cloneRouterProfile(profile)
	if copy.External == nil || copy.NodeKind != "external" {
		return common.RouterProfile{}, errors.New("external bootstrap has no captured private node")
	}
	exit, err := standardExitFromExternalProfile(copy)
	if err != nil {
		return common.RouterProfile{}, err
	}
	if exit.Server == address {
		return copy, nil
	}
	if !applexray.ValidNodeHostname(exit.Server) || copy.External.ResponseProbe != nil || copy.External.StartLayer != nil || copy.External.ServerPeer != nil {
		return common.RouterProfile{}, errors.New("paired external identities require their exact literal endpoint; hostname bootstrap cannot re-pair them")
	}
	copy.Endpoint = address
	ext := copy.External
	switch exit.Protocol {
	case "wireguard":
		_, port, err := net.SplitHostPort(ext.WireGuard.Endpoint)
		if err != nil {
			return common.RouterProfile{}, err
		}
		ext.WireGuard.Endpoint = net.JoinHostPort(address, port)
	case "amneziawg":
		_, port, err := net.SplitHostPort(ext.AmneziaWG.Endpoint)
		if err != nil {
			return common.RouterProfile{}, err
		}
		ext.AmneziaWG.Endpoint = net.JoinHostPort(address, port)
	case "shadowsocks":
		ext.Shadowsocks.Server = address
	case "hysteria2":
		ext.Hysteria2.Server = address
		if ext.Hysteria2.TLSServerName == "" {
			ext.Hysteria2.TLSServerName = exit.Server
		}
	case "socks5":
		ext.SOCKS5.Host = address
	case "http-connect":
		ext.HTTPConnect.Host = address
	case "https-connect":
		ext.HTTPSConnect.Host = address
		if ext.HTTPSConnect.TLSServerName == "" {
			ext.HTTPSConnect.TLSServerName = exit.Server
		}
	default:
		return common.RouterProfile{}, errors.New("external protocol has no captured endpoint bootstrap")
	}
	return copy, nil
}

func desktopExternalPublicAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.Is4In6() && address.Zone() == "" && !netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}

// Validate the complete composition before bootstrap, then resolve each outer
// hostname once and compile those literal launch copies. No ordinary query or
// traffic destination uses the bootstrap resolver.
func compileDesktopExternalCaptured(ctx context.Context, profile, entry common.RouterProfile, exit standardExit, direct bool, restored string, files, start map[string][]byte, lookup applexray.Lookup) (*desktopNodeLaunch, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("external native preparation was cancelled")
	}
	profile, entry = cloneRouterProfile(profile), cloneRouterProfile(entry)
	if !direct && entry.NodeKind == "" {
		entry.NodeKind = "router-vpn"
	}
	hosts := []string{}
	for _, host := range []string{exit.Server, entry.Endpoint} {
		if host == "" || direct && host == entry.Endpoint {
			continue
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			continue
		}
		if !applexray.ValidNodeHostname(host) || lookup == nil {
			return nil, errors.New("external node hostname requires its captured bootstrap resolver")
		}
		if len(hosts) == 0 || !strings.EqualFold(hosts[0], host) {
			hosts = append(hosts, host)
		}
	}
	compile := func(addresses map[string]string) (*desktopNodeLaunch, error) {
		p, e, x := cloneRouterProfile(profile), cloneRouterProfile(entry), exit
		var err error
		if address := addresses[strings.ToLower(exit.Server)]; address != "" {
			p, err = freezeDesktopExternalProfile(p, address)
			if err != nil {
				return nil, err
			}
			x, err = standardExitFromExternalProfile(p)
			if err != nil {
				return nil, err
			}
		}
		if !direct {
			if address := addresses[strings.ToLower(entry.Endpoint)]; address != "" {
				if e.NodeKind == "external" {
					e, err = freezeDesktopExternalProfile(e, address)
				} else {
					e.Endpoint = address
				}
				if err != nil {
					return nil, err
				}
			}
		}
		var graph map[string]any
		predecessor := ""
		switch {
		case direct:
			graph, err = buildDirectStandardExitConfig(p, x)
		case e.NodeKind == "external":
			var predecessorExit standardExit
			predecessorExit, err = standardExitFromExternalProfile(e)
			if err == nil {
				graph, err = buildExternalEntryStandardExitConfig(p, predecessorExit, x)
			}
		default:
			mode, modeErr := desktopExternalEntryMode(p, e, "", "")
			if modeErr != nil {
				return nil, modeErr
			}
			p.MultihopEntryMode = mode
			ownedFiles, ownedStart := files, start
			if e.Endpoint != entry.Endpoint {
				ownedFiles, err = freezeDesktopNodeAssets(files, entry.Endpoint, e.Endpoint)
				if err == nil {
					ownedStart, err = freezeDesktopNodeAssets(start, entry.Endpoint, e.Endpoint)
				}
				if err != nil {
					return nil, err
				}
			}
			var node *mobilemultihop.NodeProfile
			node, _, err = compileDesktopNode(ctx, e, mode, ownedFiles, ownedStart, nil)
			if err != nil {
				return nil, err
			}
			predecessor = node.Config()
			endpoint, outbound, partErr := directStandardExitRuntimeParts(x)
			if partErr != nil {
				return nil, partErr
			}
			dns, dnsErr := selectedStandardExitDNS(p, false)
			if dnsErr != nil {
				return nil, dnsErr
			}
			endpoints, outbounds := []any{}, []any{}
			if endpoint != nil {
				endpoints = append(endpoints, endpoint)
			}
			if outbound != nil {
				outbounds = append(outbounds, outbound)
			}
			graph = standardExitConfig(p, dns, endpoints, outbounds)
		}
		if err != nil {
			return nil, err
		}
		return compileDesktopExternalGraphWithPredecessor(graph, p, e, x, direct, restored, predecessor)
	}
	if len(hosts) == 0 {
		return compile(nil)
	}
	validation := map[string]string{}
	for i, host := range hosts {
		address := "192.0.2.253"
		if i == 1 {
			address = "192.0.2.254"
		}
		validation[strings.ToLower(host)] = address
	}
	trial, err := compile(validation)
	if err != nil {
		return nil, err
	}
	clear(trial.config)
	clear(trial.metadata)
	clear(trial.external.source)
	clear(trial.external.capture)
	addresses := map[string]string{}
	for _, host := range hosts {
		answers, err := lookup(ctx, host)
		if err != nil || ctx.Err() != nil || len(answers) == 0 || len(answers) > 32 {
			return nil, errors.New("captured external endpoint lookup failed or expired")
		}
		var chosen netip.Addr
		for _, address := range answers {
			if !desktopExternalPublicAddress(address) {
				continue
			}
			if !chosen.IsValid() || address.Is4() {
				chosen = address
				if address.Is4() {
					break
				}
			}
		}
		if !chosen.IsValid() {
			return nil, errors.New("captured external endpoint has no usable public address")
		}
		addresses[strings.ToLower(host)] = chosen.String()
	}
	launch, err := compile(addresses)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return launch, err
}

type desktopExternalPreflightCommand func(context.Context, string, []string, []string, string) error

func runDesktopExternalPreflightCommand(ctx context.Context, binary string, args, environment []string, directory string) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Env, command.Dir = environment, directory
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("bundled native runtime did not accept its captured external command and configuration")
	}
	return nil
}

// Direct utility invocations have no firewall, PID-registry or old-runtime
// effects. This completes before any stop or transition mutation is allowed.
func preflightDesktopExternalLaunch(ctx context.Context, binary string, launch *desktopNodeLaunch, run desktopExternalPreflightCommand) (result error) {
	if launch == nil || launch.external == nil || len(launch.config) == 0 || run == nil || !filepath.IsAbs(binary) {
		return errors.New("external preflight has no exact native executable and graph")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := newPrivateRuntimeDir(launch.root, "native-node")
	if err != nil {
		return err
	}
	workspace := &desktopNodeLaunch{}
	if err = captureDesktopRuntimeDirectory(workspace, directory); err != nil {
		return err
	}
	defer workspace.directoryRoot.Close()
	defer func() { result = errors.Join(result, cleanupDesktopNodeLaunch(workspace)) }()
	if err = writeDesktopRuntimeFile(workspace, "sing-box.json", launch.config, false); err != nil {
		return err
	}
	environment := desktopNativeEnvironment(os.Environ(), launch.root, launch.profileID, launch.endpoint)
	if err = run(ctx, binary, []string{"routervpn-external", "--help"}, environment, directory); err != nil {
		return err
	}
	if err = desktopExternalDirectoryCurrent(workspace); err != nil {
		return err
	}
	if err = run(ctx, binary, []string{"check", "-D", directory, "-c", filepath.Join(directory, "sing-box.json")}, environment, directory); err != nil {
		return err
	}
	checked, err := readDesktopRuntimeFile(workspace, "sing-box.json", 4<<20)
	if err != nil || !bytes.Equal(checked, launch.config) {
		return errors.New("native external preflight changed the captured configuration")
	}
	if err = desktopExternalDirectoryCurrent(workspace); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
