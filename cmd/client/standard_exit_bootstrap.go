package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
)

type standardExitBootstrap struct {
	lookup  applexray.Lookup
	network func() string
}

func standardExitSystemBootstrap() standardExitBootstrap {
	return standardExitBootstrap{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		network: physicalNetworkIdentity,
	}
}

type standardExitPrepared struct {
	directory, alias, endpoint string
}

// Endpoint bootstrap is confined to transport hostnames. Validate the complete
// graph first, resolve each hostname once, then compile literal launch copies.
// It cannot resolve application destinations, selected DNS or proof addresses.
func prepareCapturedStandardExit(parent context.Context, root string, control, entry common.RouterProfile, exit standardExit, direct bool, bootstrap standardExitBootstrap) (standardExitPrepared, error) {
	var result standardExitPrepared
	if parent == nil || parent.Err() != nil {
		return result, errors.New("standard exit bootstrap lost its captured operation")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	control, entry = cloneRouterProfile(control), cloneRouterProfile(entry)
	profile, err := desktopExternalCapture(control, exit)
	if err != nil {
		return result, err
	}
	exit, err = standardExitFromExternalProfile(profile)
	if err != nil {
		return result, err
	}
	var router nativeWG
	var upstream standardExit
	if !direct {
		if entry.NodeKind == "external" {
			upstream, err = standardExitFromExternalProfile(entry)
		} else {
			var directory string
			directory, err = nativeGeneratedDir(root, entry.ID, "wg")
			if err == nil {
				router, err = parseNativeWG(filepath.Join(directory, "wg.conf"))
			}
		}
		if err != nil {
			return result, err
		}
	}
	physical := exit.Server
	if !direct {
		physical = router.Host
		if entry.NodeKind == "external" {
			physical = upstream.Server
		}
	}
	hosts := []string{}
	for _, value := range []string{exit.Server, physical} {
		if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			continue
		}
		if !applexray.ValidNodeHostname(value) || bootstrap.lookup == nil || bootstrap.network == nil {
			return result, errors.New("standard transport hostname requires its captured bootstrap resolver")
		}
		name := strings.ToLower(value)
		if len(hosts) == 0 || hosts[0] != name {
			hosts = append(hosts, name)
		}
	}
	compile := func(addresses map[string]string) (map[string]any, string, error) {
		p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
		x, wg := exit, router
		if address := addresses[strings.ToLower(exit.Server)]; address != "" {
			var err error
			p, err = freezeDesktopExternalProfile(p, address)
			if err != nil {
				return nil, "", err
			}
			x, err = standardExitFromExternalProfile(p)
			if err != nil {
				return nil, "", err
			}
		}
		endpoint := x.Server
		var graph map[string]any
		var err error
		switch {
		case direct:
			graph, err = buildDirectStandardExitConfig(p, x)
		case e.NodeKind == "external":
			if address := addresses[strings.ToLower(upstream.Server)]; address != "" {
				e, err = freezeDesktopExternalProfile(e, address)
				if err != nil {
					return nil, "", err
				}
			}
			var first standardExit
			first, err = standardExitFromExternalProfile(e)
			if err == nil {
				graph, err = buildExternalEntryStandardExitConfig(p, first, x)
			}
			endpoint = first.Server
		default:
			if address := addresses[strings.ToLower(wg.Host)]; address != "" {
				wg.Host, e.Endpoint = address, address
			}
			graph, err = buildNativeStandardExitConfig(p, wg, x)
			endpoint = wg.Host
		}
		if err != nil {
			return nil, "", err
		}
		var capturedEntry *common.RouterProfile
		if !direct {
			capturedEntry = &e
		}
		graph, err = compileDesktopStandardExitPolicy(graph, p, capturedEntry, x)
		return graph, endpoint, err
	}
	addresses := map[string]string{}
	capturedNetwork := ""
	if len(hosts) != 0 {
		validation := map[string]string{}
		for i, host := range hosts {
			validation[host] = []string{"192.0.2.253", "192.0.2.254"}[i]
		}
		if _, _, err := compile(validation); err != nil {
			return result, err
		}
		capturedNetwork = bootstrap.network()
		if capturedNetwork == "" {
			return result, errors.New("standard endpoint bootstrap has no captured physical network")
		}
		for _, host := range hosts {
			if ctx.Err() != nil || bootstrap.network() != capturedNetwork {
				return result, errors.New("standard endpoint bootstrap belongs to a retired network or operation")
			}
			answers, err := bootstrap.lookup(ctx, host)
			if err != nil || ctx.Err() != nil || bootstrap.network() != capturedNetwork || len(answers) == 0 || len(answers) > 32 {
				return result, errors.New("captured standard endpoint lookup failed or expired")
			}
			var chosen netip.Addr
			for _, address := range answers {
				if !desktopExternalPublicAddress(address) || address.Is6() && (control.IPv6Mode == "off" || !direct && entry.IPv6Mode == "off") {
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
				return result, errors.New("captured standard endpoint has no usable public address for the selected IP policy")
			}
			addresses[host] = chosen.String()
		}
	}
	graph, endpoint, err := compile(addresses)
	if err != nil {
		return result, err
	}
	if err := prepareLegacyStandardDNSGraph(graph, direct, exit); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if capturedNetwork != "" && bootstrap.network() != capturedNetwork {
		return result, errors.New("standard endpoint network changed before preparation")
	}
	directory, alias, err := writeStandardExitRuntime(root, graph)
	if err != nil {
		return result, err
	}
	if ctx.Err() != nil || capturedNetwork != "" && bootstrap.network() != capturedNetwork {
		// This unpublished, freshly allocated session directory belongs only to
		// this preparation. Never leave a cancelled bootstrap available to run.
		_ = os.RemoveAll(directory)
		return result, errors.New("standard endpoint preparation lost its captured network or operation")
	}
	return standardExitPrepared{directory: directory, alias: alias, endpoint: endpoint}, nil
}
