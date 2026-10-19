// Package mobiletor owns the native Tor control protocol and bridge plan shared
// by Android VpnService and Apple's PacketTunnel. It never spawns executables.
package mobiletor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

type Bridge struct {
	Transport string
	Target    string
	Arguments map[string]string
	Line      string
}

type Plan struct {
	Bridges []Bridge
}

// NewPlan uses the same strict, data-only bridge grammar as desktop. Neither
// caller-owned profile slices nor maps are retained or modified.
func NewPlan(configuration common.ExternalTorBridgeConfig) (Plan, error) {
	configuration.Bridges = append([]string(nil), configuration.Bridges...)
	profile := common.RouterProfile{ID: "mobile-tor", NodeKind: "external", External: &common.ExternalNodeConfig{
		Protocol: "tor-bridge", TorBridge: &configuration,
	}}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		return Plan{}, err
	}
	plan := Plan{}
	for _, line := range configuration.Bridges {
		fields := strings.Fields(line)
		bridge := Bridge{Transport: fields[0], Target: fields[1], Arguments: map[string]string{}, Line: line}
		for _, field := range fields[2:] {
			if key, value, ok := strings.Cut(field, "="); ok {
				bridge.Arguments[key] = value
			}
		}
		plan.Bridges = append(plan.Bridges, bridge)
	}
	return plan, nil
}

func (p Plan) Transports() []string {
	set := make(map[string]bool)
	for _, bridge := range p.Bridges {
		set[bridge.Transport] = true
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// Arguments starts Tor with networking disabled. The native owning control
// socket is injected by the C API. Only the owner enables networking after its
// PT listeners and protected network dialers are ready.
func (p Plan) Arguments(directory string, listeners map[string]string) ([]string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") {
		return nil, errors.New("Tor requires an absolute private data directory")
	}
	if len(p.Bridges) == 0 || len(p.Bridges) > 8 {
		return nil, errors.New("Tor bridge plan is empty or oversized")
	}
	// Revalidate exported plan values, so mutating a Plan cannot inject torrc
	// directives after initial profile validation.
	lines := make([]string, len(p.Bridges))
	for i, bridge := range p.Bridges {
		lines[i] = bridge.Line
	}
	verified, err := NewPlan(common.ExternalTorBridgeConfig{Transport: "custom", Bridges: lines})
	if err != nil {
		return nil, err
	}
	transports := verified.Transports()
	if len(listeners) != len(transports) {
		return nil, errors.New("Tor requires exactly its owned pluggable transport listeners")
	}
	torrc := filepath.Join(directory, "routervpn-empty-torrc")
	args := []string{"tor", "--quiet", "--defaults-torrc", torrc, "-f", torrc,
		"--DataDirectory", directory, "--ClientOnly", "1", "--AvoidDiskWrites", "1",
		"--__DisableSignalHandlers", "1",
		"--SafeLogging", "1", "--Log", "err stderr", "--UseBridges", "1",
		"--ClientUseIPv6", "1", "--SocksPort", "auto IsolateSOCKSAuth",
		"--ControlPort", "0", "--DNSPort", "0", "--TransPort", "0",
		"--NATDPort", "0", "--HTTPTunnelPort", "0", "--DisableNetwork", "1"}
	used := map[string]bool{}
	for _, transport := range transports {
		listener := listeners[transport]
		host, port, splitErr := net.SplitHostPort(listener)
		n, numberErr := strconv.Atoi(port)
		if splitErr != nil || numberErr != nil || host != "127.0.0.1" || n < 1024 || n > 65535 || used[listener] {
			return nil, errors.New("Tor pluggable transport listener must be a distinct owned IPv4 loopback port")
		}
		used[listener] = true
		args = append(args, "--ClientTransportPlugin", fmt.Sprintf("%s socks5 %s", transport, listener))
	}
	for _, bridge := range verified.Bridges {
		args = append(args, "--Bridge", bridge.Line)
	}
	return args, nil
}

// PrepareState creates only the host-owned private data directory and an empty
// configuration file. Tor refuses non-regular torrc paths on mobile; /dev/null
// is not a portable substitute. Existing nonempty or linked files are rejected.
func PrepareState(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || len(directory) > 4096 || strings.ContainsAny(directory, "\x00\r\n") {
		return errors.New("invalid native Tor private directory")
	}
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("native Tor directory must be private and unlinked")
	}
	path := filepath.Join(directory, "routervpn-empty-torrc")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		return file.Close()
	}
	if !os.IsExist(err) {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("native Tor configuration must be an owned empty private file")
	}
	return nil
}
