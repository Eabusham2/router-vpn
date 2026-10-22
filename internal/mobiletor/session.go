package mobiletor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

const proxyKeys = "HTTPProxy HTTPProxyAuthenticator HTTPSProxy HTTPSProxyAuthenticator Socks4Proxy Socks5Proxy Socks5ProxyUsername Socks5ProxyPassword TCPProxy"
const configurationKeys = "DisableNetwork __ReloadTorrcOnSIGHUP SocksPort UseBridges Bridge ClientTransportPlugin " + proxyKeys
const clearConfiguration = "SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort=0 UseBridges=0 Bridge ClientTransportPlugin " + proxyKeys

var idleInventories = []string{
	"orconn-status", "circuit-status", "stream-status", "address-mappings/cache",
	"net/listeners/or", "net/listeners/extor", "net/listeners/dir", "net/listeners/socks",
	"net/listeners/trans", "net/listeners/natd", "net/listeners/httptunnel",
	"net/listeners/dns", "net/listeners/control", "net/listeners/metrics",
}

// Quiesce disables Tor networking, removes session bridge/PT configuration,
// upstream proxy credentials and SOCKS listeners, clears transient DNS answers,
// and verifies the daemon's
// configuration plus current connection, circuit, stream and listener lists.
// The VPN owner must then close and join its PT listeners and protected sockets
// before releasing the session lease. Tor's control lists omit connections
// already marked for close; they alone do not prove that PT sockets drained.
// A failure retires the control stream: the native owner must shut down the core
// and must not reuse it for another session after an unverified disconnect.
func (c *Control) Quiesce(ctx context.Context) (failure error) {
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.conn.Close()
		}
	}()
	return c.quiesce(ctx)
}

func (c *Control) quiesce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.change(ctx, clearConfiguration); err != nil {
		return err
	}
	if err := c.change(ctx, "SIGNAL CLEARDNSCACHE"); err != nil {
		return err
	}
	if err := c.configuration(ctx, withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {"0"}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		values, err := c.command(ctx, "GETINFO "+strings.Join(idleInventories, " "))
		if err != nil {
			return err
		}
		inventory, err := keyedReply(values, idleInventories)
		if err != nil {
			return err
		}
		idle := true
		for _, key := range idleInventories {
			if len(inventory[key]) != 1 {
				return errors.New("ambiguous native Tor idle inventory")
			}
			idle = idle && inventory[key][0] == ""
		}
		if idle {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("native Tor connections did not quiesce")
		case <-ticker.C:
		}
	}
}

// Configure replaces a previous session only after verified quiescence. It
// revalidates the shared data-only bridge grammar and binds exactly the PT
// listeners owned by the new session. Networking stays disabled until the VPN
// host has installed its protected network owner and explicitly enables Tor.
func (c *Control) Configure(ctx context.Context, plan Plan, listeners map[string]string) (failure error) {
	verified, plugins, err := plan.bindings(listeners)
	if err != nil {
		return err
	}
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.conn.Close()
		}
	}()
	if err := c.quiesce(ctx); err != nil {
		return err
	}
	command := `SETCONF DisableNetwork=1 SocksPort="auto IsolateSOCKSAuth" UseBridges=1`
	for _, plugin := range plugins {
		command += " ClientTransportPlugin=" + torQuote(plugin)
	}
	bridges := make([]string, 0, len(verified.Bridges))
	for _, bridge := range verified.Bridges {
		bridges = append(bridges, bridge.Line)
		command += " Bridge=" + torQuote(bridge.Line)
	}
	if err := c.change(ctx, command); err != nil {
		return err
	}
	return c.restartBootstrap(ctx, withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {"auto IsolateSOCKSAuth"}, "UseBridges": {"1"},
		"Bridge": bridges, "ClientTransportPlugin": plugins,
	}))
}

// ConfigurePlain selects ordinary Tor guard relays without inserting bridges.
// Its sole upstream is the live session's authenticated process-local proxy.
// The pinned client-only Tor requires directory traffic to use OR connections;
// Socks5Proxy covers those connections as well as guard circuit connections.
func (c *Control) ConfigurePlain(ctx context.Context, proxy *TCPProxy) (failure error) {
	address, username, password, err := proxy.binding()
	if err != nil {
		return err
	}
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.conn.Close()
		}
	}()
	if err := c.quiesce(ctx); err != nil {
		return err
	}
	if _, _, _, err := proxy.binding(); err != nil {
		return err
	}
	command := `SETCONF DisableNetwork=1 SocksPort="auto IsolateSOCKSAuth" UseBridges=0 Socks5Proxy=` + torQuote(address) +
		" Socks5ProxyUsername=" + torQuote(username) + " Socks5ProxyPassword=" + torQuote(password)
	if err := c.change(ctx, command); err != nil {
		return err
	}
	expected := withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {"auto IsolateSOCKSAuth"}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})
	expected["Socks5Proxy"] = []string{address}
	expected["Socks5ProxyUsername"] = []string{username}
	expected["Socks5ProxyPassword"] = []string{password}
	return c.restartBootstrap(ctx, expected)
}

// DisableNetwork closes a session's sockets but leaves the resident Tor's
// consensus-download attempt/backoff schedules intact. A new captured path
// must not inherit a previous canceled session's bootstrap delay. Tor's reload
// operation resets those schedules without discarding persistent guard state.
// Verify the controller-only reload policy before signaling it, so Tor cannot
// reload the empty startup torrc and replace the newly captured proxy/bridges.
// Networking remains disabled and the complete session is checked again before
// the caller may enable it. Failures are retired by the enclosing Configure.
func (c *Control) restartBootstrap(ctx context.Context, expected map[string][]string) error {
	if err := c.configuration(ctx, expected); err != nil {
		return err
	}
	if err := c.change(ctx, "SIGNAL RELOAD"); err != nil {
		return err
	}
	return c.configuration(ctx, expected)
}

func withEmptyProxies(configuration map[string][]string) map[string][]string {
	for _, key := range strings.Fields(proxyKeys) {
		configuration[key] = []string{""}
	}
	return configuration
}

func torQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func (c *Control) configuration(ctx context.Context, expected map[string][]string) error {
	values, err := c.command(ctx, "GETCONF "+configurationKeys)
	if err != nil {
		return err
	}
	actual, err := keyedReply(values, strings.Fields(configurationKeys))
	if err != nil {
		return err
	}
	for key, want := range expected {
		got := actual[key]
		// Tor may reorder its repeated Bridge and ClientTransportPlugin lines.
		// Sorting copies preserves multiplicity and never mutates caller data.
		got, want = slices.Clone(got), slices.Clone(want)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return errors.New("native Tor configuration readback did not match the owned session")
		}
	}
	return nil
}

func keyedReply(values, keys []string) (map[string][]string, error) {
	result := make(map[string][]string, len(keys))
	for _, key := range keys {
		result[key] = nil
	}
	for _, value := range values {
		key, text, _ := strings.Cut(value, "=")
		if _, ok := result[key]; !ok {
			return nil, errors.New("unexpected native Tor control field")
		}
		result[key] = append(result[key], text)
	}
	for _, values := range result {
		if len(values) == 0 {
			return nil, errors.New("incomplete native Tor control readback")
		}
	}
	return result, nil
}
