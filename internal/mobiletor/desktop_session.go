package mobiletor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	desktopSessionClaimed int32 = iota + 1
	desktopSessionConfigured
	desktopSessionEnabled
	desktopSessionRetiring
	desktopSessionQuiesced
)

// DesktopBridgeSession permanently binds one authenticated Tor child to one
// immutable policy. It owns control operations only: the native host must start
// and retain the actual PT/network owner before EnableNetwork, then prove the
// selected DNS and public Tor path before reporting Connected.
type DesktopBridgeSession struct {
	owner          *DesktopControl
	metadata       DesktopBridgeMetadata
	plan           Plan
	mode           string
	proxy          *TCPProxy // guarded by owner.operation; required only for plain Tor
	state          atomic.Int32
	expected       map[string][]string // guarded by owner.operation
	isolation      string
	paddingClaimed bool // guarded by owner.operation; never transferred or reset
}

func NewDesktopBridgeSession(owner *DesktopControl, policy *DesktopBridgePolicy) (*DesktopBridgeSession, error) {
	if owner == nil || owner.control == nil || owner.pid <= 0 || policy == nil || policy.ServerPolicy() != nil || policy.metadata.Execution != "" || !desktopHex(policy.SourceSHA256(), 32) || !desktopHex(policy.isolation, 32) || policy.metadata.ConfigSHA256 != desktopDigest([]byte(policy.config)) {
		return nil, errors.New("desktop Tor session requires its authenticated child and immutable policy")
	}
	plan := Plan{}
	if policy.Mode() == "tor-bridge" {
		var err error
		plan, err = policy.Plan()
		if err != nil {
			return nil, err
		}
	} else if policy.Mode() != "tor" {
		return nil, errors.New("desktop Tor session has an unknown captured protocol")
	}
	owner.operation.Lock()
	defer owner.operation.Unlock()
	if owner.closed.Load() || owner.claimed {
		return nil, errors.New("desktop Tor child already belongs to a captured or retired session")
	}
	owner.claimed = true
	session := &DesktopBridgeSession{owner: owner, metadata: policy.Metadata(), plan: plan, mode: policy.Mode(), isolation: policy.isolation}
	session.state.Store(desktopSessionClaimed)
	return session, nil
}

func (s *DesktopBridgeSession) Metadata() DesktopBridgeMetadata { return s.metadata }

// Current is control ownership, not a DNS/public-exit proof. Retirement is
// monotonic even while an older command is still unwinding.
func (s *DesktopBridgeSession) Current() bool {
	if s == nil || s.state.Load() != desktopSessionEnabled || s.owner.closed.Load() {
		return false
	}
	if s.mode == "tor" {
		if s.proxy == nil {
			return false
		}
		select {
		case <-s.proxy.Stopping():
			return false
		default:
		}
	}
	return true
}

func (s *DesktopBridgeSession) Configure(ctx context.Context, listeners map[string]string) error {
	return s.configure(ctx, listeners, nil)
}

// ConfigurePlain accepts only the same live authenticated guard proxy owned by
// the native graph. A saved address or external proxy credential cannot enable
// plain Tor or turn a bridge selection into an unprotected direct connection.
func (s *DesktopBridgeSession) ConfigurePlain(ctx context.Context, proxy *TCPProxy) error {
	return s.configure(ctx, nil, proxy)
}

func (s *DesktopBridgeSession) configure(ctx context.Context, listeners map[string]string, proxy *TCPProxy) (failure error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("desktop Tor configuration requires its live captured context")
	}
	socks := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort))
	if socks == s.owner.address {
		return errors.New("desktop Tor SOCKS and control listeners require separate captured ports")
	}
	socks += " IsolateSOCKSAuth"
	expected := withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {socks}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})
	command := "SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort=" + torQuote(socks)
	switch s.mode {
	case "tor":
		if len(listeners) != 0 || proxy == nil {
			return errors.New("plain desktop Tor requires only its captured native guard proxy")
		}
		address, username, password, err := proxy.binding()
		if err != nil || address == s.owner.address || address == net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort)) {
			return errors.New("plain desktop Tor guard proxy has no distinct live owner")
		}
		expected["Socks5Proxy"], expected["Socks5ProxyUsername"], expected["Socks5ProxyPassword"] = []string{address}, []string{username}, []string{password}
		command += " UseBridges=0 Socks5Proxy=" + torQuote(address) + " Socks5ProxyUsername=" + torQuote(username) + " Socks5ProxyPassword=" + torQuote(password)
	case "tor-bridge":
		if proxy != nil {
			return errors.New("desktop Tor bridge cannot borrow a plain guard proxy")
		}
		verified, plugins, err := s.plan.bindings(listeners)
		if err != nil {
			return err
		}
		for _, listener := range listeners {
			if listener == net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort)) || listener == s.owner.address {
				return errors.New("desktop Tor SOCKS, control and PT listeners require separate captured ports")
			}
		}
		expected["UseBridges"], expected["ClientTransportPlugin"] = []string{"1"}, plugins
		expected["Bridge"] = nil
		command += " UseBridges=1"
		for _, plugin := range plugins {
			command += " ClientTransportPlugin=" + torQuote(plugin)
		}
		for _, bridge := range verified.Bridges {
			expected["Bridge"] = append(expected["Bridge"], bridge.Line)
			command += " Bridge=" + torQuote(bridge.Line)
		}
	default:
		return errors.New("desktop Tor session has an unknown captured protocol")
	}
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if s.owner.closed.Load() || s.state.Load() != desktopSessionClaimed || ctx.Err() != nil {
		return errors.New("desktop Tor captured session cannot be configured again")
	}
	defer s.retireOnFailure(&failure)
	if err := s.owner.verifyProcess(ctx); err != nil {
		return err
	}
	if err := s.owner.control.configuration(ctx, desktopIdleConfiguration()); err != nil {
		return err
	}
	if err := s.owner.verifyIdle(ctx); err != nil {
		return err
	}
	if err := desktopGuardCurrent(s.mode, proxy, expected); err != nil {
		return err
	}
	if err := s.owner.control.change(ctx, command); err != nil {
		return err
	}
	if err := s.owner.control.restartBootstrap(ctx, expected); err != nil {
		return err
	}
	s.expected, s.proxy = expected, proxy
	if ctx.Err() != nil || s.owner.closed.Load() || !s.state.CompareAndSwap(desktopSessionClaimed, desktopSessionConfigured) {
		return errors.New("desktop Tor configuration completed after its captured session retired")
	}
	return nil
}

func desktopGuardCurrent(mode string, proxy *TCPProxy, expected map[string][]string) error {
	if mode != "tor" {
		return nil
	}
	address, username, password, err := proxy.binding()
	if err != nil || len(expected["Socks5Proxy"]) != 1 || len(expected["Socks5ProxyUsername"]) != 1 || len(expected["Socks5ProxyPassword"]) != 1 ||
		address != expected["Socks5Proxy"][0] || username != expected["Socks5ProxyUsername"][0] || password != expected["Socks5ProxyPassword"][0] {
		return errors.New("plain desktop Tor lost its exact captured guard proxy")
	}
	return nil
}

func (s *DesktopBridgeSession) EnableNetwork(ctx context.Context) (failure error) {
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if ctx == nil || s.owner.closed.Load() || s.state.Load() != desktopSessionConfigured {
		return errors.New("desktop Tor cannot enable networking before its exact PT configuration is ready")
	}
	defer s.retireOnFailure(&failure)
	if err := desktopGuardCurrent(s.mode, s.proxy, s.expected); err != nil {
		return err
	}
	// Read back the disabled configuration immediately before enabling it. A
	// successful earlier SETCONF is not authority for a later changed plan.
	if err := s.owner.control.configuration(ctx, s.expected); err != nil {
		return err
	}
	if err := s.owner.control.change(ctx, "SETCONF DisableNetwork=0"); err != nil {
		return err
	}
	s.expected["DisableNetwork"] = []string{"0"}
	if err := s.owner.control.configuration(ctx, s.expected); err != nil {
		return err
	}
	if err := s.owner.verifyProcess(ctx); err != nil {
		return err
	}
	if err := s.listeners(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || s.owner.closed.Load() || !s.state.CompareAndSwap(desktopSessionConfigured, desktopSessionEnabled) {
		return errors.New("desktop Tor enable completed after its captured session retired")
	}
	return nil
}

// Verify requires actual completed bootstrap plus the complete captured bridge,
// plugin, SOCKS, proxy, process and listener readback. The separate native DNS and
// TorProject path proofs are still required after this control-plane check.
func (s *DesktopBridgeSession) Verify(ctx context.Context) (Bootstrap, error) {
	status, err := s.bootstrap(ctx)
	if err != nil {
		return Bootstrap{}, err
	}
	if status.Progress != 100 || !status.CircuitEstablished {
		return Bootstrap{}, errors.New("captured desktop Tor circuit has not completed bootstrap")
	}
	return status, nil
}

func (s *DesktopBridgeSession) WaitBootstrap(ctx context.Context) (status Bootstrap, failure error) {
	if ctx == nil {
		return Bootstrap{}, errors.New("desktop Tor bootstrap requires its captured context")
	}
	defer s.retireOnFailure(&failure)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := s.bootstrap(ctx)
		if err != nil {
			return Bootstrap{}, err
		}
		if status.Progress == 100 && status.CircuitEstablished {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return Bootstrap{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *DesktopBridgeSession) bootstrap(ctx context.Context) (status Bootstrap, failure error) {
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if ctx == nil || !s.Current() {
		return Bootstrap{}, errors.New("desktop Tor bootstrap lost its captured session")
	}
	defer s.retireOnFailure(&failure)
	if err := desktopGuardCurrent(s.mode, s.proxy, s.expected); err != nil {
		return Bootstrap{}, err
	}
	if err := s.owner.verifyProcess(ctx); err != nil {
		return Bootstrap{}, err
	}
	if err := s.owner.control.configuration(ctx, s.expected); err != nil {
		return Bootstrap{}, err
	}
	if err := s.listeners(ctx); err != nil {
		return Bootstrap{}, err
	}
	status, err := s.owner.control.Bootstrap(ctx)
	if err != nil {
		return Bootstrap{}, err
	}
	if status.SOCKSAddress != net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort)) || ctx.Err() != nil || !s.Current() {
		return Bootstrap{}, errors.New("desktop Tor bootstrap belongs to a different or retired SOCKS owner")
	}
	return status, nil
}

func (s *DesktopBridgeSession) listeners(ctx context.Context) error {
	keys := []string{}
	for _, key := range idleInventories {
		if strings.HasPrefix(key, "net/listeners/") {
			keys = append(keys, key)
		}
	}
	values, err := s.owner.control.command(ctx, "GETINFO "+strings.Join(keys, " "))
	if err != nil {
		return err
	}
	actual, err := keyedReply(values, keys)
	if err != nil {
		return err
	}
	for _, key := range keys {
		want := ""
		switch key {
		case "net/listeners/control":
			want = strconv.Quote(s.owner.address)
		case "net/listeners/socks":
			want = strconv.Quote(net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort)))
		}
		if len(actual[key]) != 1 || actual[key][0] != want {
			return errors.New("desktop Tor listener readback differs from the exact captured session")
		}
	}
	return nil
}

// Quiesce only verifies Tor's own shutdown barrier. The caller must independently
// close and join its native PT listeners, owned sockets, proof/DNS workers, child
// process and Box before acknowledging complete runtime cleanup.
func (s *DesktopBridgeSession) Quiesce(parent context.Context) (failure error) {
	if parent == nil {
		return errors.New("desktop Tor quiescence requires a context")
	}
	for {
		state := s.state.Load()
		if state == desktopSessionQuiesced {
			return nil
		}
		if state == desktopSessionRetiring || s.state.CompareAndSwap(state, desktopSessionRetiring) {
			break
		}
	}
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if s.state.Load() == desktopSessionQuiesced {
		return nil
	}
	if s.owner.closed.Load() {
		return net.ErrClosed
	}
	defer s.retireOnFailure(&failure)
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := s.owner.verifyProcess(ctx); err != nil {
		return err
	}
	if err := s.owner.control.change(ctx, clearConfiguration); err != nil {
		return err
	}
	if err := s.owner.control.change(ctx, "SIGNAL CLEARDNSCACHE"); err != nil {
		return err
	}
	if err := s.owner.control.configuration(ctx, desktopIdleConfiguration()); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		idle, err := s.owner.idle(ctx)
		if err != nil {
			return err
		}
		if idle {
			if ctx.Err() != nil || s.owner.closed.Load() {
				return errors.New("desktop Tor quiescence completed after cancellation")
			}
			s.state.Store(desktopSessionQuiesced)
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("desktop Tor connections did not quiesce")
		case <-ticker.C:
		}
	}
}

func (s *DesktopBridgeSession) retireOnFailure(failure *error) {
	if *failure != nil {
		for {
			state := s.state.Load()
			if state == desktopSessionQuiesced || state == desktopSessionRetiring || s.state.CompareAndSwap(state, desktopSessionRetiring) {
				break
			}
		}
		_ = s.owner.Close()
	}
}
