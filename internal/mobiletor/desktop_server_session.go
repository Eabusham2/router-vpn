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

// ServerTorSession owns only the authenticated Tor child's control state. It
// has no desktop metadata and never claims an interface, node RTT or circuit
// proof. The no-TUN native worker owns the separate front, PTs, selected DNS,
// dynamic exit proof and joined child shutdown.
type ServerTorSession struct {
	owner             *DesktopControl
	policy            *ServerTorPolicy
	socks             string
	state             atomic.Int32
	expected          map[string][]string // guarded by owner.operation
	proxy             *TCPProxy           // the exact plain-Tor guard path, if selected
	paddingClaimed    bool                // guarded by owner.operation; one cover owner
	comparisonClaimed bool                // guarded by owner.operation; one private comparison front
}

func NewServerTorSession(owner *DesktopControl, policy *ServerTorPolicy, socksPort int) (*ServerTorSession, error) {
	if owner == nil || owner.control == nil || policy == nil || policy.sourceSHA256 != desktopDigest([]byte(policy.source)) || !desktopHex(policy.dnsSHA256, 32) {
		return nil, errors.New("server Tor session requires its authenticated child and immutable source")
	}
	socks, err := policy.SocksAddress(socksPort)
	if err != nil || socks == owner.address {
		return nil, errors.New("server Tor SOCKS and control require separate captured listeners")
	}
	owner.operation.Lock()
	defer owner.operation.Unlock()
	if owner.closed.Load() || owner.claimed {
		return nil, errors.New("server Tor child already belongs to a captured or retired owner")
	}
	owner.claimed = true
	session := &ServerTorSession{owner: owner, policy: policy, socks: socks}
	session.state.Store(desktopSessionClaimed)
	return session, nil
}

func (s *ServerTorSession) SourceSHA256() string { return s.policy.sourceSHA256 }
func (s *ServerTorSession) SocksAddress() string { return s.socks }
func (s *ServerTorSession) Current() bool {
	return s != nil && s.state.Load() == desktopSessionEnabled && !s.owner.closed.Load()
}

// Configure chooses exactly one guard path. Plain Tor requires its live
// authenticated process-local proxy; bridge Tor requires exactly its native
// PT bindings. No caller-supplied proxy address or executable is accepted.
func (s *ServerTorSession) Configure(ctx context.Context, listeners map[string]string, proxy *TCPProxy) (failure error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("server Tor configuration requires its live owner")
	}
	socks := s.socks + " IsolateSOCKSAuth"
	expected := withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {socks}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})
	command := "SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort=" + torQuote(socks)
	switch s.policy.mode {
	case "tor":
		if len(listeners) != 0 || proxy == nil {
			return errors.New("plain server Tor requires only its captured guard proxy")
		}
		address, username, password, err := proxy.binding()
		if err != nil || address == s.socks || address == s.owner.address {
			return errors.New("plain server Tor guard proxy is not a distinct live owner")
		}
		expected["Socks5Proxy"], expected["Socks5ProxyUsername"], expected["Socks5ProxyPassword"] = []string{address}, []string{username}, []string{password}
		command += " UseBridges=0 Socks5Proxy=" + torQuote(address) + " Socks5ProxyUsername=" + torQuote(username) + " Socks5ProxyPassword=" + torQuote(password)
	case "tor-bridge":
		if proxy != nil {
			return errors.New("server Tor bridge cannot borrow a plain guard proxy")
		}
		plan, err := s.policy.Plan()
		if err != nil {
			return err
		}
		verified, plugins, err := plan.bindings(listeners)
		if err != nil {
			return err
		}
		for _, address := range listeners {
			if address == s.socks || address == s.owner.address {
				return errors.New("server Tor PT, SOCKS and control listeners must be distinct")
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
		return errors.New("unknown captured server Tor mode")
	}
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if s.owner.closed.Load() || s.state.Load() != desktopSessionClaimed || ctx.Err() != nil {
		return errors.New("server Tor session cannot be configured again")
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
	if proxy != nil {
		address, username, password, err := proxy.binding()
		if err != nil || address != expected["Socks5Proxy"][0] || username != expected["Socks5ProxyUsername"][0] || password != expected["Socks5ProxyPassword"][0] {
			return errors.New("server Tor guard path retired before configuration")
		}
	}
	if err := s.owner.control.change(ctx, command); err != nil {
		return err
	}
	if err := s.owner.control.restartBootstrap(ctx, expected); err != nil {
		return err
	}
	s.expected, s.proxy = expected, proxy
	if ctx.Err() != nil || s.owner.closed.Load() || !s.state.CompareAndSwap(desktopSessionClaimed, desktopSessionConfigured) {
		return errors.New("server Tor configuration completed after retirement")
	}
	return nil
}

func (s *ServerTorSession) EnableNetwork(ctx context.Context) (failure error) {
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if ctx == nil || ctx.Err() != nil || s.owner.closed.Load() || s.state.Load() != desktopSessionConfigured {
		return errors.New("server Tor cannot enable an unconfigured or retired owner")
	}
	defer s.retireOnFailure(&failure)
	if err := s.guardCurrent(); err != nil {
		return err
	}
	if err := s.owner.control.configuration(ctx, s.expected); err != nil {
		return err
	}
	if err := s.owner.control.change(ctx, "SETCONF DisableNetwork=0"); err != nil {
		return err
	}
	s.expected["DisableNetwork"] = []string{"0"}
	if err := s.readback(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || s.owner.closed.Load() || !s.state.CompareAndSwap(desktopSessionConfigured, desktopSessionEnabled) {
		return errors.New("server Tor enable completed after retirement")
	}
	return nil
}

func (s *ServerTorSession) guardCurrent() error {
	if s.policy.mode != "tor" {
		return nil
	}
	address, username, password, err := s.proxy.binding()
	if err != nil || address != s.expected["Socks5Proxy"][0] || username != s.expected["Socks5ProxyUsername"][0] || password != s.expected["Socks5ProxyPassword"][0] {
		return errors.New("server Tor lost its captured guard owner")
	}
	return nil
}

func (s *ServerTorSession) readback(ctx context.Context) error {
	if err := s.guardCurrent(); err != nil {
		return err
	}
	if err := s.owner.verifyProcess(ctx); err != nil {
		return err
	}
	if err := s.owner.control.configuration(ctx, s.expected); err != nil {
		return err
	}
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
		if key == "net/listeners/control" {
			want = strconv.Quote(s.owner.address)
		} else if key == "net/listeners/socks" {
			want = strconv.Quote(s.socks)
		}
		if len(actual[key]) != 1 || actual[key][0] != want {
			return errors.New("server Tor listener differs from the captured child")
		}
	}
	return nil
}

func (s *ServerTorSession) Bootstrap(ctx context.Context) (status Bootstrap, failure error) {
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if ctx == nil || ctx.Err() != nil || !s.Current() {
		return Bootstrap{}, errors.New("server Tor bootstrap lost its owner")
	}
	defer s.retireOnFailure(&failure)
	if err := s.readback(ctx); err != nil {
		return Bootstrap{}, err
	}
	status, err := s.owner.control.Bootstrap(ctx)
	if err != nil {
		return Bootstrap{}, err
	}
	if status.SOCKSAddress != s.socks || ctx.Err() != nil || !s.Current() {
		return Bootstrap{}, errors.New("server Tor bootstrap changed its SOCKS owner")
	}
	return status, nil
}

func (s *ServerTorSession) WaitBootstrap(ctx context.Context) (status Bootstrap, failure error) {
	if ctx == nil {
		return Bootstrap{}, errors.New("server Tor bootstrap requires an owned deadline")
	}
	defer s.retireOnFailure(&failure)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := s.Bootstrap(ctx)
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

// Quiesce is the Tor control barrier only. The host must also join the exact
// Tor process, PT/network workers and authenticated front before freeing a lease.
func (s *ServerTorSession) Quiesce(parent context.Context) (failure error) {
	if parent == nil {
		return errors.New("server Tor quiescence requires an owned context")
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
				return errors.New("server Tor quiescence completed after cancellation")
			}
			s.state.Store(desktopSessionQuiesced)
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("server Tor connections did not quiesce")
		case <-ticker.C:
		}
	}
}

func (s *ServerTorSession) retireOnFailure(failure *error) {
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
