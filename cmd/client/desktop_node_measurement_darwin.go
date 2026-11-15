//go:build darwin

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"router-vpn/internal/dnsmeasure"
)

// Immutable measurement authority is a particular proved native reader, not
// whichever utun or active profile happens to exist when a response arrives.
type desktopMacOSPairedNodeNativeMeasurement struct {
	host     *desktopMacOSPairedNodeHost
	identity desktopMacOSPairedNodeMeasurementIdentity
	reader   desktopNodeMTURecord
	epoch    uint64
	ipv6     bool
}

func (h *desktopMacOSPairedNodeHost) CaptureMeasurement(ctx context.Context) (desktopMacOSPairedNodeMeasurement, error) {
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	if !h.activated || !h.proved || h.measurementRetired.Load() {
		return nil, errors.New("macOS Router measurement has no original active proof")
	}
	ready, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return nil, err
	}
	if live.Active || live.Failure != "" || h.mtu != nil {
		return nil, errors.New("macOS Router measurement conflicts with its original MTU lease")
	}
	value := &desktopMacOSPairedNodeNativeMeasurement{host: h, reader: live, epoch: h.measurementEpoch.Load(), ipv6: h.policy.Metadata().IPv6Mode == "on", identity: desktopMacOSPairedNodeMeasurementIdentity{
		launch: h.launch, host: h, command: h.launch.command, profileID: h.launch.profileID, mode: h.launch.mode, nodeID: h.selection.NodeID, session: ready.SessionID, source: ready.SourceSHA256, config: ready.ConfigSHA256, network: h.network, profileToken: h.revision}}
	if !value.identity.valid() || !value.MatchesOriginal() {
		return nil, errors.New("macOS Router measurement lost immutable source authority")
	}
	return value, nil
}
func (m *desktopMacOSPairedNodeNativeMeasurement) Identity() desktopMacOSPairedNodeMeasurementIdentity {
	if m == nil {
		return desktopMacOSPairedNodeMeasurementIdentity{}
	}
	return m.identity
}
func (m *desktopMacOSPairedNodeNativeMeasurement) MatchesOriginal() bool {
	return m != nil && m.host != nil && m.identity.host == m.host && m.identity.launch == m.host.launch && !m.host.measurementRetired.Load() && m.epoch == m.host.measurementEpoch.Load()
}
func (m *desktopMacOSPairedNodeNativeMeasurement) Current(ctx context.Context) error {
	if !m.MatchesOriginal() {
		return errors.New("macOS Router measurement retired its captured reader")
	}
	h := m.host
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if !m.MatchesOriginal() || !h.activated || !h.proved || h.mtu != nil {
		return errors.New("macOS Router measurement no longer owns its original activation")
	}
	_, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return err
	}
	if !sameDesktopMacOSMTUReadback(live, m.reader) {
		return errors.New("macOS Router measurement changed its captured native reader or MTU generation")
	}
	return ctx.Err()
}

func (m *desktopMacOSPairedNodeNativeMeasurement) currentBeforeHTTPIO(ctx context.Context) error {
	if timing := clientHTTPRequestTiming(ctx); timing != nil {
		return timing.currentBeforeIO(ctx, m)
	}
	return m.Current(ctx)
}

func (m *desktopMacOSPairedNodeNativeMeasurement) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := m.currentBeforeHTTPIO(ctx); err != nil {
		return nil, err
	}
	dialer := net.Dialer{ControlContext: func(call context.Context, actualNetwork, actualAddress string, raw syscall.RawConn) error {
		if actualNetwork != network || actualAddress != address || !m.MatchesOriginal() {
			return errors.New("macOS Router measurement changed its bound socket destination")
		}
		var failure error
		err := raw.Control(func(fd uintptr) { failure = bindDesktopImportedMTUKernel(call, network, fd, m.reader) })
		return errors.Join(err, failure)
	}}
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := m.currentBeforeHTTPIO(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

// This reserved address is an injection destination, never a resolver choice.
// The sealed graph hijacks port53 from its captured TUN before LAN/payload
// rules and dispatches to the immutable selected DNS object and transport.
// Every packet is bound to this exact utun; no system resolver is consulted.
const desktopMacOSPairedDNSInjection = "198.18.0.53:53"

func (m *desktopMacOSPairedNodeNativeMeasurement) lookup(parent context.Context, name string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(name); err == nil {
		if literal.Zone() != "" || literal.Is4In6() || literal.IsUnspecified() || literal.IsMulticast() || !m.ipv6 && !literal.Is4() {
			return nil, errors.New("macOS Router measurement has an invalid literal")
		}
		return []netip.Addr{literal}, nil
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var result []netip.Addr
	for _, ipv6 := range []bool{false, true} {
		if ipv6 && !m.ipv6 {
			continue
		}
		query, err := dnsmeasure.TransportBootstrapQuery(name, ipv6)
		if err != nil {
			return nil, err
		}
		connection, err := m.dial(ctx, "udp4", desktopMacOSPairedDNSInjection)
		if err != nil {
			return nil, err
		}
		timing := clientHTTPRequestTiming(ctx)
		if timing != nil {
			if err := timing.beginDNS(m); err != nil {
				_ = connection.Close()
				return nil, err
			}
		}
		answer, exchangeErr := func() ([]byte, error) {
			var once sync.Once
			closeConnection := func() { once.Do(func() { _ = connection.Close() }) }
			stop := context.AfterFunc(ctx, closeConnection)
			defer func() { stop(); closeConnection() }()
			deadline, _ := ctx.Deadline()
			if err := connection.SetDeadline(deadline); err != nil {
				return nil, err
			}
			if n, err := connection.Write(query); err != nil || n != len(query) {
				return nil, errors.Join(err, io.ErrShortWrite)
			}
			body := make([]byte, (16<<10)+1)
			n, err := connection.Read(body)
			if err != nil || n > 16<<10 {
				return nil, errors.Join(err, errors.New("selected DNS exceeded bounded original reply"))
			}
			return body[:n], nil
		}()
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		answers, err := dnsmeasure.TransportBootstrapAnswers(query, answer)
		if err != nil {
			return nil, err
		}
		if timing != nil {
			if err := timing.endDNS(m); err != nil {
				return nil, err
			}
		}
		if err := m.currentBeforeHTTPIO(ctx); err != nil {
			return nil, err
		}
		result = append(result, answers...)
	}
	if len(result) == 0 {
		return nil, errors.New("captured selected DNS returned no usable address")
	}
	return result, nil
}
func (m *desktopMacOSPairedNodeNativeMeasurement) HTTPClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 45*time.Second {
		return nil, errors.New("macOS Router measurement has no bounded HTTP deadline")
	}
	if err := m.Current(ctx); err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: timeout,
		DialContext: func(detached context.Context, network, address string) (net.Conn, error) {
			call, ok := detached.Value(desktopMacOSPairedNodeRequestContextKey{}).(context.Context)
			if !ok || call == nil || call.Err() != nil {
				return nil, errors.New("captured Router dial lost its original HTTP caller")
			}

			if network != "tcp" {
				return nil, errors.New("macOS Router measurement requires TCP")
			}
			host, port, err := net.SplitHostPort(address)
			numeric, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || numeric < 1 || numeric > 65535 {
				return nil, errors.New("macOS Router measurement changed its bounded HTTP authority")
			}
			ips, err := m.lookup(call, host)
			if err != nil {
				return nil, err
			}
			var failure error
			for _, ip := range ips {
				kind := "tcp4"
				if ip.Is6() {
					kind = "tcp6"
				}
				connection, err := m.dial(call, kind, net.JoinHostPort(ip.String(), port))
				if err == nil {
					if timing := clientHTTPRequestTiming(call); timing != nil {
						if err := timing.beginHTTP(m); err != nil {
							_ = connection.Close()
							return nil, err
						}
					}
					return connection, nil
				}
				failure = err
				if call.Err() != nil {
					return nil, call.Err()
				}
			}
			return nil, failure
		}}
	return &http.Client{Transport: &desktopMacOSPairedNodeRoundTripper{measurement: m, transport: transport}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("captured Router measurement refuses redirects")
	}}, nil
}

type desktopMacOSPairedNodeRequestContextKey struct{}

type desktopMacOSPairedNodeRoundTripper struct {
	measurement *desktopMacOSPairedNodeNativeMeasurement
	transport   *http.Transport
}

func (r *desktopMacOSPairedNodeRoundTripper) CloseIdleConnections() {
	r.transport.CloseIdleConnections()
}
func (r *desktopMacOSPairedNodeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	timing := clientHTTPRequestTiming(request.Context())
	if timing != nil {
		if err := timing.claim(r.measurement); err != nil {
			return nil, err
		}
	}
	if err := r.measurement.currentBeforeHTTPIO(request.Context()); err != nil {
		return nil, err
	}
	owned := request.WithContext(context.WithValue(request.Context(), desktopMacOSPairedNodeRequestContextKey{}, request.Context()))
	response, err := r.transport.RoundTrip(owned)
	if err != nil {
		return nil, err
	}
	if timing != nil {
		body, err := timing.responseBody(request.Context(), r.measurement, response.Body)
		if err != nil {
			_ = response.Body.Close()
			return nil, err
		}
		response.Body = body
		return response, nil
	}
	if err := r.measurement.Current(request.Context()); err != nil {
		response.Body.Close()
		return nil, err
	}
	response.Body = &desktopMacOSPairedNodeResponseBody{ReadCloser: response.Body, measurement: r.measurement}
	return response, nil
}

type desktopMacOSPairedNodeResponseBody struct {
	io.ReadCloser
	measurement *desktopMacOSPairedNodeNativeMeasurement
}

func (b *desktopMacOSPairedNodeResponseBody) Read(raw []byte) (int, error) {
	if !b.measurement.MatchesOriginal() {
		_ = b.ReadCloser.Close()
		return 0, errors.New("captured Router response belongs to a retired native reader")
	}
	n, err := b.ReadCloser.Read(raw)
	if !b.measurement.MatchesOriginal() {
		_ = b.ReadCloser.Close()
		return 0, errors.New("captured Router response changed its original native reader")
	}
	return n, err
}
